/*
** W^X strategy probe: attempts one way of producing executable code and
** reports whether the kernel/seccomp policy allowed each step.
**
** Usage: wx-probe <strategy>
** Exit 0 = code was written and executed and returned the expected value.
** Exit 2 = a syscall was refused (the failing step is printed to stdout).
** Exit 3 = unknown strategy / setup error.
** Any signal death means the policy silently let a step "succeed" but the
** code was not executable (should not happen; reported by the caller).
**
** Strategies model LuaJIT allocator designs; see docs/MDWE_RESEARCH.md.
*/
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef MFD_EXEC
#define MFD_EXEC 0x0010U
#endif
#ifndef MFD_NOEXEC_SEAL
#define MFD_NOEXEC_SEAL 0x0008U
#endif

#define SZ 65536

typedef int (*fn_t)(void);

#if defined(__x86_64__)
/* mov eax, imm32 ; ret */
static void emit(uint8_t *p, int v) { p[0] = 0xb8; memcpy(p+1, &v, 4); p[5] = 0xc3; }
#elif defined(__aarch64__)
/* movz w0, #v ; ret */
static void emit(uint8_t *p, int v)
{
	uint32_t i0 = 0x52800000u | ((uint32_t)(v & 0xffff) << 5), i1 = 0xd65f03c0u;
	memcpy(p, &i0, 4); memcpy(p+4, &i1, 4);
}
#else
#error "unsupported probe architecture"
#endif

static int refused(const char *step)
{
	printf("REFUSED %s: %s\n", step, strerror(errno));
	return 2;
}

static int run(void *code, int want)
{
	int got = ((fn_t)code)();
	if (got != want) { printf("WRONG %d != %d\n", got, want); return 1; }
	printf("OK %d\n", got);
	return 0;
}

static void sync_icache(void *p, size_t n) { __builtin___clear_cache((char *)p, (char *)p + n); }

/* WX_MFD=exec|noexec-seal|plain selects memfd_create flags (default exec). */
static int memfd_new(void)
{
	const char *m = getenv("WX_MFD");
	unsigned fl = !m || !strcmp(m, "exec") ? MFD_EXEC : !strcmp(m, "noexec-seal") ? MFD_NOEXEC_SEAL : 0;
	int fd = (int)syscall(SYS_memfd_create, "wx-probe", MFD_CLOEXEC|fl);
	if (fd < 0 && errno == EINVAL)  /* Kernel < 6.3 has no MFD_EXEC. */
		fd = (int)syscall(SYS_memfd_create, "wx-probe", MFD_CLOEXEC);
	if (fd >= 0 && ftruncate(fd, SZ)) { close(fd); return -1; }
	return fd;
}

/* Upstream LUAJIT_SECURITY_MCODE=1: anonymous RW, then mprotect to RX. */
static int s_mprotect(void)
{
	uint8_t *p = mmap(NULL, SZ, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED) return refused("mmap RW");
	emit(p, 42); sync_icache(p, 16);
	if (mprotect(p, SZ, PROT_READ|PROT_EXEC)) return refused("mprotect RX");
	return run(p, 42);
}

/* Upstream LUAJIT_SECURITY_MCODE=0: anonymous RWX. */
static int s_rwx(void)
{
	uint8_t *p = mmap(NULL, SZ, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED) return refused("mmap RWX");
	emit(p, 42); sync_icache(p, 16);
	return run(p, 42);
}

/* Persistent dual mapping of one memfd: RW alias + RX alias. */
static int s_dual(void)
{
	int fd = memfd_new();
	uint8_t *w, *x;
	if (fd < 0) return refused("memfd_create");
	w = mmap(NULL, SZ, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (w == MAP_FAILED) return refused("mmap RW alias");
	x = mmap(NULL, SZ, PROT_READ|PROT_EXEC, MAP_SHARED, fd, 0);
	if (x == MAP_FAILED) return refused("mmap RX alias");
	emit(w, 42); sync_icache(x, 16);
	if (run(x, 42)) return 1;
	emit(w, 43); sync_icache(x, 16);  /* Patch through the alias. */
	return run(x, 43);
}

/* Single address, protection toggled by MAP_FIXED re-mapping of a memfd. */
static int s_remap(void)
{
	int fd = memfd_new();
	uint8_t *p, *q;
	if (fd < 0) return refused("memfd_create");
	p = mmap(NULL, SZ, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED) return refused("mmap RW");
	emit(p, 42);
	q = mmap(p, SZ, PROT_READ|PROT_EXEC, MAP_SHARED|MAP_FIXED, fd, 0);
	if (q == MAP_FAILED) return refused("remap RX");
	sync_icache(p, 16);
	if (run(p, 42)) return 1;
	q = mmap(p, SZ, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_FIXED, fd, 0);
	if (q == MAP_FAILED) return refused("remap RW (patch)");
	emit(p, 43);
	q = mmap(p, SZ, PROT_READ|PROT_EXEC, MAP_SHARED|MAP_FIXED, fd, 0);
	if (q == MAP_FAILED) return refused("remap RX (after patch)");
	sync_icache(p, 16);
	return run(p, 43);
}

/* mprotect of a memfd mapping RW -> RX (file-backed rather than anonymous). */
static int s_memfd_mprotect(void)
{
	int fd = memfd_new();
	uint8_t *p;
	if (fd < 0) return refused("memfd_create");
	p = mmap(NULL, SZ, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED) return refused("mmap RW");
	emit(p, 42); sync_icache(p, 16);
	if (mprotect(p, SZ, PROT_READ|PROT_EXEC)) return refused("mprotect RX");
	return run(p, 42);
}

/* Fresh RX anonymous mapping written through /proc/self/mem (FOLL_FORCE). */
static int s_procmem(void)
{
	uint8_t buf[16], *p;
	int fd;
	p = mmap(NULL, SZ, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED) return refused("mmap RX");
	fd = open("/proc/self/mem", O_RDWR|O_CLOEXEC);
	if (fd < 0) return refused("open /proc/self/mem");
	emit(buf, 42);
	if (pwrite(fd, buf, sizeof(buf), (off_t)(uintptr_t)p) != (ssize_t)sizeof(buf))
		return refused("pwrite /proc/self/mem");
	sync_icache(p, 16);
	return run(p, 42);
}

/* fork() hazard: after fork, a child patching through its inherited RW alias
** changes the code the PARENT executes, because both map the same memfd pages.
** Upstream MAP_PRIVATE|MAP_ANONYMOUS code is copy-on-write and isolated.
** Exit 0 = isolated (safe), 4 = parent observed the child's write (shared). */
static int s_fork_isolation(int private_rx)
{
	int fd = memfd_new(), st;
	uint8_t *w, *x;
	pid_t pid;
	if (fd < 0) return refused("memfd_create");
	w = mmap(NULL, SZ, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (w == MAP_FAILED) return refused("mmap RW alias");
	x = mmap(NULL, SZ, PROT_READ|PROT_EXEC, private_rx ? MAP_PRIVATE : MAP_SHARED, fd, 0);
	if (x == MAP_FAILED) return refused("mmap RX alias");
	emit(w, 42); sync_icache(x, 16);
	if (run(x, 42)) return 1;
	pid = fork();
	if (pid == 0) { emit(w, 666); _exit(0); }  /* Child compiles/patches. */
	if (pid < 0 || waitpid(pid, &st, 0) != pid) return refused("fork");
	sync_icache(x, 16);
	if (((fn_t)x)() != 42) { printf("SHARED parent now runs child code (%d)\n", ((fn_t)x)()); return 4; }
	printf("ISOLATED\n");
	return 0;
}
/* Control for the above: upstream-style anonymous private code (needs mprotect, so no MDWE). */
static int s_fork_anon(void)
{
	int st;
	pid_t pid;
	uint8_t *p = mmap(NULL, SZ, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED) return refused("mmap RW");
	emit(p, 42); sync_icache(p, 16);
	if (mprotect(p, SZ, PROT_READ|PROT_EXEC)) return refused("mprotect RX");
	pid = fork();
	if (pid == 0) {
		if (mprotect(p, SZ, PROT_READ|PROT_WRITE)) _exit(2);
		emit(p, 666); _exit(0);
	}
	if (pid < 0 || waitpid(pid, &st, 0) != pid) return refused("fork");
	if (((fn_t)p)() != 42) { printf("SHARED parent now runs child code\n"); return 4; }
	printf("ISOLATED\n");
	return 0;
}
static int s_fork_dual(void) { return s_fork_isolation(0); }
static int s_fork_dual_private_rx(void) { return s_fork_isolation(1); }

/* Re-asserting PROT_EXEC on a mapping that never was writable (no exec gain). */
static int s_rx_noop(void)
{
	uint8_t *p = mmap(NULL, SZ, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED) return refused("mmap RX");
	if (mprotect(p, SZ, PROT_READ|PROT_EXEC)) return refused("mprotect RX again");
	printf("OK noop\n");
	return 0;
}

/* Control: mprotect of an existing RX mapping back to RW must not grant exec. */
static int s_rx_to_rwx(void)
{
	uint8_t *p = mmap(NULL, SZ, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED) return refused("mmap RX");
	if (mprotect(p, SZ, PROT_READ|PROT_WRITE|PROT_EXEC)) return refused("mprotect RWX");
	emit(p, 42); sync_icache(p, 16);
	return run(p, 42);
}

int main(int argc, char **argv)
{
	static const struct { const char *name; int (*fn)(void); } s[] = {
		{ "mprotect", s_mprotect }, { "rwx", s_rwx }, { "dual", s_dual },
		{ "remap", s_remap }, { "memfd-mprotect", s_memfd_mprotect },
		{ "procmem", s_procmem }, { "rx-to-rwx", s_rx_to_rwx }, { "rx-noop", s_rx_noop },
		{ "fork-anon", s_fork_anon }, { "fork-dual", s_fork_dual }, { "fork-dual-private-rx", s_fork_dual_private_rx },
	};
	size_t i;
	setvbuf(stdout, NULL, _IONBF, 0);
	if (argc == 2)
		for (i = 0; i < sizeof(s)/sizeof(s[0]); i++)
			if (!strcmp(argv[1], s[i].name)) return s[i].fn();
	fprintf(stderr, "usage: wx-probe {");
	for (i = 0; i < sizeof(s)/sizeof(s[0]); i++)
		fprintf(stderr, "%s%s", i ? "|" : "", s[i].name);
	fprintf(stderr, "}\n");
	return 3;
}
