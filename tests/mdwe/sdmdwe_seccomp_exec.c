/*
** Launch a command under a seccomp filter replicating systemd's
** seccomp_memory_deny_write_execute() fallback (src/shared/seccomp-util.c,
** systemd main @ 889bc48f, 2026-09-29). systemd >= v254 prefers kernel
** PR_SET_MDWE and uses this filter only when prctl() returns EINVAL
** (kernel < 6.3), so a current system never exercises it on its own.
**
** Rules, each answered with EPERM exactly as systemd's SCMP_ACT_ERRNO(EPERM):
**   mmap(..., prot & (PROT_WRITE|PROT_EXEC) == both, ...)
**   mprotect(..., prot & PROT_EXEC, ...)
**   pkey_mprotect(..., prot & PROT_EXEC, ...)
**   shmat(..., shmflg & SHM_EXEC, ...)
** Limitation: only the native ABI is filtered here. systemd also installs
** per-architecture filters for secondary ABIs (i386/x32 on x86_64); a
** compat-ABI caller is out of scope for LuaJIT's native build.
**
** Usage: sdmdwe-seccomp-exec [--] command [args...]
*/
#define _GNU_SOURCE
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/shm.h>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(__x86_64__)
#define NATIVE_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define NATIVE_ARCH AUDIT_ARCH_AARCH64
#else
#error "unsupported architecture"
#endif

#define ARG2_LO offsetof(struct seccomp_data, args[2])
#define DENY BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ERRNO|(EPERM & SECCOMP_RET_DATA))
#define ALLOW BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW)

int main(int argc, char **argv)
{
	struct sock_filter f[] = {
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, arch)),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, NATIVE_ARCH, 1, 0),
		ALLOW,
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, nr)),
#if defined(__x86_64__)
		/* x32 syscalls share AUDIT_ARCH_X86_64; leave them unfiltered (see above). */
		BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 0x40000000u, 0, 1),
		ALLOW,
#endif
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, SYS_mmap, 0, 5),
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS, ARG2_LO),
		BPF_STMT(BPF_ALU|BPF_AND|BPF_K, PROT_WRITE|PROT_EXEC),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, PROT_WRITE|PROT_EXEC, 0, 1),
		DENY,
		ALLOW,
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, SYS_mprotect, 1, 0),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, SYS_pkey_mprotect, 0, 4),
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS, ARG2_LO),
		BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K, PROT_EXEC, 0, 1),
		DENY,
		ALLOW,
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, SYS_shmat, 0, 4),
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS, ARG2_LO),
		BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K, SHM_EXEC, 0, 1),
		DENY,
		ALLOW,
		ALLOW,  /* Any other syscall. */
	};
	struct sock_fprog prog = { (unsigned short)(sizeof(f)/sizeof(f[0])), f };
	int i = 1;
	if (i < argc && !strcmp(argv[i], "--")) i++;
	if (i >= argc) {
		fprintf(stderr, "usage: sdmdwe-seccomp-exec [--] command [args...]\n");
		return 125;
	}
	if (prctl(PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L) ||
	    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
		fprintf(stderr, "sdmdwe-seccomp-exec: installing filter failed: %s\n", strerror(errno));
		return 125;
	}
	execvp(argv[i], argv + i);
	fprintf(stderr, "sdmdwe-seccomp-exec: exec %s: %s\n", argv[i], strerror(errno));
	return 127;
}
