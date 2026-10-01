/*
** T5c/T5d: a second thread keeps compiling in its own lua_State while the
** main thread forks. The child snapshots every mapping of the LuaJIT mcode
** memfd, waits until the parent thread has compiled more traces, then
** compares. With LUAJIT_SECURITY_MCODE=2's seal-at-fork protocol the child's
** code must be UNCHANGED.
**
** Usage: embed-fork fork    expect "UNCHANGED" (exit 0)
**        embed-fork forkloop  1000 ordinary forks while the thread compiles
**                             (review R2: run with ThreadSanitizer).
**        embed-fork clone   raw clone(SIGCHLD): bypasses pthread_atfork, so
**                           the documented residual shows as "CHANGED".
** Bounded: one extra thread, fixed trace counts. No sleeps: pipe handshakes
** and an atomic counter.
*/
#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

#define MAXREG 256
#define SNAPMAX (16u << 20)

static atomic_long compiled;
static atomic_int stop;
static char snapbuf[SNAPMAX];
static char mapsbuf[1 << 20];
static struct { unsigned long lo, hi; } reg[MAXREG];

/* Each call compiles a fresh function (new root trace) in state L. */
/* Apply LJ_EMBED_JITOPT (e.g. "mcoderemap=1") via jit.opt.start, as an
** embedding host would. */
static void jitopt(lua_State *L)
{
	const char *o = getenv("LJ_EMBED_JITOPT");
	if (!o) return;
	lua_getglobal(L, "jit");
	lua_getfield(L, -1, "opt");
	lua_getfield(L, -1, "start");
	lua_pushstring(L, o);
	if (lua_pcall(L, 1, 0, 0)) { fprintf(stderr, "jit.opt.start: %s\n", lua_tostring(L, -1)); exit(3); }
	lua_pop(L, 2);
}

static const char *churn =
	"local k = ... "
	"local f = load(('return function(n) local s = 0 for i = 1, n do s = s + (i %% %d) * %d end return s end'):format(k % 97 + 2, k))() "
	"return f(2000)";

static void *compiler(void *arg)
{
	lua_State *L = luaL_newstate();
	long k = 0;
	(void)arg;
	luaL_openlibs(L);
	jitopt(L);
	if (luaL_loadstring(L, churn)) { fprintf(stderr, "load: %s\n", lua_tostring(L, -1)); exit(3); }
	lua_setglobal(L, "churn");
	while (!atomic_load(&stop)) {
		lua_getglobal(L, "churn");
		lua_pushinteger(L, (lua_Integer)++k);
		if (lua_pcall(L, 1, 1, 0)) { fprintf(stderr, "run: %s\n", lua_tostring(L, -1)); exit(3); }
		lua_pop(L, 1);
		atomic_fetch_add(&compiled, 1);
	}
	lua_close(L);
	return NULL;
}

/* Raw-syscall helpers: safe in a raw clone child. */
static long rd(int fd, void *b, unsigned long n) { return syscall(SYS_read, fd, b, n); }
static long wr(int fd, const void *b, unsigned long n) { return syscall(SYS_write, fd, b, n); }

/* Parse /proc/self/maps for memfd:luajit-mcode ranges. */
static int find_regions(void)
{
	int fd = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/maps", O_RDONLY), n = 0;
	long len = 0, r;
	char *p, *e;
	if (fd < 0) return -1;
	while ((r = rd(fd, mapsbuf + len, sizeof(mapsbuf) - 1 - (unsigned long)len)) > 0) len += r;
	syscall(SYS_close, fd);
	mapsbuf[len] = 0;
	for (p = mapsbuf; p && *p && n < MAXREG; p = e ? e + 1 : NULL) {
		e = strchr(p, '\n');
		if (e) *e = 0;
		if (strstr(p, "memfd:luajit-mcode")) {
			reg[n].lo = strtoul(p, &p, 16);
			reg[n].hi = strtoul(p + 1, NULL, 16);
			n++;
		}
	}
	return n;
}

static int child_main(int ready_w, int go_r)
{
	int n = find_regions(), i;
	unsigned long off = 0;
	char c = 0;
	if (n <= 0) { wr(1, "NO-REGIONS\n", 11); return 2; }
	for (i = 0; i < n; i++) {
		unsigned long sz = reg[i].hi - reg[i].lo;
		if (off + sz > SNAPMAX) return 2;
		memcpy(snapbuf + off, (void *)reg[i].lo, sz);
		off += sz;
	}
	wr(ready_w, "r", 1);
	if (rd(go_r, &c, 1) != 1) return 2;
	for (off = 0, i = 0; i < n; i++) {
		unsigned long sz = reg[i].hi - reg[i].lo;
		if (memcmp(snapbuf + off, (void *)reg[i].lo, sz)) { wr(1, "CHANGED\n", 8); return 4; }
		off += sz;
	}
	wr(1, "UNCHANGED\n", 10);
	return 0;
}

int main(int argc, char **argv)
{
	int use_clone = argc > 1 && !strcmp(argv[1], "clone");
	int ready[2], go[2], st = 0;
	long c0, pid;
	pthread_t th;
	char c;
	setvbuf(stdout, NULL, _IONBF, 0);
	if (pipe(ready) || pipe(go)) return 3;
	if (pthread_create(&th, NULL, compiler, NULL)) return 3;
	while (atomic_load(&compiled) < 50) sched_yield();
	if (argc > 1 && !strcmp(argv[1], "forkloop")) {
		int i;
		for (i = 0; i < 1000; i++) {
			pid = fork();
			if (pid == 0) _exit(0);
			if (pid < 0 || waitpid((pid_t)pid, &st, 0) < 0 || st != 0) { printf("forkloop: FAIL at %d\n", i); return 1; }
		}
		atomic_store(&stop, 1);
		pthread_join(th, NULL);
		printf("forkloop: 1000 ok\n");
		return 0;
	}
	if (use_clone)
		pid = syscall(SYS_clone, (unsigned long)SIGCHLD, 0UL, 0UL, 0UL, 0UL);
	else
		pid = fork();
	if (pid == 0) syscall(SYS_exit_group, child_main(ready[1], go[0]));
	if (pid < 0) return 3;
	/* Close the child's ends so an early child exit reads as EOF, not a hang. */
	close(ready[1]); close(go[0]);
	if (read(ready[0], &c, 1) != 1) {
		waitpid((pid_t)pid, &st, 0);
		atomic_store(&stop, 1);
		pthread_join(th, NULL);
		return WIFEXITED(st) ? WEXITSTATUS(st) : 3;
	}
	c0 = atomic_load(&compiled);
	while (atomic_load(&compiled) < c0 + 50) sched_yield();
	if (write(go[1], "g", 1) != 1) return 3;
	if (waitpid((pid_t)pid, &st, 0) != pid) return 3;
	atomic_store(&stop, 1);
	pthread_join(th, NULL);
	return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
}
