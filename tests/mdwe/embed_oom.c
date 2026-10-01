/*
** Allocation-failure sweep for the JIT's machine-code allocator (review R1).
**
** For k = 1, 2, ... a forked child fails exactly the k-th Lua allocation after
** arming and must survive: lua_pcall returns 0 with the right result or
** LUA_ERRMEM, the state still runs Lua afterwards, and lua_close completes.
** A panic or signal in any child fails the sweep. The sweep ends at the first
** k that is never reached. Phase "cold": the first trace compiles under the
** sweep. Phase "warm": traces already exist, and small areas (-Osizemcode=4)
** with large traces force further area allocations, past the initial array
** capacity, under the sweep.
**
** Usage: embed-oom [jitopt]   e.g. embed-oom mcoderemap=1 (default: )
** Prints "oom: cold=N warm=M ok" and exits 0 when every child survived.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

#define KMAX 20000

static long countdown = -1;	/* Fail when it reaches 0; -1 = disarmed. */
static int fired;

static void *alloc(void *ud, void *p, size_t osz, size_t nsz)
{
	(void)ud; (void)osz;
	if (nsz == 0) { free(p); return NULL; }
	if (countdown > 0 && --countdown == 0) { fired = 1; countdown = -1; return NULL; }
	return realloc(p, nsz);
}

static int panic(lua_State *L)
{
	fprintf(stderr, "PANIC: %s\n", lua_tostring(L, -1));
	_exit(70);
}

/* Each loop sums TERMS remainders, so traces are large enough that the warm
** phase grows past the allocator's initial 8-area capacity (4 KiB areas). */
#define TERMS 24
#define ITERS 300	/* Well above hotloop (56), so every loop compiles a trace. */

static int run(lua_State *L, int m, long want)
{
	char src[1024];
	int rc, j, n;
	n = snprintf(src, sizeof(src), "local s = 0 for i = 1, %d do s = s", ITERS);
	for (j = 1; j <= TERMS; j++)
		n += snprintf(src + n, sizeof(src) - (size_t)n, " + i %% %d", m + j);
	snprintf(src + n, sizeof(src) - (size_t)n, " end return s");
	if ((rc = luaL_loadstring(L, src))) {
		if (rc != LUA_ERRMEM) return 3;
		lua_settop(L, 0);
		return 0;
	}
	rc = lua_pcall(L, 0, 1, 0);
	if (rc == 0 && (long)lua_tonumber(L, -1) != want) {
		fprintf(stderr, "WRONG m=%d %ld != %ld\n", m, (long)lua_tonumber(L, -1), want);
		return 4;
	}
	if (rc != 0 && rc != LUA_ERRMEM) {
		fprintf(stderr, "pcall rc=%d: %s\n", rc, lua_tostring(L, -1));
		return 5;
	}
	lua_settop(L, 0);
	return 0;
}

static long expect(int m)
{
	long s = 0, i, j;
	for (i = 1; i <= ITERS; i++)
		for (j = 1; j <= TERMS; j++) s += i % (m + j);
	return s;
}

/* Child: returns 0 = survived, 1 = k never reached, other = failure. */
static int child(const char *opt, int warm, long k)
{
	lua_State *L = lua_newstate(alloc, NULL);
	int m, rc;
	if (!L) return 2;
	lua_atpanic(L, panic);
	luaL_openlibs(L);
	if (opt || warm) {
		char s[160];
		snprintf(s, sizeof(s), "jit.opt.start(%s%s%s%s)", opt ? "'" : "", opt ? opt : "",
			 opt ? "'" : "", warm ? (opt ? ", 'sizemcode=4'" : "'sizemcode=4'") : "");
		if (luaL_dostring(L, s)) { fprintf(stderr, "%s\n", lua_tostring(L, -1)); return 2; }
	}
	if (warm)
		for (m = 2; m < 12; m++)
			if ((rc = run(L, m, expect(m)))) return rc;
	countdown = k;
	for (m = 12; m < 40; m++)
		if ((rc = run(L, m, expect(m)))) return rc;
	countdown = -1;
	if ((rc = run(L, 7, expect(7)))) return rc;	/* Still usable afterwards. */
	lua_close(L);
	return fired ? 0 : 1;
}

static long sweep(const char *opt, int warm)
{
	long k;
	for (k = 1; k <= KMAX; k++) {
		int st;
		pid_t pid = fork();
		if (pid < 0) { perror("fork"); exit(2); }
		if (pid == 0) _exit(child(opt, warm, k));
		if (waitpid(pid, &st, 0) < 0) { perror("waitpid"); exit(2); }
		if (WIFEXITED(st) && WEXITSTATUS(st) == 1) return k - 1;
		if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
			printf("oom: FAIL %s k=%ld: %s %d\n", warm ? "warm" : "cold", k,
			       WIFEXITED(st) ? "exit" : "signal",
			       WIFEXITED(st) ? WEXITSTATUS(st) : WTERMSIG(st));
			exit(1);
		}
	}
	printf("oom: FAIL sweep exceeded %d allocations\n", KMAX);
	exit(1);
}

int main(int argc, char **argv)
{
	const char *opt = argc > 1 ? argv[1] : getenv("LJ_EMBED_JITOPT");
	long cold, warm;
	setvbuf(stdout, NULL, _IONBF, 0);
	cold = sweep(opt, 0);
	warm = sweep(opt, 1);
	printf("oom: cold=%ld warm=%ld ok\n", cold, warm);
	return 0;
}
