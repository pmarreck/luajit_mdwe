/*
** T7: bounded multi-state JIT stress. NTHREADS threads (default 8, max 16),
** each with its own lua_State, compile and run ROUNDS fresh functions and
** check every result against the value computed with the JIT off.
** Prints "stress: threads=N rounds=R ok" and exits 0 on success.
*/
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
#include "luajit.h"

#define ROUNDS 200

static const char *prog =
	"local k = ... "
	"local f = load(('return function(n) local s = 0 for i = 1, n do if i %% %d == 0 then s = s + i else s = s - 1 end end return s end'):format(k % 13 + 2))() "
	"return f(3000)";

static int run(lua_State *L, int k, lua_Number *out)
{
	lua_getglobal(L, "prog");
	lua_pushinteger(L, k);
	if (lua_pcall(L, 1, 1, 0)) return -1;
	*out = lua_tonumber(L, -1);
	lua_pop(L, 1);
	return 0;
}

static void *worker(void *arg)
{
	lua_State *L = luaL_newstate(), *R = luaL_newstate();
	long bad = 0;
	int k;
	(void)arg;
	luaL_openlibs(L); luaL_openlibs(R);
	luaJIT_setmode(R, 0, LUAJIT_MODE_ENGINE|LUAJIT_MODE_OFF);
	if (luaL_loadstring(L, prog) || luaL_loadstring(R, prog)) return (void *)1;
	lua_setglobal(L, "prog"); lua_setglobal(R, "prog");
	for (k = 1; k <= ROUNDS; k++) {
		lua_Number a, b;
		if (run(L, k, &a) || run(R, k, &b) || a != b) bad++;
	}
	lua_close(L); lua_close(R);
	return (void *)bad;
}

int main(void)
{
	const char *e = getenv("NTHREADS");
	int n = e ? atoi(e) : 8, i;
	pthread_t th[16];
	long bad = 0;
	if (n < 1 || n > 16) n = 8;
	for (i = 0; i < n; i++) if (pthread_create(&th[i], NULL, worker, NULL)) return 3;
	for (i = 0; i < n; i++) { void *r; pthread_join(th[i], &r); bad += (long)r; }
	printf("stress: threads=%d rounds=%d %s\n", n, ROUNDS, bad ? "FAIL" : "ok");
	return bad ? 1 : 0;
}
