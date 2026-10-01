/*
** Machine code management.
** Copyright (C) 2005-2026 Mike Pall. See Copyright Notice in luajit.h
*/

#define lj_mcode_c
#define LUA_CORE

#include "lj_obj.h"
#if LJ_HASJIT
#include "lj_gc.h"
#include "lj_err.h"
#include "lj_jit.h"
#include "lj_mcode.h"
#include "lj_trace.h"
#include "lj_dispatch.h"
#include "lj_prng.h"
#endif
#if LJ_HASJIT || LJ_HASFFI
#include "lj_vm.h"
#endif

/* -- OS-specific functions ----------------------------------------------- */

#if LJ_HASJIT || LJ_HASFFI

/* Define this if you want to run LuaJIT with Valgrind. */
#ifdef LUAJIT_USE_VALGRIND
#include <valgrind/valgrind.h>
#endif

#if LJ_TARGET_WINDOWS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#if LJ_TARGET_IOS
void sys_icache_invalidate(void *start, size_t len);
#endif

/* Synchronize data/instruction cache. */
void lj_mcode_sync(void *start, void *end)
{
#ifdef LUAJIT_USE_VALGRIND
  VALGRIND_DISCARD_TRANSLATIONS(start, (char *)end-(char *)start);
#endif
#if LJ_TARGET_X86ORX64
  UNUSED(start); UNUSED(end);
#elif LJ_TARGET_WINDOWS
  FlushInstructionCache(GetCurrentProcess(), start, (char *)end-(char *)start);
#elif LJ_TARGET_IOS
  sys_icache_invalidate(start, (char *)end-(char *)start);
#elif LJ_TARGET_PPC
  lj_vm_cachesync(start, end);
#elif defined(__GNUC__) || defined(__clang__)
  __clear_cache(start, end);
#else
#error "Missing builtin to flush instruction cache"
#endif
}

#if LJ_MCODE_REMAP
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC		0x0001U
#endif
#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING	0x0002U
#endif
#ifndef MFD_NOEXEC_SEAL
#define MFD_NOEXEC_SEAL		0x0008U
#endif

/* Create an anonymous file for machine code (LUAJIT_SECURITY_MCODE=2).
** MFD_NOEXEC_SEAL governs execve(), not mmap(PROT_EXEC), works at every
** vm.memfd_noexec level and leaves the file sealable. Linux < 6.3 rejects
** the flag with EINVAL; retry without it there.
*/
int lj_mcode_memfd(void)
{
  int fd = (int)syscall(SYS_memfd_create, "luajit-mcode",
			MFD_CLOEXEC|MFD_ALLOW_SEALING|MFD_NOEXEC_SEAL);
  if (fd < 0 && errno == EINVAL)
    fd = (int)syscall(SYS_memfd_create, "luajit-mcode",
		      MFD_CLOEXEC|MFD_ALLOW_SEALING);
  return fd;
}
#endif

#endif

#if LJ_HASJIT

#if LJ_TARGET_POSIX
#include <sys/mman.h>
#endif

/* Check for macOS hardened runtime. */
#if LJ_TARGET_POSIX && defined(LUAJIT_ENABLE_OSX_HRT) && LUAJIT_SECURITY_MCODE != 0 && defined(MAP_JIT) && __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ >= 110000
#include <pthread.h>
#define MCMAP_CREATE	MAP_JIT
#else
#define MCMAP_CREATE	0
#endif

#if LUAJIT_SECURITY_MCODE != 0 && !MCMAP_CREATE
/* Protection twiddling failed. Probably due to kernel security. */
static LJ_NORET LJ_NOINLINE void mcode_protfail(jit_State *J)
{
  lua_CFunction panic = J2G(J)->panic;
  if (panic) {
    lua_State *L = J->L;
    setstrV(L, L->top++, lj_err_str(L, LJ_ERR_JITPROT));
    panic(L);
  }
  exit(EXIT_FAILURE);
}
#endif

#if LJ_MCODE_REMAP
static void mc_setprot(jit_State *J, void *p, size_t sz, int prot);
#endif

#if LJ_TARGET_WINDOWS

#define MCPROT_RW	PAGE_READWRITE
#define MCPROT_RX	PAGE_EXECUTE_READ
#define MCPROT_RWX	PAGE_EXECUTE_READWRITE

static void *mcode_alloc_at(uintptr_t hint, size_t sz, DWORD prot)
{
  return LJ_WIN_VALLOC((void *)hint, sz,
		       MEM_RESERVE|MEM_COMMIT|MEM_TOP_DOWN, prot);
}

static void mcode_free(void *p, size_t sz)
{
  UNUSED(sz);
  VirtualFree(p, 0, MEM_RELEASE);
}

static void mcode_setprot(jit_State *J, void *p, size_t sz, DWORD prot)
{
#if LUAJIT_SECURITY_MCODE != 0
  DWORD oprot;
  if (!LJ_WIN_VPROTECT(p, sz, prot, &oprot)) mcode_protfail(J);
#else
  UNUSED(J); UNUSED(p); UNUSED(sz); UNUSED(prot);
#endif
}

#elif LJ_TARGET_POSIX

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS	MAP_ANON
#endif

#define MCPROT_RW	(PROT_READ|PROT_WRITE)
#define MCPROT_RX	(PROT_READ|PROT_EXEC)
#define MCPROT_RWX	(PROT_READ|PROT_WRITE|PROT_EXEC)
#ifdef PROT_MPROTECT
#define MCPROT_CREATE	(PROT_MPROTECT(MCPROT_RWX))
#elif MCMAP_CREATE
#define MCPROT_CREATE	PROT_EXEC
#else
#define MCPROT_CREATE	0
#endif

static void *mcode_alloc_at(uintptr_t hint, size_t sz, int prot)
{
  void *p = mmap((void *)hint, sz, prot|MCPROT_CREATE, MAP_PRIVATE|MAP_ANONYMOUS|MCMAP_CREATE, -1, 0);
  if (p == MAP_FAILED) return NULL;
#if MCMAP_CREATE
  pthread_jit_write_protect_np(0);
#endif
  return p;
}

static void mcode_free(void *p, size_t sz)
{
  munmap(p, sz);
}

static void mcode_setprot(jit_State *J, void *p, size_t sz, int prot)
{
#if LUAJIT_SECURITY_MCODE != 0
#if LJ_MCODE_REMAP
  if (J->mcremap) { mc_setprot(J, p, sz, prot); return; }
#endif
#if MCMAP_CREATE
  UNUSED(J); UNUSED(p); UNUSED(sz);
  pthread_jit_write_protect_np((prot & PROT_EXEC));
#else
  if (mprotect(p, sz, prot)) mcode_protfail(J);
#endif
#else
  UNUSED(J); UNUSED(p); UNUSED(sz); UNUSED(prot);
#endif
}

#else

#error "Missing OS support for explicit placement of executable memory"

#endif

#if LJ_MCODE_REMAP

/* RW^X by memfd remapping (Linux; JIT param mcoderemap, default on for
** LUAJIT_SECURITY_MCODE=2; latched in J->mcremap while no area exists).
**
** Works under MemoryDenyWriteExecute (kernel PR_SET_MDWE or systemd's seccomp
** filter), which refuse mprotect() gaining PROT_EXEC but allow a fresh
** mmap(PROT_READ|PROT_EXEC) of a file. Each mcode area stays at one address,
** backed by a per-jit_State memfd, and switches between a shared RW view and a
** private RX view with MAP_FIXED. No mapping is ever W+X and no mprotect() is
** used. fork() handling: a pthread_atfork prepare handler waits for in-flight
** writes and write-seals every memfd, so neither process can change the
** other's code; each side moves to a fresh memfd ("re-home") before its next
** write. Design and review: docs/MDWE_SPEC.md §5.
*/

#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>

#ifndef F_ADD_SEALS
#define F_ADD_SEALS		1033
#endif
#ifndef F_SEAL_SHRINK
#define F_SEAL_SHRINK		0x0002
#define F_SEAL_GROW		0x0004
#define F_SEAL_WRITE		0x0008
#endif
#ifndef FALLOC_FL_KEEP_SIZE
#define FALLOC_FL_KEEP_SIZE	0x01
#endif
#ifndef FALLOC_FL_PUNCH_HOLE
#define FALLOC_FL_PUNCH_HOLE	0x02
#endif

#define MC_SEALS	(F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE)

typedef struct MCodeArea {
  MCode *p;		/* Address of the area (never changes). */
  size_t sz;
  off_t ofs;		/* Offset in the current memfd. */
  int rw;		/* Currently mapped writable (holds one lock depth). */
} MCodeArea;

typedef struct MCodeExtent {
  off_t ofs;
  size_t sz;
} MCodeExtent;

typedef struct MCodeCtx {
  struct MCodeCtx *next;	/* Process-wide registry for fork handling. */
  pthread_mutex_t lock;	/* Held while any area is writable or the file mutates. */
  pthread_t owner;
  volatile int owned;
  int depth;		/* Nesting of lock holders in the owning thread. */
  int fd;		/* Current memfd. */
  int sealed;		/* Write-sealed by a fork(): re-home before mutating. */
  off_t fsize;
  MCodeArea *area;	/* Registered areas; also the MAP_FIXED guard. */
  MCodeExtent *ext;	/* Punched extents available for reuse. */
  MSize narea, nextent;
  MSize acap, ecap;	/* Capacities: narea <= acap, narea + nextent <= ecap. */
} MCodeCtx;

static pthread_mutex_t mc_reglock = PTHREAD_MUTEX_INITIALIZER;
static MCodeCtx *mc_registry;
static pthread_once_t mc_once = PTHREAD_ONCE_INIT;
static int mc_atfork_ok;

/* Failures inside fork handlers: no lua_State is safe to use there. */
static LJ_NORET void mc_forkfail(const char *what)
{
  fprintf(stderr, "LuaJIT: %s (runtime code generation failed, restricted kernel?)\n", what);
  fflush(stderr);
  abort();
}

/* pthread_atfork prepare: wait for every state's in-flight write, then
** write-seal each memfd so neither side of the fork can modify it.
*/
static void mc_prepare(void)
{
  MCodeCtx *c;
  pthread_mutex_lock(&mc_reglock);
  for (c = mc_registry; c; c = c->next) {
    if (c->owned && pthread_equal(c->owner, pthread_self()))
      mc_forkfail("fork() called while this thread is generating machine code");
    pthread_mutex_lock(&c->lock);
    if (!c->sealed) {
      if (fcntl(c->fd, F_ADD_SEALS, MC_SEALS))
	mc_forkfail("cannot write-seal machine code at fork()");
      c->sealed = 1;
    }
  }
}

/* pthread_atfork parent and child: release in both processes. */
static void mc_release(void)
{
  MCodeCtx *c;
  for (c = mc_registry; c; c = c->next)
    pthread_mutex_unlock(&c->lock);
  pthread_mutex_unlock(&mc_reglock);
}

static void mc_atfork_init(void)
{
  mc_atfork_ok = (pthread_atfork(mc_prepare, mc_release, mc_release) == 0);
}

/* Get (or lazily create) the memfd context of a jit_State. */
static MCodeCtx *mc_ctx(jit_State *J)
{
  MCodeCtx *c = J->mcctx;
  if (!c) {
    pthread_once(&mc_once, mc_atfork_init);
    if (!mc_atfork_ok) mcode_protfail(J);
    c = (MCodeCtx *)lj_mem_new(J->L, sizeof(MCodeCtx));
    memset(c, 0, sizeof(MCodeCtx));
    c->fd = lj_mcode_memfd();
    if (c->fd < 0) {  /* E.g. SystemCallFilter=~memfd_create: never silent. */
      lj_mem_free(J2G(J), c, sizeof(MCodeCtx));
      mcode_protfail(J);
    }
    pthread_mutex_init(&c->lock, NULL);
    pthread_mutex_lock(&mc_reglock);
    c->next = mc_registry;
    mc_registry = c;
    pthread_mutex_unlock(&mc_reglock);
    J->mcctx = c;
  }
  return c;
}

/* Copy all live areas to a fresh memfd and remap them RX from it. Called
** with the lock held and no area writable, after a fork() sealed the file.
*/
static void mc_rehome(jit_State *J, MCodeCtx *c)
{
  int fd = lj_mcode_memfd();
  off_t ofs = 0;
  MSize i;
  if (fd < 0) mcode_protfail(J);
  for (i = 0; i < c->narea; i++) ofs += (off_t)c->area[i].sz;
  if (ftruncate(fd, ofs)) mcode_protfail(J);
  for (ofs = 0, i = 0; i < c->narea; i++) {
    MCodeArea *a = &c->area[i];
    size_t done = 0;
    while (done < a->sz) {  /* Read through the (readable) RX view. */
      ssize_t n = pwrite(fd, (char *)a->p + done, a->sz - done, ofs + (off_t)done);
      if (n <= 0) mcode_protfail(J);
      done += (size_t)n;
    }
    a->ofs = ofs;
    ofs += (off_t)a->sz;
  }
  for (i = 0; i < c->narea; i++) {
    MCodeArea *a = &c->area[i];
    if (mmap(a->p, a->sz, MCPROT_RX, MAP_PRIVATE|MAP_FIXED, fd, a->ofs) != (void *)a->p)
      mcode_protfail(J);  /* No mixed-fd continuation. */
  }
  close(c->fd);  /* Never punched or truncated: the other process may use it. */
  c->fd = fd;
  c->fsize = ofs;
  c->nextent = 0;
  c->sealed = 0;
}

/* Begin a mutation (writable view or file change). Re-homes if sealed. */
static void mc_begin(jit_State *J, MCodeCtx *c, int rehome)
{
  if (c->depth++ == 0) {
    pthread_mutex_lock(&c->lock);
    c->owner = pthread_self();
    c->owned = 1;
  }
  if (rehome && c->sealed) mc_rehome(J, c);
}

static void mc_end(MCodeCtx *c)
{
  if (--c->depth == 0) {
    c->owned = 0;
    pthread_mutex_unlock(&c->lock);
  }
}

/* Hard runtime check before any MAP_FIXED: p/sz must be a registered area. */
static MCodeArea *mc_find(jit_State *J, MCodeCtx *c, void *p, size_t sz)
{
  MSize i;
  if (c)
    for (i = 0; i < c->narea; i++)
      if ((void *)c->area[i].p == p && c->area[i].sz == sz) return &c->area[i];
  mcode_protfail(J);
  return NULL;
}

/* Make every fallible Lua allocation for one more area (context, area and
** extent slots) before the area is published, so an out-of-memory error
** unwinds with J unchanged. Each array has its own capacity, so a failure
** between the two reallocations leaves both sizes correct.
*/
static void mc_reserve(jit_State *J)
{
  MCodeCtx *c = mc_ctx(J);
  if (c->narea + 1 > c->acap) {
    MSize n = c->acap ? 2*c->acap : 8;
    c->area = (MCodeArea *)lj_mem_realloc(J->L, c->area,
      c->acap*sizeof(MCodeArea), n*sizeof(MCodeArea));
    c->acap = n;
  }
  if (c->narea + c->nextent + 1 > c->ecap) {
    MSize n = c->ecap ? 2*c->ecap : 8;
    c->ext = (MCodeExtent *)lj_mem_realloc(J->L, c->ext,
      c->ecap*sizeof(MCodeExtent), n*sizeof(MCodeExtent));
    c->ecap = n;
  }
}

/* Back an accepted reservation with the memfd, mapped RW (after mc_reserve). */
static void mc_area_commit(jit_State *J, MCode *p, size_t sz)
{
  MCodeCtx *c = J->mcctx;
  off_t ofs;
  MSize i;
  mc_begin(J, c, 1);  /* Held while the new area is writable. */
  for (i = 0; i < c->nextent; i++)
    if (c->ext[i].sz == sz) break;
  if (i < c->nextent) {
    ofs = c->ext[i].ofs;
    c->ext[i] = c->ext[--c->nextent];
  } else {
    ofs = c->fsize;
    if (ftruncate(c->fd, ofs + (off_t)sz)) mcode_protfail(J);
    c->fsize = ofs + (off_t)sz;
  }
  if (mmap(p, sz, MCPROT_RW, MAP_SHARED|MAP_FIXED, c->fd, ofs) != (void *)p)
    mcode_protfail(J);
  c->area[c->narea].p = p;
  c->area[c->narea].sz = sz;
  c->area[c->narea].ofs = ofs;
  c->area[c->narea].rw = 1;
  c->narea++;
}

/* Unmap an area; punch and recycle its extent unless the file is sealed. */
static void mc_area_free(jit_State *J, MCode *p, size_t sz)
{
  MCodeCtx *c = J->mcctx;
  MCodeArea *a = mc_find(J, c, p, sz);
  if (a->rw) { a->rw = 0; mc_end(c); }
  mc_begin(J, c, 0);
  munmap(p, sz);
  if (!c->sealed) {
    syscall(SYS_fallocate, c->fd, FALLOC_FL_PUNCH_HOLE|FALLOC_FL_KEEP_SIZE,
	    a->ofs, (off_t)sz);
    c->ext[c->nextent].ofs = a->ofs;
    c->ext[c->nextent].sz = sz;
    c->nextent++;
  }
  *a = c->area[--c->narea];
  mc_end(c);
}

static void mc_setprot(jit_State *J, void *p, size_t sz, int prot)
{
  MCodeCtx *c = J->mcctx;
  MCodeArea *a = mc_find(J, c, p, sz);
  if (prot == MCPROT_RW) {
    if (a->rw) return;
    mc_begin(J, c, 1);  /* May re-home, which updates a->ofs. */
    if (mmap(p, sz, MCPROT_RW, MAP_SHARED|MAP_FIXED, c->fd, a->ofs) != p)
      mcode_protfail(J);  /* A failed MAP_FIXED may leave no mapping at p. */
    a->rw = 1;
  } else {
    if (!a->rw) return;
    if (mmap(p, sz, MCPROT_RX, MAP_PRIVATE|MAP_FIXED, c->fd, a->ofs) != p)
      mcode_protfail(J);
    a->rw = 0;
    mc_end(c);
  }
}

/* Tear down the memfd context when the jit_State is freed. */
void lj_mcode_freestate(jit_State *J)
{
  MCodeCtx *c = J->mcctx, **pp;
  if (!c) return;
  pthread_mutex_lock(&mc_reglock);
  for (pp = &mc_registry; *pp; pp = &(*pp)->next)
    if (*pp == c) { *pp = c->next; break; }
  pthread_mutex_unlock(&mc_reglock);
  close(c->fd);
  pthread_mutex_destroy(&c->lock);
  lj_mem_free(J2G(J), c->area, c->acap*sizeof(MCodeArea));
  lj_mem_free(J2G(J), c->ext, c->ecap*sizeof(MCodeExtent));
  lj_mem_free(J2G(J), c, sizeof(MCodeCtx));
  J->mcctx = NULL;
}

#endif

#ifdef LUAJIT_MCODE_TEST
/* Test wrapper for mcode allocation. DO NOT ENABLE in production! Try:
**   LUAJIT_MCODE_TEST=hhhhhhhhhhhhhhhh luajit -jv main.lua
**   LUAJIT_MCODE_TEST=F luajit -jv main.lua
*/
static void *mcode_alloc_at_TEST(jit_State *J, uintptr_t hint, size_t sz, int prot)
{
  static int test_ofs = 0;
  static const char *test_str;
  if (!test_str) {
    test_str = getenv("LUAJIT_MCODE_TEST");
    if (!test_str) test_str = "";
  }
  switch (test_str[test_ofs]) {
  case 'a':  /* OK for one allocation. */
    test_ofs++;
    /* fallthrough */
  case '\0':  /* EOS: OK for any further allocations. */
    break;
  case 'h':  /* Ignore one hint. */
    test_ofs++;
    /* fallthrough */
  case 'H':  /* Ignore any further hints. */
    hint = 0u;
    break;
  case 'r':  /* Randomize one hint. */
    test_ofs++;
    /* fallthrough */
  case 'R':  /* Randomize any further hints. */
    hint = lj_prng_u64(&J2G(J)->prng) & ~(uintptr_t)0xffffu;
    hint &= ((uintptr_t)1 << (LJ_64 ? 47 : 31)) - 1;
    break;
  case 'f':  /* Fail one allocation. */
    test_ofs++;
    /* fallthrough */
  default:  /* 'F' or unknown: Fail any further allocations. */
    return NULL;
  }
  return mcode_alloc_at(hint, sz, prot);
}
#define mcode_alloc_at(hint, sz, prot)	mcode_alloc_at_TEST(J, hint, sz, prot)
#endif

/* -- MCode area protection ----------------------------------------------- */

#if LUAJIT_SECURITY_MCODE == 0

/* Define this ONLY if page protection twiddling becomes a bottleneck.
**
** It's generally considered to be a potential security risk to have
** pages with simultaneous write *and* execute access in a process.
**
** Do not even think about using this mode for server processes or
** apps handling untrusted external data.
**
** The security risk is not in LuaJIT itself -- but if an adversary finds
** any *other* flaw in your C application logic, then any RWX memory pages
** simplify writing an exploit considerably.
*/
#define MCPROT_GEN	MCPROT_RWX
#define MCPROT_RUN	MCPROT_RWX

static void mcode_protect(jit_State *J, int prot)
{
  UNUSED(J); UNUSED(prot);
}

#else

/* This is the default behaviour and much safer:
**
** Most of the time the memory pages holding machine code are executable,
** but NONE of them is writable.
**
** The current memory area is marked read-write (but NOT executable) only
** during the short time window while the assembler generates machine code.
*/
#define MCPROT_GEN	MCPROT_RW
#define MCPROT_RUN	MCPROT_RX

/* Change protection of MCode area. */
static void mcode_protect(jit_State *J, int prot)
{
  if (J->mcprot != prot) {
    mcode_setprot(J, J->mcarea, J->szmcarea, prot);
    J->mcprot = prot;
  }
}

#endif

/* -- MCode area allocation ----------------------------------------------- */

#ifdef LJ_TARGET_JUMPRANGE

#define MCODE_RANGE64	((1u << LJ_TARGET_JUMPRANGE) - 0x10000u)

/* Set a memory range for mcode allocation with addr in the middle. */
static void mcode_setrange(jit_State *J, uintptr_t addr)
{
#if LJ_TARGET_MIPS
  /* Use the whole 256MB-aligned region. */
  J->mcmin = addr & ~(uintptr_t)((1u << LJ_TARGET_JUMPRANGE) - 1);
  J->mcmax = J->mcmin + (1u << LJ_TARGET_JUMPRANGE);
#else
  /* Every address in the 64KB-aligned range should be able to reach
  ** any other, so MCODE_RANGE64 is only half the (signed) branch range.
  */
  J->mcmin = (addr - (MCODE_RANGE64 >> 1) + 0xffffu) & ~(uintptr_t)0xffffu;
  J->mcmax = J->mcmin + MCODE_RANGE64;
#endif
  /* Avoid wrap-around and the 64KB corners. */
  if (addr < J->mcmin || !J->mcmin) J->mcmin = 0x10000u;
  if (addr > J->mcmax) J->mcmax = ~(uintptr_t)0xffffu;
}

/* Check if an address is in range of the mcode allocation range. */
static LJ_AINLINE int mcode_inrange(jit_State *J, uintptr_t addr, size_t sz)
{
  /* Take care of unsigned wrap-around of addr + sz, too. */
  return addr >= J->mcmin && addr + sz >= J->mcmin && addr + sz <= J->mcmax;
}

/* Get memory within a specific jump range in 64 bit mode. */
static void *mcode_alloc(jit_State *J, size_t sz)
{
  uintptr_t hint;
  int i = 0, j;
  if (!J->mcmin)  /* Place initial range near the interpreter code. */
    mcode_setrange(J, (uintptr_t)(void *)lj_vm_exit_handler);
  else if (!J->mcmax)  /* Switch to a new range (already flushed). */
    goto newrange;
  /* First try a contiguous area below the last one (if in range). */
  hint = (uintptr_t)J->mcarea - sz;
  if (!mcode_inrange(J, hint, sz))  /* Also takes care of NULL J->mcarea. */
    goto probe;
  for (; i < 16; i++) {
    void *p = mcode_alloc_at(hint, sz, MCPROT_GEN);
    if (mcode_inrange(J, (uintptr_t)p, sz))
      return p;  /* Success. */
    else if (p)
      mcode_free(p, sz);  /* Free badly placed area. */
  probe:
    /* Next try probing 64KB-aligned pseudo-random addresses. */
    j = 0;
    do {
      hint = J->mcmin + (lj_prng_u64(&J2G(J)->prng) & MCODE_RANGE64);
      if (++j > 15) goto fail;
    } while (!mcode_inrange(J, hint, sz));
  }
fail:
  if (!J->mcarea) {  /* Switch to a new range now. */
    void *p;
  newrange:
    p = mcode_alloc_at(0, sz, MCPROT_GEN);
    if (p) {
      mcode_setrange(J, (uintptr_t)p + (sz >> 1));
      return p;  /* Success. */
    }
  } else {
    J->mcmax = 0;  /* Switch to a new range after the flush. */
  }
  lj_trace_err(J, LJ_TRERR_MCODEAL);  /* Give up. OS probably ignores hints? */
  return NULL;
}

#else

/* All memory addresses are reachable by relative jumps. */
static void *mcode_alloc(jit_State *J, size_t sz)
{
#if defined(__OpenBSD__) || defined(__NetBSD__) || LJ_TARGET_UWP
  /* Allow better executable memory allocation for OpenBSD W^X mode. */
  void *p = mcode_alloc_at(0, sz, MCPROT_RUN);
  if (p) mcode_setprot(J, p, sz, MCPROT_GEN);
#else
  void *p = mcode_alloc_at(0, sz, MCPROT_GEN);
#endif
  if (!p) lj_trace_err(J, LJ_TRERR_MCODEAL);
  return p;
}

#endif

/* -- MCode area management ----------------------------------------------- */

/* Allocate a new MCode area. */
static void mcode_allocarea(jit_State *J)
{
  MCode *oldarea = J->mcarea;
  size_t sz = (size_t)J->param[JIT_P_sizemcode] << 10;
#if LJ_MCODE_REMAP
  if (!oldarea)  /* Mode can only change while no area exists. */
    J->mcremap = J->param[JIT_P_mcoderemap] != 0;
#endif
#if LJ_MCODE_REMAP
  if (J->mcremap)
    mc_reserve(J);  /* May throw LUA_ERRMEM: nothing is published yet. */
#endif
  J->mcarea = (MCode *)mcode_alloc(J, sz);
#if LJ_MCODE_REMAP
  if (J->mcremap)
    mc_area_commit(J, J->mcarea, sz);  /* Placement accepted: back it, RW. */
#endif
  J->szmcarea = sz;
  J->mcprot = MCPROT_GEN;
  J->mctop = (MCode *)((char *)J->mcarea + J->szmcarea);
  J->mcbot = (MCode *)((char *)J->mcarea + sizeof(MCLink));
  ((MCLink *)J->mcarea)->next = oldarea;
  ((MCLink *)J->mcarea)->size = sz;
  J->szallmcarea += sz;
  J->mcbot = (MCode *)lj_err_register_mcode(J->mcarea, sz, (uint8_t *)J->mcbot);
}

/* Free all MCode areas. */
void lj_mcode_free(jit_State *J)
{
  MCode *mc = J->mcarea;
  J->mcarea = NULL;
  J->szallmcarea = 0;
  while (mc) {
    MCode *next = ((MCLink *)mc)->next;
    size_t sz = ((MCLink *)mc)->size;
    lj_err_deregister_mcode(mc, sz, (uint8_t *)mc + sizeof(MCLink));
#if LJ_MCODE_REMAP
    if (J->mcremap) mc_area_free(J, mc, sz); else
#endif
    mcode_free(mc, sz);
    mc = next;
  }
}

/* -- MCode transactions -------------------------------------------------- */

/* Reserve the remainder of the current MCode area. */
MCode *lj_mcode_reserve(jit_State *J, MCode **lim)
{
  if (!J->mcarea)
    mcode_allocarea(J);
  else
    mcode_protect(J, MCPROT_GEN);
  *lim = J->mcbot;
  return J->mctop;
}

/* Commit the top part of the current MCode area. */
void lj_mcode_commit(jit_State *J, MCode *top)
{
  J->mctop = top;
  mcode_protect(J, MCPROT_RUN);
}

/* Abort the reservation. */
void lj_mcode_abort(jit_State *J)
{
  if (J->mcarea)
    mcode_protect(J, MCPROT_RUN);
}

/* Set/reset protection to allow patching of MCode areas. */
MCode *lj_mcode_patch(jit_State *J, MCode *ptr, int finish)
{
  if (finish) {
    if (J->mcarea == ptr)
      mcode_protect(J, MCPROT_RUN);
    else
      mcode_setprot(J, ptr, ((MCLink *)ptr)->size, MCPROT_RUN);
    return NULL;
  } else {
    uintptr_t base = (uintptr_t)J->mcarea, addr = (uintptr_t)ptr;
    /* Try current area first to use the protection cache. */
    if (addr >= base && addr < base + J->szmcarea) {
      mcode_protect(J, MCPROT_GEN);
      return (MCode *)base;
    }
    /* Otherwise search through the list of MCode areas. */
    for (;;) {
      base = (uintptr_t)(((MCLink *)base)->next);
      lj_assertJ(base != 0, "broken MCode area chain");
      if (addr >= base && addr < base + ((MCLink *)base)->size) {
	mcode_setprot(J, (MCode *)base, ((MCLink *)base)->size, MCPROT_GEN);
	return (MCode *)base;
      }
    }
  }
}

/* Limit of MCode reservation reached. */
void lj_mcode_limiterr(jit_State *J, size_t need)
{
  size_t sizemcode, maxmcode;
  lj_mcode_abort(J);
  sizemcode = (size_t)J->param[JIT_P_sizemcode] << 10;
  maxmcode = (size_t)J->param[JIT_P_maxmcode] << 10;
  if (need * sizeof(MCode) > sizemcode)
    lj_trace_err(J, LJ_TRERR_MCODEOV);  /* Too long for any area. */
  if (J->szallmcarea + sizemcode > maxmcode)
    lj_trace_err(J, LJ_TRERR_MCODEAL);
  mcode_allocarea(J);
  lj_trace_err(J, LJ_TRERR_MCODELM);  /* Retry with new area. */
}

#endif
