/*
** Cost of one RW->RX protection round trip on a 64 KB mcode-sized area,
** per strategy, touching (writing then executing) one page per round.
** Models lj_mcode_reserve()+lj_mcode_commit() or one exit patch.
**
** Usage: flip-bench <mprotect|remap|dual> [rounds]
** Prints: strategy rounds total_ns ns_per_round
** "mprotect" is upstream and fails under MDWE; run it unrestricted.
*/
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#ifndef MFD_EXEC
#define MFD_EXEC 0x0010U
#endif
#define SZ 65536

typedef int (*fn_t)(void);

#if defined(__x86_64__)
static void emit(uint8_t *p, int v) { p[0] = 0xb8; memcpy(p+1, &v, 4); p[5] = 0xc3; }
#elif defined(__aarch64__)
static void emit(uint8_t *p, int v)
{
	uint32_t i0 = 0x52800000u | ((uint32_t)(v & 0xffff) << 5), i1 = 0xd65f03c0u;
	memcpy(p, &i0, 4); memcpy(p+4, &i1, 4);
}
#endif

static uint64_t now_ns(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return (uint64_t)t.tv_sec * 1000000000u + (uint64_t)t.tv_nsec;
}

static void die(const char *m) { perror(m); exit(2); }

int main(int argc, char **argv)
{
	const char *s = argc > 1 ? argv[1] : "";
	long rounds = argc > 2 ? atol(argv[2]) : 20000, i;
	uint8_t *x, *w;
	int fd = -1, acc = 0;
	uint64_t t0, t1;
	if (!strcmp(s, "mprotect")) {
		x = w = mmap(NULL, SZ, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	} else {
		fd = (int)syscall(SYS_memfd_create, "flip-bench", MFD_CLOEXEC|MFD_EXEC);
		if (fd < 0 || ftruncate(fd, SZ)) die("memfd");
		x = w = mmap(NULL, SZ, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
		if (!strcmp(s, "dual"))
			x = mmap(NULL, SZ, PROT_READ|PROT_EXEC, MAP_SHARED, fd, 0);
		else if (strcmp(s, "remap")) { fprintf(stderr, "usage: flip-bench <mprotect|remap|dual> [rounds]\n"); return 3; }
	}
	if (x == MAP_FAILED || w == MAP_FAILED) die("mmap");
	t0 = now_ns();
	for (i = 0; i < rounds; i++) {
		size_t off = (size_t)(i % (SZ / 4096)) * 4096;
		if (!strcmp(s, "mprotect")) {
			if (mprotect(x, SZ, PROT_READ|PROT_WRITE)) die("mprotect RW");
		} else if (!strcmp(s, "remap")) {
			if (mmap(x, SZ, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_FIXED, fd, 0) == MAP_FAILED) die("remap RW");
		}
		emit(w + off, (int)i);
		if (!strcmp(s, "mprotect")) {
			if (mprotect(x, SZ, PROT_READ|PROT_EXEC)) die("mprotect RX");
		} else if (!strcmp(s, "remap")) {
			if (mmap(x, SZ, PROT_READ|PROT_EXEC, MAP_SHARED|MAP_FIXED, fd, 0) == MAP_FAILED) die("remap RX");
		}
		__builtin___clear_cache((char *)x + off, (char *)x + off + 16);
		acc += ((fn_t)(x + off))();
	}
	t1 = now_ns();
	printf("%s %ld %llu %.1f\n", s, rounds, (unsigned long long)(t1 - t0), (double)(t1 - t0) / (double)rounds);
	return acc == 0x7fffffff;  /* Keep the calls observable. */
}
