/*
** Does the backing of executable pages change instruction-fetch cost?
** Fills a 64 KiB area with 1024 tiny functions (mov eax, imm; ret; 64-byte
** stride), then calls all of them ROUNDS times. Backing (argv[1]):
**   anon         MAP_PRIVATE|MAP_ANONYMOUS, RW then mprotect RX (upstream =1)
**   memfd-priv   memfd written via a shared RW view, then MAP_FIXED RX private (=2)
**   memfd-shared memfd, MAP_FIXED RX shared
** Run under `perf stat -e L1-icache-load-misses,iTLB-load-misses`.
** x86_64 only.
*/
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#define SZ 65536
#define STRIDE 64
#define ROUNDS 20000

typedef int (*fn_t)(void);

int main(int argc, char **argv)
{
	const char *m = argc > 1 ? argv[1] : "anon";
	uint8_t *p, *w;
	long r, i, acc = 0;
	int fd = -1;
	if (!strcmp(m, "anon")) {
		p = w = mmap(NULL, SZ, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	} else {
		fd = (int)syscall(SYS_memfd_create, "exec-bench", 1U|2U|8U);
		if (fd < 0 || ftruncate(fd, SZ)) return 2;
		p = w = mmap(NULL, SZ, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	}
	if (p == MAP_FAILED) return 2;
	for (i = 0; i < SZ / STRIDE; i++) {
		uint8_t *f = w + i * STRIDE;
		int v = (int)i;
		f[0] = 0xb8; memcpy(f + 1, &v, 4); f[5] = 0xc3;
	}
	if (!strcmp(m, "anon")) {
		if (mprotect(p, SZ, PROT_READ|PROT_EXEC)) return 2;
	} else if (!strcmp(m, "memfd-priv")) {
		if (mmap(p, SZ, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED, fd, 0) != p) return 2;
	} else if (!strcmp(m, "memfd-shared")) {
		if (mmap(p, SZ, PROT_READ|PROT_EXEC, MAP_SHARED|MAP_FIXED, fd, 0) != p) return 2;
	} else return 3;
	for (r = 0; r < ROUNDS; r++)
		for (i = 0; i < SZ / STRIDE; i++)
			acc += ((fn_t)(p + i * STRIDE))();
	printf("%s %ld\n", m, acc);
	return 0;
}
