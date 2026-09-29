/*
** Launch a command under the kernel's PR_SET_MDWE (Linux >= 6.3), the
** non-seccomp counterpart of systemd's MemoryDenyWriteExecute.
**
** Usage: mdwe-exec [--] command [args...]
*/
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

#ifndef PR_SET_MDWE
#define PR_SET_MDWE 65
#define PR_GET_MDWE 66
#endif
#ifndef PR_MDWE_REFUSE_EXEC_GAIN
#define PR_MDWE_REFUSE_EXEC_GAIN (1UL << 0)
#endif

int main(int argc, char **argv)
{
	int i = 1;
	if (i < argc && !strcmp(argv[i], "--")) i++;
	if (i >= argc) {
		fprintf(stderr, "usage: mdwe-exec [--] command [args...]\n");
		return 125;
	}
	if (prctl(PR_SET_MDWE, PR_MDWE_REFUSE_EXEC_GAIN, 0L, 0L, 0L)) {
		fprintf(stderr, "mdwe-exec: PR_SET_MDWE failed: %s\n", strerror(errno));
		return 125;
	}
	execvp(argv[i], argv + i);
	fprintf(stderr, "mdwe-exec: exec %s: %s\n", argv[i], strerror(errno));
	return 127;
}
