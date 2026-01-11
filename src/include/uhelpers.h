// SPDX-License-Identifier: BSD-3-Clause
/* https://github.com/pathtofile/bad-bpf/blob/main/src/common_um.h */
#ifndef __UHELPERS_H
#define __UHELPERS_H

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <errno.h>
#include <fcntl.h>
#include "proteus.h"

struct env env;

static volatile sig_atomic_t exiting;

void ubpf_sigint(int signo)
{
	exiting = 1;
}

static bool ubpf_sighandler()
{
	// Add handlers for SIGINT and SIGTERM so we shutdown cleanly
	__sighandler_t sighandler = signal(SIGINT, ubpf_sigint);
	if (sighandler == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		return false;
	}
	sighandler = signal(SIGTERM, ubpf_sigint);
	if (sighandler == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		return false;
	}
	return true;
}

static int ubpf_print(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static bool ubpf_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit! (hint: run as root)\n");
		return false;
	}
	return true;
}

static bool setup()
{
	// Set up libbpf errors and debug info callback
	libbpf_set_print(ubpf_print);

	// Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything
	if (!ubpf_rlimit()) {
		return false;
	};

	// Setup signal handler so we exit cleanly
	if (!ubpf_sighandler()) {
		return false;
	}

	return true;
}

#endif /* __UHELPERS_H */
