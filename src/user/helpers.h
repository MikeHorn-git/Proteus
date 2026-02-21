// SPDX-License-Identifier: BSD-3-Clause
/* https://github.com/pathtofile/bad-bpf/blob/main/src/common_um.h */
#ifndef __USER_HELPERS_H_
#define __USER_HELPERS_H_

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

void sigint(int signo)
{
	exiting = 1;
}

static bool sighandler()
{
	// Add handlers for SIGINT and SIGTERM so we shutdown cleanly
	__sighandler_t sighandler = signal(SIGINT, sigint);
	if (sighandler == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n",
			strerror(errno));
		return false;
	}
	sighandler = signal(SIGTERM, sigint);
	if (sighandler == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n",
			strerror(errno));
		return false;
	}
	return true;
}

static int print(enum libbpf_print_level level, const char *format,
		 va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static bool rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr,
			"Failed to increase RLIMIT_MEMLOCK limit! (hint: run as root)\n");
		return false;
	}
	return true;
}

static bool setup()
{
	// Set up libbpf errors and debug info callback
	libbpf_set_print(print);

	// Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything
	if (!rlimit()) {
		return false;
	};

	// Setup signal handler so we exit cleanly
	if (!sighandler()) {
		return false;
	}

	return true;
}

static int attach_prog(struct bpf_program *prog, const char *name)
{
	if (!prog)
		return 0;
	if (!bpf_program__attach(prog)) {
		fprintf(stderr, "Failed to attach %s\n", name);
		return -1;
	}
	return 0;
}

#endif /* __USER_HELPERS_H_ */
