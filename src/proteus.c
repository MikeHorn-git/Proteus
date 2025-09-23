// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <argp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "proteus.skel.h"
#include "proteus.h"

// Setup Argument stuff
static struct env {
	int pid_to_hide;
	int target_pid;
	int target_ppid;
	bool verbose;
} env;

const char *argp_program_version = "proteus 0.0";
const char *argp_program_bug_address = "<github@MikeHorn-git>";
const char argp_program_doc[] = "eBPF process injection\n"
				"\n"
				"USAGE: ./proteus -p [-t]\n";

static const struct argp_option opts[] = {
	{ "target-ppid", 'p', "PID", 0, "PID target." },
	{ "target-ppid", 't', "PPID", 0, "Optional Parent PID target." },
	{ "verbose", 'v', NULL, 0, "Verbose output" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'p':
		errno = 0;
		env.target_pid = strtol(arg, NULL, 10);
		if (errno || env.target_pid <= 0) {
			fprintf(stderr, "Invalid pid: %s\n", arg);
			argp_usage(state);
		}
		break;

	case 't':
		errno = 0;
		env.target_ppid = strtol(arg, NULL, 10);
		if (errno || env.target_ppid <= 0) {
			fprintf(stderr, "Invalid ppid: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'v':
		env.verbose = true;
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}
static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	if (e->success)
		printf("Sucess: %d | %s\n", e->pid, e->comm);
	else
		printf("Failed: %d | %s\n", e->pid, e->comm);
	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct proteus_bpf *skel;
	int err;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = proteus_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Parameterize BPF code with (P)Pid */
	skel->rodata->target_pid = env.target_pid;
	skel->rodata->target_ppid = env.target_ppid;

	/* Load & verify BPF programs */
	err = proteus_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	err = proteus_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF program: %s\n", strerror(errno));
		goto cleanup;
	}

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

cleanup:
	/* Clean up */
	ring_buffer__free(rb);
	proteus_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
