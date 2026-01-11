// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <bpf/libbpf.h>
#include <argp.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

#include "include/uhelpers.h"
#include "include/proteus.h"
#include "proteus.skel.h"

const char *argp_program_version = "proteus 0.0";
const char *argp_program_bug_address = "<github@MikeHorn-git>";
const char argp_program_doc[] = "eBPF\n";

static const struct argp_option opts[] = {
	{ "fentry", 'f', NULL, 0, "Fentry tracing" },
	{ "kprobe", 'k', NULL, 0, "Kprobe tracing" },
	{ "tracepoints", 't', NULL, 0, "Tracepoints tracing" },
	{ "verbose", 'v', NULL, 0, "Verbose output" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'f':
		env.fentry = true;
		break;
	case 'k':
		env.kprobe = true;
		break;
	case 't':
		env.tracepoints = true;
		break;
	case 'v':
		env.verbose = true;
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

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	if (e->success)
		printf("[+] Event: %s-%d\n", e->comm, e->pid);
	else
		printf("[-] Event: %s-%d\n", e->comm, e->pid);
	fflush(stdout);
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

	bool flags = env.fentry || env.kprobe || env.tracepoints;

	/* Do common setup */
	if (!setup())
		return 1;

	/* Load and verify BPF application */
	skel = proteus_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = proteus_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	if (!flags) {
		err = proteus_bpf__attach(skel);
	} else {
		if (env.kprobe) {
			if (skel->progs.bpf_prog_kprobe &&
			    !bpf_program__attach(skel->progs.bpf_prog_kprobe)) {
				fprintf(stderr, "Failed to attach bpf_prog_kprobe\n");
				goto cleanup;
			}
			if (skel->progs.init_module &&
			    !bpf_program__attach(skel->progs.init_module)) {
				fprintf(stderr, "Failed to attach init_module kprobe\n");
				goto cleanup;
			}
			if (skel->progs.finit_module &&
			    !bpf_program__attach(skel->progs.finit_module)) {
				fprintf(stderr, "Failed to attach finit_module kprobe\n");
				goto cleanup;
			}
			if (skel->progs.delete_module &&
			    !bpf_program__attach(skel->progs.delete_module)) {
				fprintf(stderr, "Failed to attach delete_module kprobe\n");
				goto cleanup;
			}
			if (skel->progs.bpf_prog && !bpf_program__attach(skel->progs.bpf_prog)) {
				fprintf(stderr, "Failed to attach ptrace kprobe\n");
				goto cleanup;
			}
		}

		if (env.tracepoints) {
			if (skel->progs.bpf_dos_bpf_enter &&
			    !bpf_program__attach(skel->progs.bpf_dos_bpf_enter)) {
				fprintf(stderr, "Failed to attach bpf_dos_bpf_enter\n");
				goto cleanup;
			}
			if (skel->progs.bpf_dos_bpf_exit &&
			    !bpf_program__attach(skel->progs.bpf_dos_bpf_exit)) {
				fprintf(stderr, "Failed to attach bpf_dos_bpf_exit\n");
				goto cleanup;
			}
			if (skel->progs.bpf_dos_lkm_init &&
			    !bpf_program__attach(skel->progs.bpf_dos_lkm_init)) {
				fprintf(stderr, "Failed to attach bpf_dos_lkm_init\n");
				goto cleanup;
			}
			if (skel->progs.bpf_dos_lkm_finit &&
			    !bpf_program__attach(skel->progs.bpf_dos_lkm_finit)) {
				fprintf(stderr, "Failed to attach bpf_dos_lkm_finit\n");
				goto cleanup;
			}
			if (skel->progs.bpf_dos_lkm_delete &&
			    !bpf_program__attach(skel->progs.bpf_dos_lkm_delete)) {
				fprintf(stderr, "Failed to attach bpf_dos_lkm_delete\n");
				goto cleanup;
			}
			if (skel->progs.bpf_dos_ptrace_enter &&
			    !bpf_program__attach(skel->progs.bpf_dos_ptrace_enter)) {
				fprintf(stderr, "Failed to attach bpf_dos_ptrace_enter\n");
				goto cleanup;
			}
			if (skel->progs.bpf_dos_ptrace_exit &&
			    !bpf_program__attach(skel->progs.bpf_dos_ptrace_exit)) {
				fprintf(stderr, "Failed to attach bpf_dos_ptrace_exit\n");
				goto cleanup;
			}
		}

		if (env.fentry) {
			if (skel->progs.ptrace_fentry &&
			    !bpf_program__attach(skel->progs.ptrace_fentry)) {
				fprintf(stderr, "Failed to attach ptrace_fentry\n");
				goto cleanup;
			}
			if (skel->progs.bpf_fentry &&
			    !bpf_program__attach(skel->progs.bpf_fentry)) {
				fprintf(stderr, "Failed to attach bpf_fentry\n");
				goto cleanup;
			}
		}
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
