// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <bpf/libbpf.h>
#include <argp.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

#include "common/proteus.h"
#include "user/helpers.h"
#include "proteus.skel.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

const char *argp_program_version = "proteus 0.0";
const char *argp_program_bug_address = "<github@MikeHorn-git>";
const char argp_program_doc[] = "eBPF\n";

static const struct argp_option opts[] = {
	{ "fentry", 'f', NULL, 0, "Fentry tracing" },
	{ "kprobe", 'k', NULL, 0, "Kprobe tracing" },
	{ "lsm", 'l', NULL, 0, "LSM tracing" },
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
	case 'l':
		env.lsm = true;
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

	int pid_key = 0;
	__u8 flag = 1;
	bpf_map_update_elem(bpf_map__fd(skel->maps.pids), &pid_key, &flag,
			    BPF_ANY);

	if (!flags) {
		err = proteus_bpf__attach(skel);
	} else {
		const struct {
			struct bpf_program *prog;
			const char *name;
		} kprobes[] = {
			{ skel->progs.kprobe__bpf, "kprobe__bpf" },
			{ skel->progs.kprobe__init_module,
			  "kprobe__init_module" },
			{ skel->progs.kprobe__finit_module,
			  "kprobe__finit_module" },
			{ skel->progs.kprobe__delete_module,
			  "kprobe__delete_module" },
			{ skel->progs.kprobe__ptrace, "kprobe__ptrace" },
		};

		if (env.kprobe) {
			for (size_t i = 0; i < ARRAY_SIZE(kprobes); i++) {
				if (attach_prog(kprobes[i].prog,
						kprobes[i].name)) {
					goto cleanup;
				}
			}
		}

		const struct {
			struct bpf_program *prog;
			const char *name;
		} tracepoints[] = {
			{ skel->progs.tp__enter_bpf, "tp__enter_bpf" },
			{ skel->progs.tp__exit_bpf, "tp__exit_bpf" },
			{ skel->progs.tp__init_module, "tp__init_module" },
			{ skel->progs.tp__finit_module, "tp__finit_module" },
			{ skel->progs.tp__delete_module, "tp__delete_module" },
			{ skel->progs.tp__enter_ptrace, "tp__enter_ptrace" },
			{ skel->progs.tp__exit_ptrace, "tp__exit_ptrace" },
		};

		if (env.tracepoints) {
			for (size_t i = 0; i < ARRAY_SIZE(tracepoints); i++) {
				if (attach_prog(tracepoints[i].prog,
						tracepoints[i].name)) {
					goto cleanup;
				}
			}
		}

		const struct {
			struct bpf_program *prog;
			const char *name;
		} fentry[] = {
			{ skel->progs.fentry__ptrace, "fentry__ptrace" },
			{ skel->progs.bpf__fentry, "bpf__fentry" },
		};

		if (env.fentry) {
			for (size_t i = 0; i < ARRAY_SIZE(fentry); i++) {
				if (attach_prog(fentry[i].prog,
						fentry[i].name)) {
					goto cleanup;
				}
			}
		}
	}

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL,
			      NULL);
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
