#ifndef _LKM_H_
#define _LKM_H_

#include "vmlinux.h"
#include "helpers.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* ---- Fentry ---- */

/* ---- Kprobe ---- */

SEC("kprobe/__x64_sys_init_module")
int BPF_KPROBE(init_module, int dfd, struct filename *name)
{
	long ret = 0;
	size_t pid_tgid = bpf_get_current_pid_tgid();
	int pid = pid_tgid >> 32;

	// Log trace_pipe
	bpf_printk("[+] lkm_init: Detected");
	// Log userland
	ring_buffer(ret, pid);

	return 0;
}

SEC("kprobe/__x64_sys_finit_module")
int BPF_KPROBE(finit_module, long ret)
{
	size_t pid_tgid = bpf_get_current_pid_tgid();
	int pid = pid_tgid >> 32;

	// Log trace_pipe
	bpf_printk("[+] lkm_finit: Detected");
	// Log userland
	ring_buffer(ret, pid);

	return 0;
}

SEC("kprobe/__x64_sys_delete_module")
int BPF_KPROBE(delete_module, long ret)
{
	size_t pid_tgid = bpf_get_current_pid_tgid();
	int pid = pid_tgid >> 32;

	// Log trace_pipe
	bpf_printk("[+] lkm_delete: Detected");
	// Log userland
	ring_buffer(ret, pid);

	return 0;
}

/* ---- Tracepoints ---- */

SEC("tp/syscalls/sys_enter_init_module")
int bpf_dos_lkm_init(struct trace_event_raw_sys_enter *ctx)
{
	long ret = 0;
	size_t pid_tgid = bpf_get_current_pid_tgid();
	int pid = pid_tgid >> 32;

	// Filter events
	u8 flag = 1;
	u8 *exists = bpf_map_lookup_elem(&pids, &pid);
	if (exists)
		return 0;
	bpf_map_update_elem(&pids, &pid, &flag, BPF_ANY);

	// Log trace_pipe
	bpf_printk("[*] lkm_init: Detected");
	// Log event
	ring_buffer(ret, pid);

	return 0;
}

SEC("tp/syscalls/sys_enter_finit_module")
int bpf_dos_lkm_finit(struct trace_event_raw_sys_enter *ctx)
{
	long ret = 0;
	size_t pid_tgid = bpf_get_current_pid_tgid();
	int pid = pid_tgid >> 32;

	// Filter events
	u8 flag = 1;
	u8 *exists = bpf_map_lookup_elem(&pids, &pid);
	if (exists)
		return 0;
	bpf_map_update_elem(&pids, &pid, &flag, BPF_ANY);

	// Log trace_pipe
	bpf_printk("[*] lkm_finit: Detected");
	// Log event
	ring_buffer(ret, pid);

	return 0;
}

SEC("tp/syscalls/sys_enter_delete_module")
int bpf_dos_lkm_delete(struct trace_event_raw_sys_enter *ctx)
{
	long ret = 0;
	size_t pid_tgid = bpf_get_current_pid_tgid();
	int pid = pid_tgid >> 32;

	// Filter events
	u8 flag = 1;
	u8 *exists = bpf_map_lookup_elem(&pids, &pid);
	if (exists)
		return 0;
	bpf_map_update_elem(&pids, &pid, &flag, BPF_ANY);

	// Log trace_pipe
	bpf_printk("[*] lkm_delete: Detected");
	// Log event
	ring_buffer(ret, pid);

	return 0;
}

#endif /* _LKM_H_ */
