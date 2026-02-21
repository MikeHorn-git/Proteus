#ifndef _LKM_H_
#define _LKM_H_

#include "vmlinux.h"
#include "helpers.h"
#include "logs.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* ---- Kprobe ---- */

SEC("kprobe/__x64_sys_init_module")
int BPF_KPROBE(kprobe__init_module)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!__filter_pid())
		return 0;

	// Log trace_pipe
	bpf_printk("[+] lkm_init: Detected");
	// Log userland
	ring_buffer(pid);

	return 0;
}

SEC("kprobe/__x64_sys_finit_module")
int BPF_KPROBE(kprobe__finit_module, int fd, const char *uargs, int flags)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!__filter_pid())
		return 0;

	// Log trace_pipe
	bpf_printk("[+] lkm_finit: Detected");
	// Log userland
	ring_buffer(pid);

	return 0;
}

SEC("kprobe/__x64_sys_delete_module")
int BPF_KPROBE(kprobe__delete_module)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!__filter_pid())
		return 0;

	// Log trace_pipe
	bpf_printk("[+] lkm_delete: Detected");
	// Log userland

	return 0;
}

/* ---- Tracepoints ---- */

SEC("tp/syscalls/sys_enter_init_module")
int BPF_PROG(tp__init_module)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!__filter_pid())
		return 0;

	// Log trace_pipe
	bpf_printk("[*] lkm_init: Detected");
	// Log event
	ring_buffer(pid);

	return 0;
}

SEC("tp/syscalls/sys_enter_finit_module")
int BPF_PROG(tp__finit_module)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!__filter_pid())
		return 0;

	// Log trace_pipe
	bpf_printk("[*] lkm_finit: Detected");
	// Log event
	ring_buffer(pid);

	return 0;
}

SEC("tp/syscalls/sys_enter_delete_module")
int BPF_PROG(tp__delete_module)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!__filter_pid())
		return 0;
	// Log trace_pipe
	bpf_printk("[*] lkm_delete: Detected");
	// Log event
	ring_buffer(pid);

	return 0;
}

#endif /* _LKM_H_ */
