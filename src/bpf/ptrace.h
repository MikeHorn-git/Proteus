#ifndef _PTRACE_H_
#define _PTRACE_H_

#include "vmlinux.h"
#include "helpers.h"
#include "logs.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* ---- Fentry ---- */

SEC("fentry/__x64_sys_ptrace")
int BPF_PROG(fentry__ptrace)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!__filter_pid())
		return 0;

	// Log trace_pipe
	bpf_printk("[*] ptrace: Detected");
	// Log userland
	ring_buffer(pid);

	return 0;
}

/* ---- Kprobe ---- */

SEC("kprobe/__x64_sys_ptrace")
int BPF_KPROBE(kprobe__ptrace)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!__filter_pid())
		return 0;

	// Log trace_pipe
	bpf_printk("[+] ptrace: Detected");
	// Log userland
	ring_buffer(pid);

	return 0;
}

/* ---- LSM ---- */

//SEC("lsm/ptrace_traceme")

/* ---- Tracepoints ---- */

SEC("tp/syscalls/sys_enter_ptrace")
int BPF_PROG(tp__enter_ptrace)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!__filter_pid())
		return 0;

	// Log trace_pipe
	bpf_printk("[*] ptrace_enter: Detected");
	// Log event
	ring_buffer(pid);

	return 0;
}

SEC("tp/syscalls/sys_exit_ptrace")
int BPF_PROG(tp__exit_ptrace)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!__filter_pid())
		return 0

			// Log trace_pipe
			bpf_printk("[*] ptrace_exit: Detected");
	// Log event
	ring_buffer(pid);

	return 0;
}

#endif /* _PTRACE_H_ */
