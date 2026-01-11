#ifndef _PTRACE_H_
#define _PTRACE_H_

#include "vmlinux.h"
#include "helpers.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* ---- Fentry ---- */

SEC("fentry/__x64_sys_ptrace")
int BPF_PROG(ptrace_fentry, int op, void *addr, void *data)
{
	long ret = 0;
	size_t pid_tgid = bpf_get_current_pid_tgid();
	int pid = pid_tgid >> 32;

	// Log trace_pipe
	bpf_printk("[*] ptrace: Detected");
	// Log userland
	ring_buffer(ret, pid);

	return 0;
}

/* ---- Kprobe ---- */

SEC("kprobe/__x64_sys_ptrace")
int bpf_prog(struct pt_regs *ctx)
{
	long ret = 0;
	size_t pid_tgid = bpf_get_current_pid_tgid();
	int pid = pid_tgid >> 32;

	// Read syscall args (cmd, attr pointer)
	// If cmd == BPF_LINK_CREATE && attach_type == BPF_TRACE_FENTRY
	// then log it
	int cmd = PT_REGS_PARM1(ctx); // usually ctx->di
	void *attr = (void *)PT_REGS_PARM2(ctx); // ctx->si
	unsigned int size = PT_REGS_PARM3(ctx); // ctx->dx

	// Log trace_pipe
	bpf_printk("[+] Ptrace: sys_ptrace(cmd=%d, attr=%p, size=%u)", cmd, attr, size);
	// Log userland
	ring_buffer(ret, pid);

	return 0;
}

/* ---- Tracepoints ---- */

SEC("tp/syscalls/sys_enter_ptrace")
int bpf_dos_ptrace_enter(struct trace_event_raw_sys_enter *ctx)
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
	bpf_printk("[*] ptrace_enter: Detected");
	// Log event
	ring_buffer(ret, pid);

	return 0;
}

SEC("tp/syscalls/sys_exit_ptrace")
int bpf_dos_ptrace_exit(struct trace_event_raw_sys_enter *ctx)
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
	bpf_printk("[*] ptrace_exit: Detected");
	// Log event
	ring_buffer(ret, pid);

	return 0;
}

#endif /* _PTRACE_H_ */
