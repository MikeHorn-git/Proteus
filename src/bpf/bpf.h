#ifndef _BPF_H_
#define _BPF_H_

#include "vmlinux.h"
#include "helpers.h"
#include "logs.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* ---- Fentry ---- */

SEC("fentry/__x64_sys_bpf")
int BPF_PROG(bpf__fentry, enum bpf_cmd cmd, union bpf_attr *attr,
	     unsigned int size)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!__filter_pid())
		return 0;

	// Log trace_pipe
	bpf_printk("[+] Bpf: sys_bpf");
	// Log userland
	ring_buffer(pid);

	return 0;
}

/* ---- Kprobe ---- */

SEC("kprobe/__x64_sys_bpf")
int BPF_KPROBE(kprobe__bpf, enum bpf_cmd cmd, union bpf_attr *attr,
	       unsigned int size)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!__filter_pid())
		return 0;

	// Log trace_pipe
	bpf_printk("[+] Bpf: sys_bpf(cmd=%d, attr=%p, size=%u)", cmd, attr,
		   size);
	// Log userland
	ring_buffer(pid);

	return 0;
}

/* ---- Tracepoints ---- */

SEC("tp/syscalls/sys_enter_bpf")
int BPF_PROG(tp__enter_bpf)
{
	/*
   * field:int cmd;	offset:16;	size:8;	signed:0;
   * field:union bpf_attr * uattr;	offset:24;	size:8;	signed:0;
   * field:unsigned int size;	offset:32;	size:8;	signed:0;
   */
	__u64 cmd = *(__u64 *)((char *)ctx + 16);
	__u64 attr = *(__u64 *)((char *)ctx + 24);
	__u64 size = *(__u64 *)((char *)ctx + 32);

	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!__filter_pid())
		return 0;

	// Log trace_pipe
	bpf_printk(
		"[+] Bpf: bpf_enter(cmd=0x%08lx, uattr=0x%08lx, size=0x%08lx)",
		cmd, attr, size);
	// Log event
	ring_buffer(pid);

	return 0;
}

SEC("tp/syscalls/sys_exit_bpf")
int BPF_PROG(tp__exit_bpf)
{
	/*
   * field:long ret;	offset:16;	size:8;	signed:1;
   */
	__u64 ret = *(__u64 *)((char *)ctx + 16);

	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!__filter_pid())
		return 0;

	// Log trace_pipe
	bpf_printk("[+] Bpf: bpf_exit(ret=0x%lx)", ret);
	// Log event
	ring_buffer(pid);

	return 0;
}

#endif /* _BPF_H_ */
