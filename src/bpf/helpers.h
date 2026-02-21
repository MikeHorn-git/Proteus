#ifndef __BPF_MAPS_H_
#define __BPF_MAPS_H_

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define EPERM 1 /* Operation not permitted */
#define EACCES 13 /* Permission denied */
#define MIN(a, b) ((a) < (b) ? (a) : (b))

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, int);
	__type(value, __u8);
} pids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline int __filter_pid(void)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	// Skip own PID
	//int pid_key = 0;
	//__u8 *getpid = bpf_map_lookup_elem(&pids, &pid_key);
	//if (getpid) {
	//return 0;
	//}

	// Skip traced
	__u8 flag = 1;
	__u8 *exists = bpf_map_lookup_elem(&pids, &pid);
	if (exists)
		return 0;
	bpf_map_update_elem(&pids, &pid, &flag, BPF_ANY);
	return 1;
}

#endif /* __BPF_MAPS_H_ */
