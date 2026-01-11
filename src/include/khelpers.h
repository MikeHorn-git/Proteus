/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* https://github.com/pathtofile/bad-bpf/blob/main/src/common_um.h */
#ifndef __KHELPERS_H
#define __KHELPERS_H

#include "proteus.h"

#define EPERM	  1 /* Operation not permitted */
#define EACCES	  13 /* Permission denied */
#define MIN(a, b) ((a) < (b) ? (a) : (b))

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// Log kernel land
static __always_inline int ring_buffer(long ret, int pid)
{
	struct event *e;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (e) {
		e->success = (ret == 0);
		e->pid = pid;
		bpf_get_current_comm(&e->comm, sizeof(e->comm));
		bpf_ringbuf_submit(e, 0);
	}

	return 0;
}

#endif /* __KHELPERS_H */
