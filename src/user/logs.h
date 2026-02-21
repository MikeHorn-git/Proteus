#ifndef __USER_LOGS_H
#define __USER_LOGS_H

#include "proteus.h"

int ring_buffer(long ret, int pid)
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

#endif /* __USER_LOGS_H_ */
