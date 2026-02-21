/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __PROTEUS_H
#define __PROTEUS_H

#define FILENAME_LEN 256
#define TASK_COMM_LEN 16

struct env {
	bool fentry;
	bool kprobe;
	bool lsm;
	bool tracepoints;
	bool verbose;
};

struct event {
	int pid;
	char comm[TASK_COMM_LEN];
	char filename[FILENAME_LEN];
	bool success;
};

#endif /* __PROTEUS_H */
