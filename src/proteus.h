/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* https://github.com/pathtofile/bad-bpf/blob/main/src/common_um.h */
#ifndef __PROTEUS_H
#define __PROTEUS_H

#define TASK_COMM_LEN 16

struct event {
	int pid;
	int ppid;
	char comm[TASK_COMM_LEN];
	bool success;
};

#endif /* __PROTEUS_H */
