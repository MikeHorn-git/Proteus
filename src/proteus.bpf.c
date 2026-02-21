// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "bpf/helpers.h"
#include "bpf/logs.h"

#include "bpf/bpf.h"
#include "bpf/lkm.h"
#include "bpf/ptrace.h"

char LICENSE[] SEC("license") = "GPL";
