# Proteus

![image](https://miro.medium.com/v2/resize:fit:1200/1*jospO_aej1eOiawuQkqBOQ.jpeg)

> [!WARNING]
> This project is a **prototype** and considered **BETA**.

## Table of content

- [Requirements](https://github.com/MikeHorn-git/Proteus#requirements)
- [Installation](https://github.com/MikeHorn-git/Proteus#installation)
- [Usage](https://github.com/MikeHorn-git/Proteus#usage)
- [Credits](https://github.com/MikeHorn-git/Proteus#credits)

## Requirements

- Clang
- Llvm

## Installation

```bash
git clone https://github.com/MikeHorn-git/Proteus --recursive
git submodule update --init --recursive
make
```

## Description

Proteus is a research‑grade Linux eBPF telemetry framework that emulates key EDR primitives—syscall‑level monitoring activities to help maldevs and defenders.

## Features

### Hooks

- [Fentry](https://docs.ebpf.io/linux/concepts/trampolines/)
- [Kprobe](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_KPROBE/)
- [Tracepoint](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_RAW_TRACEPOINT/)

### Monitoring

- Bpf
- Lkm
- Ptrace

## Usage

```bash
Usage: proteus [OPTION...]
eBPF

  -f, --fentry               Fentry tracing
  -k, --kprobe               Kprobe tracing
  -t, --tracepoints          Tracepoints tracing
  -v, --verbose              Verbose output
  -?, --help                 Give this help list
      --usage                Give a short usage message
  -V, --version              Print program version

Report bugs to <github@MikeHorn-git>.
```

## Credits

- [eBPF Docs](https://docs.ebpf.io/)
- [bad-bpf](https://github.com/pathtofile/bad-bpf)
- [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap)
