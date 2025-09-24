# Proteus

![image](https://miro.medium.com/v2/resize:fit:1200/1*jospO_aej1eOiawuQkqBOQ.jpeg)

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

## Usage

```bash
Usage: proteus [OPTION...]
eBPF process injection

  -p, --target-ppid=PID      PID target.
  -t, --target-ppid=PPID     Optional Parent PID target.
  -v, --verbose              Verbose output
  -?, --help                 Give this help list
      --usage                Give a short usage message
  -V, --version              Print program version

Mandatory or optional arguments to long options are also mandatory or optional
for any corresponding short options.

Report bugs to <github@MikeHorn-git>.
```

## Credits

- [bad-bpf](https://github.com/pathtofile/bad-bpf)
- [libbpf-starter-template](https://github.com/eunomia-bpf/libbpf-starter-template)
