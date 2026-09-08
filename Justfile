# Main Justfile for LibAFL
# Provides multiple useful variables.
#
# Must be set:
#   - `FUZZER_NAME`: Name of the executable.
#
# Provides:
#   - `PROFILE`: Profile (either `dev` or `release`). Default is `release`.
#   - `PROFILE_DIR`: Profile directory (either `debug` or `release`).
#   - `TARGET_DIR`: target directry. Defaults to `target`.
#   - `BUILD_DIR`: Root directory in which the program is compiled.
#   - `FUZZER`: Executable path.

PROFILE := env("PROFILE", "release")

PROJECT_DIR := absolute_path(".")
PROFILE_DIR := if PROFILE == "dev" { "debug" } else { "release" }
TARGET_DIR := absolute_path(env("TARGET_DIR", "target"))
BUILD_DIR := TARGET_DIR / PROFILE_DIR

FUZZER_NAME := "Proteus"
FUZZER := BUILD_DIR / FUZZER_NAME

JUSTHASHES := ".justhashes"

default: run

target_dir:
    mkdir -p {{ TARGET_DIR }}

build:
    cargo build --profile {{ PROFILE }}

setcap:
    sudo setcap cap_ipc_lock,cap_sys_ptrace,cap_sys_admin,cap_syslog=ep {{ FUZZER }}

run: build setcap
    {{ FUZZER }}

clean:
    cargo clean
