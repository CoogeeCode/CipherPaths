#!/usr/bin/env bash
# Builds the cipherpaths CLI for Linux, x86_64 (native) and ARM64 (cross,
# 64-bit only). Run from anywhere; paths are resolved relative to this
# script.
#
# Prerequisites (Debian/Ubuntu):
#   sudo apt update
#   sudo apt install -y build-essential cmake libssl-dev pkg-config \
#                        zlib1g-dev libzstd-dev libjitterentropy3-dev \
#                        gcc-aarch64-linux-gnu g++-aarch64-linux-gnu
#
# The x64 leg is built fully static (libstdc++, libgcc AND OpenSSL, not just
# the C runtime) by default - see the STATIC REBUILD note below for why.
# zlib1g-dev, libzstd-dev and libjitterentropy3-dev are needed for this:
# the system's static libcrypto.a (from libssl-dev) was itself built against
# zlib/zstd/jitterentropy, so linking it statically pulls in their .a files
# too, not just OpenSSL's own. Set CIPHERPATHS_LINUX_DYNAMIC=1 in the
# environment to fall back to a normal dynamically-linked build instead
# (smaller binary, faster incremental relinking, useful for local dev).
#
# The ARM64 leg additionally needs an aarch64 libssl-dev (see
# CommandLine/cmake/toolchain-linux-arm64.cmake for the multiarch setup) and
# is skipped automatically if the cross compiler or the arm64 OpenSSL
# libraries are not present. It is NOT statically linked - the aarch64
# static libs (libcrypto.a, libstdc++.a, libz.a, ...) for the cross
# toolchain aren't set up/verified yet, so it stays dynamic for now.
#
# STATIC REBUILD, 2026-08-23: switched the x64 leg from dynamic to fully
# static (see AGENTS.md's "Linux system requirements" note and
# command-line-guide.html's "System requirements" section for the full
# story). Short version: a dynamically-linked build needs the *target*
# machine to have OpenSSL >= 3.2 for the Argon2id KDF - but Ubuntu 22.04/
# 24.04 LTS, Debian 12 and RHEL/AlmaLinux 9 all still ship OpenSSL 3.0 by
# default, so that requirement fails on most current mainstream servers, not
# just old ones. Static linking bakes a known-good OpenSSL into the binary
# and removes the runtime dependency entirely (verified: the resulting
# binary is `file`-reported as "statically linked" / "not a dynamic
# executable", and the full command suite from AGENTS.md's testing section
# passes against it). The tradeoff: ~9-10 MB instead of ~500 KB, and OpenSSL
# security fixes now require rebuilding+redistributing the CLI rather than
# an OS-level package update on the target machine.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMMANDLINE_DIR="$REPO_ROOT/CommandLine"

ARCH="${1:-all}"     # x64 | arm64 | all
CONFIG="${2:-Release}"
STATIC_X64="${CIPHERPATHS_LINUX_DYNAMIC:+0}"
STATIC_X64="${STATIC_X64:-1}"

check_static_libs() {
    # Static libssl-dev/zlib1g-dev/libzstd-dev/libjitterentropy3-dev all
    # install to this multiarch dir on Debian/Ubuntu.
    local libdir="/usr/lib/x86_64-linux-gnu"
    local missing=()
    for lib in libcrypto.a libz.a libzstd.a libjitterentropy.a; do
        [ -e "$libdir/$lib" ] || missing+=("$lib")
    done
    if [ "${#missing[@]}" -gt 0 ]; then
        echo "==> Missing static libs for a static x64 build: ${missing[*]}" >&2
        echo "    sudo apt install -y libssl-dev zlib1g-dev libzstd-dev libjitterentropy3-dev" >&2
        echo "    ...or set CIPHERPATHS_LINUX_DYNAMIC=1 to build dynamically instead." >&2
        exit 1
    fi
}

build_x64() {
    local build_dir="$REPO_ROOT/build-linux-x64"
    local extra_args=()
    if [ "$STATIC_X64" = "1" ]; then
        check_static_libs
        extra_args+=(-DOPENSSL_USE_STATIC_LIBS=ON -DCMAKE_EXE_LINKER_FLAGS=-static)
        echo "==> Configuring Linux/x64 (static)"
    else
        echo "==> Configuring Linux/x64 (dynamic)"
    fi
    cmake -S "$REPO_ROOT" -B "$build_dir" \
        -DCMAKE_BUILD_TYPE="$CONFIG" \
        -DCIPHERPATHS_OUTPUT_SUBDIR=linux/x64 \
        "${extra_args[@]}"
    echo "==> Building Linux/x64 ($CONFIG)"
    cmake --build "$build_dir" --config "$CONFIG" --target cipherpaths -- -j"$(nproc)"
    echo "==> Built $COMMANDLINE_DIR/linux/x64/cipherpaths"
}

build_arm64() {
    if ! command -v aarch64-linux-gnu-g++ >/dev/null 2>&1; then
        echo "==> Skipping Linux/arm64: aarch64-linux-gnu-g++ not installed" >&2
        return 0
    fi
    if [ ! -e /usr/lib/aarch64-linux-gnu/libcrypto.so ] && \
       [ ! -e /usr/aarch64-linux-gnu/lib/libcrypto.so ]; then
        echo "==> Skipping Linux/arm64: arm64 libssl-dev not installed (see toolchain-linux-arm64.cmake)" >&2
        return 0
    fi
    local build_dir="$REPO_ROOT/build-linux-arm64"
    echo "==> Configuring Linux/arm64 (cross, dynamic)"
    cmake -S "$REPO_ROOT" -B "$build_dir" \
        -DCMAKE_BUILD_TYPE="$CONFIG" \
        -DCMAKE_TOOLCHAIN_FILE="$COMMANDLINE_DIR/cmake/toolchain-linux-arm64.cmake" \
        -DCIPHERPATHS_OUTPUT_SUBDIR=linux/arm64
    echo "==> Building Linux/arm64 ($CONFIG)"
    cmake --build "$build_dir" --config "$CONFIG" --target cipherpaths -- -j"$(nproc)"
    echo "==> Built $COMMANDLINE_DIR/linux/arm64/cipherpaths"
}

case "$ARCH" in
    x64) build_x64 ;;
    arm64) build_arm64 ;;
    all) build_x64; build_arm64 ;;
    *) echo "Usage: $0 [x64|arm64|all] [Release|Debug]" >&2; exit 1 ;;
esac
