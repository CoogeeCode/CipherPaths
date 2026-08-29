#!/usr/bin/env bash
# Builds the cipherpaths CLI for macOS, x86_64 and arm64 (Apple Silicon,
# 64-bit only). NOT tested by CI/agents in this repo (no Mac available at
# development time) - run and verify manually on real hardware before
# shipping a macOS release.
#
# Prerequisites:
#   xcode-select --install
#   brew install cmake openssl@3
#
# Homebrew does not put openssl@3 on the default include/library search
# path (to avoid clashing with the system's LibreSSL-based /usr/include),
# so its prefix is passed explicitly to CMake below.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMMANDLINE_DIR="$REPO_ROOT/CommandLine"

ARCH="${1:-all}"     # x64 | arm64 | all
CONFIG="${2:-Release}"

OPENSSL_PREFIX="$(brew --prefix openssl@3 2>/dev/null || true)"
if [ -z "$OPENSSL_PREFIX" ]; then
    echo "error: openssl@3 not found via Homebrew. Run: brew install openssl@3" >&2
    exit 1
fi

build_one() {
    local arch="$1"           # x86_64 | arm64
    local out_subdir="$2"     # macos/x64 | macos/arm64
    local build_dir="$REPO_ROOT/build-macos-$arch"
    echo "==> Configuring macOS/$arch"
    cmake -S "$REPO_ROOT" -B "$build_dir" \
        -DCMAKE_BUILD_TYPE="$CONFIG" \
        -DCMAKE_OSX_ARCHITECTURES="$arch" \
        -DOPENSSL_ROOT_DIR="$OPENSSL_PREFIX" \
        -DCIPHERPATHS_OUTPUT_SUBDIR="$out_subdir"
    echo "==> Building macOS/$arch ($CONFIG)"
    cmake --build "$build_dir" --config "$CONFIG" --target cipherpaths -- -j"$(sysctl -n hw.ncpu)"
    echo "==> Built $COMMANDLINE_DIR/$out_subdir/cipherpaths"
}

case "$ARCH" in
    x64) build_one x86_64 macos/x64 ;;
    arm64) build_one arm64 macos/arm64 ;;
    all) build_one x86_64 macos/x64; build_one arm64 macos/arm64 ;;
    *) echo "Usage: $0 [x64|arm64|all] [Release|Debug]" >&2; exit 1 ;;
esac
