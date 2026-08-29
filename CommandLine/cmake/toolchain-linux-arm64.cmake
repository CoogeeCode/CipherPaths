# CMake toolchain file to cross-compile the Linux ARM64 (aarch64) CLI binary
# from an x86_64 host, using the Debian/Ubuntu cross toolchain packages:
#   sudo apt install -y gcc-aarch64-linux-gnu g++-aarch64-linux-gnu
#
# libssl-dev for arm64 must also be available to the cross linker. The
# easiest route on Debian/Ubuntu is to enable the arm64 architecture and
# install the arm64 dev package alongside the native one:
#   sudo dpkg --add-architecture arm64
#   sudo apt update
#   sudo apt install -y libssl-dev:arm64
#
# Usage (from repo root):
#   cmake -S CommandLine -B build-linux-arm64 \
#         -DCMAKE_TOOLCHAIN_FILE=CommandLine/cmake/toolchain-linux-arm64.cmake \
#         -DCIPHERPATHS_OUTPUT_SUBDIR=linux/arm64
#   cmake --build build-linux-arm64 --config Release

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

set(CMAKE_C_COMPILER aarch64-linux-gnu-gcc)
set(CMAKE_CXX_COMPILER aarch64-linux-gnu-g++)

# Look for headers/libraries only under the target sysroot/multiarch dirs,
# but still allow finding the (host) cross-compiler programs themselves.
set(CMAKE_FIND_ROOT_PATH /usr/aarch64-linux-gnu)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

set(CMAKE_LIBRARY_ARCHITECTURE aarch64-linux-gnu)
