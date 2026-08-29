# CipherPaths - top-level CMake build.
#
# This is the cross-platform build entry point, used to produce the
# `cipherpaths` command-line tool for Windows, Linux and macOS (x86_64 and
# ARM64, 64-bit only). It builds exactly two targets:
#   - CipherPathsCore  (core/)        portable static library
#   - cipherpaths      (CommandLine/) command-line front-end
#
# The Windows GUI (win/CipherPathsWin.vcxproj) is NOT part of this build; it
# continues to be built from CipherPaths.sln via CipherPathsCore.vcxproj,
# which compiles the same core/ sources through MSBuild instead of CMake. Do
# not add win/ here.
cmake_minimum_required(VERSION 3.20)

project(CipherPaths CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

add_subdirectory(core)
add_subdirectory(CommandLine)
