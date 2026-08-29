# cipherpaths-cli - portable command-line front-end for CipherPathsCore.
# Builds identically for Windows, Linux and macOS (x86_64 / ARM64, 64-bit
# only) from the single shared main.cpp - no per-platform source files.
cmake_minimum_required(VERSION 3.20)

# Allow this directory to be configured standalone (cmake -S CommandLine -B
# build), not just as a subdirectory of the top-level CMakeLists.txt.
if (CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    project(CipherPathsCLI CXX)
    if (NOT TARGET CipherPathsCore)
        add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../core" "${CMAKE_CURRENT_BINARY_DIR}/core")
    endif()
endif()

add_executable(cipherpaths main.cpp)
target_link_libraries(cipherpaths PRIVATE CipherPathsCore)
target_compile_features(cipherpaths PRIVATE cxx_std_20)

if (MSVC)
    target_compile_options(cipherpaths PRIVATE /W4)
else()
    target_compile_options(cipherpaths PRIVATE -Wall -Wextra)
endif()

# Every platform's binary lands in its own per-platform/per-arch folder under
# CommandLine/ so the three platforms' outputs never collide, e.g.:
#   CommandLine/windows/x64/cipherpaths.exe
#   CommandLine/windows/arm64/cipherpaths.exe
#   CommandLine/linux/x64/cipherpaths
#   CommandLine/linux/arm64/cipherpaths
#   CommandLine/macos/x64/cipherpaths
#   CommandLine/macos/arm64/cipherpaths
# CIPHERPATHS_OUTPUT_SUBDIR is normally set by the per-platform build script;
# it defaults to a best-effort guess so a bare `cmake --build` still works.
if (NOT CIPHERPATHS_OUTPUT_SUBDIR)
    if (WIN32)
        set(_cp_plat "windows")
    elseif (APPLE)
        set(_cp_plat "macos")
    else()
        set(_cp_plat "linux")
    endif()
    if (CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64")
        set(_cp_arch "arm64")
    else()
        set(_cp_arch "x64")
    endif()
    set(CIPHERPATHS_OUTPUT_SUBDIR "${_cp_plat}/${_cp_arch}")
endif()

set_target_properties(cipherpaths PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/${CIPHERPATHS_OUTPUT_SUBDIR}"
)
foreach(_cfg IN ITEMS Debug Release RelWithDebInfo MinSizeRel)
    string(TOUPPER "${_cfg}" _cfg_upper)
    set_target_properties(cipherpaths PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY_${_cfg_upper} "${CMAKE_CURRENT_SOURCE_DIR}/${CIPHERPATHS_OUTPUT_SUBDIR}"
    )
endforeach()
