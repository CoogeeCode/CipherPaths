# CipherPathsCore - portable static library, CMake build (Linux/macOS/Windows).
#
# This is the cross-platform counterpart to CipherPathsCore.vcxproj, which
# remains the build used by the Windows GUI (win/CipherPathsWin.vcxproj) via
# CipherPaths.sln. The two build systems compile the exact same sources under
# include/ and src/ and must be kept in sync when files are added or removed.
#
# On Windows this target reuses the same pre-built static OpenSSL package as
# the .vcxproj build (Static-Libs/OpenSSL/<arch>), so no extra Windows
# dependency (vcpkg, etc.) is introduced. On Linux/macOS it links the system
# OpenSSL (>= 3.2, required for the Argon2id KDF provider).

add_library(CipherPathsCore STATIC
    src/Crypto.cpp
    src/Encoding.cpp
    src/EncryptedFileSystem.cpp
    src/Errors.cpp
    src/Json.cpp
    src/NameCodec.cpp
    src/NotesService.cpp
    src/PasswordEntry.cpp
    src/SearchService.cpp
    src/Vault.cpp
    src/VaultManager.cpp
    src/ViewerService.cpp
)

target_include_directories(CipherPathsCore PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)
target_compile_features(CipherPathsCore PUBLIC cxx_std_20)

if (MSVC)
    # Reuse the prebuilt static libcrypto used by the Windows GUI build
    # (only libcrypto is needed - no TLS). Map the CMake platform name onto
    # the folder names used under Static-Libs/OpenSSL (lowercase "arm64",
    # "x64").
    set(_cp_openssl_arch "x64")
    if (CMAKE_GENERATOR_PLATFORM MATCHES "ARM64" OR CMAKE_VS_PLATFORM_NAME MATCHES "ARM64")
        set(_cp_openssl_arch "arm64")
    elseif (CMAKE_SIZEOF_VOID_P EQUAL 4)
        message(FATAL_ERROR "CipherPaths is 64-bit only; 32-bit MSVC targets are not supported.")
    endif()

    set(_cp_openssl_root "${CMAKE_CURRENT_SOURCE_DIR}/../Static-Libs/OpenSSL/${_cp_openssl_arch}")
    if (NOT EXISTS "${_cp_openssl_root}/lib/libcrypto.lib")
        message(FATAL_ERROR "Prebuilt OpenSSL static lib not found at ${_cp_openssl_root}. "
                             "Expected the same Static-Libs/OpenSSL layout used by CipherPathsCore.vcxproj.")
    endif()

    target_include_directories(CipherPathsCore SYSTEM PUBLIC "${_cp_openssl_root}/include")
    target_link_libraries(CipherPathsCore PUBLIC "${_cp_openssl_root}/lib/libcrypto.lib"
                                                  ws2_32 crypt32 advapi32 user32 gdi32)
    # Match the /MD (dynamic CRT) runtime linkage the prebuilt libcrypto.lib
    # and the Windows GUI build both use.
    set_property(TARGET CipherPathsCore PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
else()
    if (CMAKE_SIZEOF_VOID_P EQUAL 4)
        message(FATAL_ERROR "CipherPaths is 64-bit only; 32-bit targets are not supported.")
    endif()

    find_package(OpenSSL 3.2 REQUIRED)
    target_link_libraries(CipherPathsCore PUBLIC OpenSSL::Crypto)
endif()
