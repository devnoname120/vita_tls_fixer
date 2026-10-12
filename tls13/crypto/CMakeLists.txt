set(TLS_FIXER_MBEDTLS_ARCHIVE
    "${CMAKE_CURRENT_LIST_DIR}/../../build/deps/mbedtls-4.2.0.tar.bz2"
    CACHE FILEPATH "Checksum-pinned official Mbed TLS release archive")
if(NOT EXISTS "${TLS_FIXER_MBEDTLS_ARCHIVE}")
    message(FATAL_ERROR "Run python3 tools/fetch_mbedtls.py on the host before configuring TLS targets")
endif()
file(SHA256 "${TLS_FIXER_MBEDTLS_ARCHIVE}" tls_fixer_archive_sha256)
if(NOT tls_fixer_archive_sha256 STREQUAL "2bed9d713b4668f76553b097e72b8aa30bc8f112a940d7ae228d524bbde6ffea")
    message(FATAL_ERROR "Mbed TLS release archive SHA-256 mismatch")
endif()

set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(GEN_FILES OFF CACHE BOOL "" FORCE)
set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "" FORCE)
set(USE_STATIC_MBEDTLS_LIBRARY ON CACHE BOOL "" FORCE)
set(MBEDTLS_USER_CONFIG_FILE "${CMAKE_CURRENT_LIST_DIR}/mbedtls_user_config.h" CACHE FILEPATH "" FORCE)
set(TF_PSA_CRYPTO_USER_CONFIG_FILE "${CMAKE_CURRENT_LIST_DIR}/psa_user_config.h" CACHE FILEPATH "" FORCE)

include(FetchContent)
include_directories(BEFORE "${CMAKE_CURRENT_LIST_DIR}")
if(POLICY CMP0135)
    cmake_policy(SET CMP0135 NEW)
endif()
FetchContent_Declare(tls_fixer_mbedtls
    URL "${TLS_FIXER_MBEDTLS_ARCHIVE}"
    URL_HASH SHA256=2bed9d713b4668f76553b097e72b8aa30bc8f112a940d7ae228d524bbde6ffea
)
FetchContent_MakeAvailable(tls_fixer_mbedtls)
# The Vita headers declare inet_pton without a compatible linked implementation.
# Upstream also uses this selector on platforms requiring its internal IP parser.
target_compile_definitions(mbedx509 PRIVATE MBEDTLS_TEST_SW_INET_PTON)
foreach(target mbedtls mbedx509 tfpsacrypto)
    target_include_directories(${target} PUBLIC "${CMAKE_CURRENT_LIST_DIR}")
    target_compile_options(${target} PRIVATE -ffunction-sections -fdata-sections -O2)
endforeach()
