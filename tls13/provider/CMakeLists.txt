include("${VITASDK}/share/vita.cmake" REQUIRED)
set(TLS_FIXER_HTTP_CA_PATH "vs0:/data/external/cert/CA_LIST.cer" CACHE STRING
    "Authoritative HTTP trust bundle; diagnostics use a separately staged VPK bundle")

add_executable(tls_fixer_http
    ca_file.c
    cert_hooks.c
    provider.c
    platform_shims.c
    private_mapping.c
    transport.c
    trust_store.c
    user_runtime.c
    vita_net.c
)
if(TLS_FIXER_ENABLE_DEBUG_LOG)
    target_sources(tls_fixer_http PRIVATE trace.c)
endif()

target_include_directories(tls_fixer_http PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

target_compile_features(tls_fixer_http PRIVATE c_std_11)
target_compile_definitions(tls_fixer_http PRIVATE
    TLS_FIXER_ENABLE_DEBUG_LOG=$<BOOL:${TLS_FIXER_ENABLE_DEBUG_LOG}>
    TLS_FIXER_FILE_LOG=1
    TLS_FIXER_TRACE_COMPONENT="http"
    TLS_FIXER_TRACE_RECORD_LIMIT=4096
    TLS_FIXER_DEFAULT_CA_PATH="${TLS_FIXER_HTTP_CA_PATH}"
)
target_compile_options(tls_fixer_http PRIVATE
    -std=gnu11
    -Wall
    -Wextra
    -Werror
    -Wshadow
    -Wstrict-prototypes
    -ffunction-sections
    -fdata-sections
    -O2
)

target_link_options(tls_fixer_http PRIVATE
    -nostdlib
    -Wl,--gc-sections
    -Wl,--undefined=module_start
    -Wl,--undefined=module_stop
)
set(tls_fixer_runtime_wrappers malloc calloc realloc free memchr memcmp memcpy memmove memset
    strchr strcmp strlen strstr printf puts snprintf vsnprintf)
foreach(function ${tls_fixer_runtime_wrappers})
    target_link_options(tls_fixer_http PRIVATE "-Wl,--wrap=${function}")
endforeach()
set_source_files_properties(user_runtime.c PROPERTIES COMPILE_OPTIONS "-fno-builtin")

target_link_libraries(tls_fixer_http PRIVATE
    tls_fixer_core
    mbedtls
    mbedx509
    tfpsacrypto
    gcc
    SceAppMgr_stub
    SceSysmem_stub
    SceNet_stub
    SceIofilemgr_stub
    SceRtc_stub
    SceLibKernel_stub
    SceKernelModulemgr_stub
    SceKernelThreadMgr_stub
    taihen_stub
)

vita_create_self(
    tls_fixer_http.suprx
    tls_fixer_http
    CONFIG ${CMAKE_CURRENT_SOURCE_DIR}/tls_fixer_http.yml
    UNSAFE
)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
add_custom_target(tls_fixer_http_runtime_check ALL
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/../../tools/check_http_runtime.py
        ${CMAKE_CURRENT_BINARY_DIR}/tls_fixer_http.suprx
    DEPENDS tls_fixer_http.suprx-self
    VERBATIM
)
