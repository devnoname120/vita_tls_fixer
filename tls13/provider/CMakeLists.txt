include("${VITASDK}/share/vita.cmake" REQUIRED)

add_executable(tls_fixer_http
    ca_file.c
    cert_hooks.c
    provider.c
    platform_shims.c
    transport.c
    trust_store.c
    vita_net.c
)

target_include_directories(tls_fixer_http PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

target_compile_features(tls_fixer_http PRIVATE c_std_11)
target_compile_definitions(tls_fixer_http PRIVATE
    TLS_FIXER_ENABLE_DEBUG_LOG=$<BOOL:${TLS_FIXER_ENABLE_DEBUG_LOG}>
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

target_link_libraries(tls_fixer_http PRIVATE
    tls_fixer_core
    mbedtls
    mbedx509
    tfpsacrypto
    gcc
    SceLibc_stub
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
