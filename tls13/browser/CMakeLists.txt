include("${VITASDK}/share/vita.cmake" REQUIRED)

add_executable(tls_fixer
    module.c
    backend.c
    config.c
    webkit_callback.c
    ../provider/ca_file.c
    ../provider/platform_shims.c
)
if(TLS_FIXER_ENABLE_DEBUG_LOG)
    target_sources(tls_fixer PRIVATE ../provider/trace.c)
else()
    target_sources(tls_fixer PRIVATE quiet_output.c)
    target_link_options(tls_fixer PRIVATE -Wl,--wrap=printf -Wl,--wrap=puts)
endif()
target_include_directories(tls_fixer PRIVATE . ../provider)
target_compile_features(tls_fixer PRIVATE c_std_11)
target_compile_definitions(tls_fixer PRIVATE TLS_FIXER_ENABLE_DEBUG_LOG=$<BOOL:${TLS_FIXER_ENABLE_DEBUG_LOG}>
    TLS_FIXER_BROWSER_START_DIAGNOSTICS=$<BOOL:${TLS_FIXER_BROWSER_START_DIAGNOSTICS}>
    TLS_FIXER_BROWSER_PASSTHROUGH_ONLY=$<BOOL:${TLS_FIXER_BROWSER_PASSTHROUGH_ONLY}>
    TLS_FIXER_BROWSER_INITIALIZE_ONLY=$<BOOL:${TLS_FIXER_BROWSER_INITIALIZE_ONLY}>
    TLS_FIXER_BROWSER_FILE_LOG=1)
if(NOT TLS_FIXER_BROWSER_HOOK_MASK STREQUAL "")
    target_compile_definitions(tls_fixer PRIVATE TLS_FIXER_BROWSER_HOOK_MASK=${TLS_FIXER_BROWSER_HOOK_MASK})
endif()
target_compile_options(tls_fixer PRIVATE -std=gnu11 -Wall -Wextra -Werror -Wshadow
    -Wstrict-prototypes -ffunction-sections -fdata-sections -O2)
target_link_options(tls_fixer PRIVATE -nostdlib -Wl,--gc-sections
    -Wl,--undefined=module_start -Wl,--undefined=module_stop)
target_link_libraries(tls_fixer PRIVATE tls_fixer_core mbedtls mbedx509 tfpsacrypto gcc
    SceLibc_stub SceNet_stub SceRtc_stub SceLibKernel_stub SceIofilemgr_stub
    SceKernelModulemgr_stub SceKernelThreadMgr_stub SceSysmem_stub taihen_stub)
if(TLS_FIXER_ENABLE_RUNTIME_UDP)
    target_sources(tls_fixer PRIVATE runtime_udp.c)
    target_compile_definitions(tls_fixer PRIVATE TLS_FIXER_ENABLE_RUNTIME_UDP=1 TLS_FIXER_RUNTIME_USE_SCE_LIBC=1
        TLS_FIXER_RUNTIME_HOST="${TLS_FIXER_RUNTIME_HOST}" TLS_FIXER_RUNTIME_PORT=${TLS_FIXER_RUNTIME_PORT}
        TLS_FIXER_RUNTIME_NONCE_HEX="${TLS_FIXER_RUNTIME_NONCE_HEX}")
endif()
vita_create_self(tls_fixer.suprx tls_fixer
    CONFIG ${CMAKE_CURRENT_SOURCE_DIR}/tls_fixer.yml UNSAFE)
