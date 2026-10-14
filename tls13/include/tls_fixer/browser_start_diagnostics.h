#ifndef TLS_FIXER_BROWSER_START_DIAGNOSTICS_H
#define TLS_FIXER_BROWSER_START_DIAGNOSTICS_H

#include <stdint.h>

#ifndef TLS_FIXER_BROWSER_START_DIAGNOSTICS
#define TLS_FIXER_BROWSER_START_DIAGNOSTICS 0
#endif

#if TLS_FIXER_BROWSER_START_DIAGNOSTICS
#define TLS_FIXER_BROWSER_PROVIDER_FILENAME "tls_fixer_startdiag.suprx"
#define TLS_FIXER_BROWSER_PROVIDER_BOOT_PATH "ur0:tai/tls_fixer_startdiag.suprx"
#else
#define TLS_FIXER_BROWSER_PROVIDER_FILENAME "tls_fixer.suprx"
#define TLS_FIXER_BROWSER_PROVIDER_BOOT_PATH "ur0:tai/tls_fixer-native/tls_fixer.suprx"
#endif

typedef enum TlsFixerBrowserStartStage {
    TLS_FIXER_START_REPEAT = 1,
    TLS_FIXER_START_ARGUMENT_BUFFER,
    TLS_FIXER_START_ARGUMENT_MAGIC,
    TLS_FIXER_START_ARGUMENT_VERSION,
    TLS_FIXER_START_ARGUMENT_MODULE,
    TLS_FIXER_START_ARGUMENT_RESERVED,
    TLS_FIXER_START_MODULE_INFO,
    TLS_FIXER_START_MODULE_NAME,
    TLS_FIXER_START_SEGMENT_ADDRESS,
    TLS_FIXER_START_TEXT_FILESZ,
    TLS_FIXER_START_TEXT_MEMSZ,
    TLS_FIXER_START_DATA_FILESZ,
    TLS_FIXER_START_DATA_MEMSZ,
    TLS_FIXER_START_SIGNATURE,
    TLS_FIXER_START_CA_PATH,
    TLS_FIXER_START_INIT_ARGUMENT,
    TLS_FIXER_START_CRYPTO_PLATFORM,
    TLS_FIXER_START_PSA,
    TLS_FIXER_START_CA_LOAD,
    TLS_FIXER_START_REGISTRY_MUTEX,
    TLS_FIXER_START_ATTACH_MUTEX,
    TLS_FIXER_START_REGISTRY,
    TLS_FIXER_START_INIT_OTHER,
    TLS_FIXER_START_HOOK_CLOSE,
    TLS_FIXER_START_HOOK_PENDING,
    TLS_FIXER_START_HOOK_CHECK,
    TLS_FIXER_START_HOOK_CONNECT
} TlsFixerBrowserStartStage;

static inline int tls_fixer_browser_start_code(TlsFixerBrowserStartStage stage, uint32_t detail) {
    return (int)(UINT32_C(0x49000000) | ((uint32_t)stage << 16) | (detail & UINT32_C(0xffff)));
}

static inline int tls_fixer_browser_is_start_code(int result) {
    return ((uint32_t)result & UINT32_C(0xff000000)) == UINT32_C(0x49000000);
}

static inline int tls_fixer_browser_start_failure(TlsFixerBrowserStartStage stage, uint32_t detail, int normal_result) {
#if TLS_FIXER_BROWSER_START_DIAGNOSTICS
    (void)normal_result;
    return tls_fixer_browser_start_code(stage, detail);
#else
    (void)stage;
    (void)detail;
    return normal_result;
#endif
}

#endif
