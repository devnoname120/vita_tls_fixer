#ifndef TLS_FIXER_SYSTEM_PAYLOADS_H
#define TLS_FIXER_SYSTEM_PAYLOADS_H

#define TLS_FIXER_AUGMENTED_HTTP_ASSET "libhttp_augmented.suprx"
#define TLS_FIXER_AUGMENTED_RUNTIME "ux0:/data/tls_fixer-runtime-installer"
#define TLS_FIXER_AUGMENTED_HTTP_MODULE_PATH TLS_FIXER_AUGMENTED_RUNTIME "/libhttp.suprx"
#define TLS_FIXER_AUGMENTED_SSL_MODULE_PATH TLS_FIXER_AUGMENTED_RUNTIME "/libssl.suprx"
#define TLS_FIXER_AUGMENTED_PSN_MODULE_PATH TLS_FIXER_AUGMENTED_RUNTIME "/tls_fixer_psn.suprx"
#define TLS_FIXER_AUGMENTED_STORE_MODULE_PATH TLS_FIXER_AUGMENTED_RUNTIME "/tls_fixer_store.suprx"
#define TLS_FIXER_RELEASE_HTTP_MODULE_PATH "vs0:/data/external/tls_fixer/native/libhttp.suprx"
#define TLS_FIXER_RELEASE_SSL_MODULE_PATH "vs0:/data/external/tls_fixer/native/libssl.suprx"

typedef enum {
    TLS_FIXER_SYSTEM_HOOKED,
    TLS_FIXER_SYSTEM_AUGMENTED,
    TLS_FIXER_SYSTEM_AUGMENTED_RELEASE
} TlsFixerSystemBackend;

typedef struct {
    int (*exists)(void *context, const char *path);
    int (*replace)(void *context, const char *source, const char *destination);
    int (*remove)(void *context, const char *path);
    void *context;
} TlsFixerSystemFiles;

int tls_fixer_system_payloads_present(TlsFixerSystemBackend backend, const TlsFixerSystemFiles *files);
int tls_fixer_system_payloads_complete(TlsFixerSystemBackend backend, const TlsFixerSystemFiles *files);
int tls_fixer_update_system_payloads(TlsFixerSystemBackend backend, int removing,
    const TlsFixerSystemFiles *files);

#endif
