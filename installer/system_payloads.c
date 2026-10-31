#include "system_payloads.h"
#include <stddef.h>

typedef struct { const char *source, *destination; } Payload;
static const Payload hooked[] = {
    {"app0:tls_fixer_http.suprx", "vs0:/data/external/tls_fixer/native/tls_fixer_http.suprx"},
    {"app0:lhttp.suprx", "vs0:/data/external/tls_fixer/libhttp.suprx"},
    {"app0:lssl.suprx", "vs0:/data/external/tls_fixer/libssl.suprx"},
};
static const Payload augmented[] = {
    {"app0:" TLS_FIXER_AUGMENTED_HTTP_ASSET, TLS_FIXER_AUGMENTED_HTTP_MODULE_PATH},
    {"app0:lssl.suprx", TLS_FIXER_AUGMENTED_SSL_MODULE_PATH},
};
static const Payload release[] = {
    {"app0:" TLS_FIXER_AUGMENTED_HTTP_ASSET, TLS_FIXER_RELEASE_HTTP_MODULE_PATH},
    {"app0:lssl.suprx", TLS_FIXER_RELEASE_SSL_MODULE_PATH},
};
static const char *const helpers[] = {
    "vs0:/data/external/tls_fixer/native/tls_fixer_psn.suprx",
    "vs0:/data/external/tls_fixer/native/tls_fixer_store.suprx",
};
static const char *const augmented_helpers[] = {TLS_FIXER_AUGMENTED_PSN_MODULE_PATH, TLS_FIXER_AUGMENTED_STORE_MODULE_PATH};
static int select_payloads(TlsFixerSystemBackend backend, const Payload **out, size_t *count) {
    if (backend == TLS_FIXER_SYSTEM_HOOKED) {
        *out = hooked; *count = sizeof(hooked) / sizeof(hooked[0]); return 0;
    }
    if (backend == TLS_FIXER_SYSTEM_AUGMENTED) {
        *out = augmented; *count = sizeof(augmented) / sizeof(augmented[0]); return 0;
    }
    if (backend == TLS_FIXER_SYSTEM_AUGMENTED_RELEASE) {
        *out = release; *count = sizeof(release) / sizeof(release[0]); return 0;
    }
    return -1;
}
int tls_fixer_system_payloads_present(TlsFixerSystemBackend backend, const TlsFixerSystemFiles *files) {
    const Payload *payloads; size_t count;
    if (!files || !files->exists || select_payloads(backend, &payloads, &count) < 0) return 0;
    for (size_t i = 0; i < count; ++i)
        if (files->exists(files->context, payloads[i].destination)) return 1;
    const char *const *selected_helpers = backend == TLS_FIXER_SYSTEM_AUGMENTED ? augmented_helpers : helpers;
    for (size_t i = 0; i < sizeof(helpers) / sizeof(helpers[0]); ++i)
        if (files->exists(files->context, selected_helpers[i])) return 1;
    if (backend == TLS_FIXER_SYSTEM_AUGMENTED) return 0;
    return files->exists(files->context, "vs0:/data/external/tls_fixer/old_dns_fix.suprx") ||
        files->exists(files->context, "vs0:/data/external/tls_fixer/np_commerce2.suprx");
}
int tls_fixer_system_payloads_complete(TlsFixerSystemBackend backend, const TlsFixerSystemFiles *files) {
    const Payload *payloads; size_t count;
    if (!files || !files->exists || select_payloads(backend, &payloads, &count) < 0) return 0;
    for (size_t i = 0; i < count; ++i)
        if (!files->exists(files->context, payloads[i].destination)) return 0;
    const char *const *selected_helpers = backend == TLS_FIXER_SYSTEM_AUGMENTED ? augmented_helpers : helpers;
    for (size_t i = 0; i < sizeof(helpers) / sizeof(helpers[0]); ++i)
        if (!files->exists(files->context, selected_helpers[i])) return 0;
    return 1;
}
int tls_fixer_update_system_payloads(TlsFixerSystemBackend backend, int removing,
    const TlsFixerSystemFiles *files) {
    const Payload *payloads; size_t count;
    if (!files || select_payloads(backend, &payloads, &count) < 0) return -1;
    if (removing) {
        if (!files->remove) return -1;
        for (size_t i = 0; i < count; ++i) {
            int rc = files->remove(files->context, payloads[i].destination);
            if (rc < 0) return rc;
        }
        if (backend == TLS_FIXER_SYSTEM_AUGMENTED_RELEASE) {
            /* Remove leftovers from the replaced HTTP-hook architecture too. */
            for (size_t i = 0; i < sizeof(hooked) / sizeof(hooked[0]); ++i) {
                int rc = files->remove(files->context, hooked[i].destination);
                if (rc < 0) return rc;
            }
        }
    } else {
        if (!files->replace) return -1;
        for (size_t i = 0; i < count; ++i) {
            int rc = files->replace(files->context, payloads[i].source, payloads[i].destination);
            if (rc < 0) return rc;
        }
    }
    return 0;
}
