#include "embedded.h"
#include "cert_facade.h"
#include "cert_hooks.h"
#include "game_ca.h"
#include "provider.h"
#include "diagnostics.h"
#include "tls_fixer/sony_abi.h"
#include <psp2/kernel/threadmgr/mutex.h>
#include <stdio.h>
#include <string.h>

static SceUID g_load_mutex = -1;
static uint32_t g_legacy;
static TlsFixerCertFacade g_facades[TLS_FIXER_NATIVE_CERT_LIMIT];
static uint8_t g_taken[TLS_FIXER_NATIVE_CERT_LIMIT];

int tls_fixer_embedded_cert_init(void) {
    memset(g_facades, 0, sizeof(g_facades));
    memset(g_taken, 0, sizeof(g_taken));
    g_legacy = 0;
    g_load_mutex = sceKernelCreateMutex("tls_fixer CA load", 0, 0, NULL);
    return g_load_mutex < 0 ? g_load_mutex : 0;
}

void tls_fixer_embedded_cert_destroy(void) {
    if (g_load_mutex >= 0) {
        tls_fixer_game_ca_free();
        sceKernelDeleteMutex(g_load_mutex);
        g_load_mutex = -1;
    }
    g_legacy = 0;
}

int tls_fixer_cert_hooks_ensure_ssl(void) { return 0; } /* Native getters need no patch. */
int tls_fixer_cert_hooks_active(void) { return g_load_mutex >= 0; }
int tls_fixer_legacy_certificates_loaded(void) { return __atomic_load_n(&g_legacy, __ATOMIC_ACQUIRE) != 0; }

int tls_fixer_embedded_load_cert(int count, const SceHttpsData **certs,
    const SceHttpsData *client, const SceHttpsData *key) {
    if (!tls_fixer_embedded_enter()) return (int)UINT32_C(0x80431001);
    int enabled = g_tls_fixer_http.state == TLS_FIXER_PROVIDER_ACTIVE && g_load_mutex >= 0;
    int rc = enabled ? sceKernelLockMutex(g_load_mutex, 1, NULL) : 0;
    if (rc < 0) { tls_fixer_embedded_leave(); return rc; }
    rc = g_tls_fixer_embedded_bindings.load_cert(count, certs, client, key);
    if (enabled && ((count > 0 && certs != NULL) || client != NULL || key != NULL)) {
        int legacy = tls_fixer_legacy_certificates_loaded() || rc < 0 || client != NULL || key != NULL;
        if (!legacy) legacy = tls_fixer_game_ca_load(count, certs) != 0;
        __atomic_store_n(&g_legacy, legacy, __ATOMIC_RELEASE);
    }
    if (enabled) sceKernelUnlockMutex(g_load_mutex, 1);
    TLS_FIXER_LOG("event=cert.load count=%d client=%d key=%d rc=%08X mirrored=%d legacy=%d",
        count, client != NULL, key != NULL, rc, enabled, tls_fixer_legacy_certificates_loaded());
    tls_fixer_embedded_leave();
    return rc;
}

int tls_fixer_embedded_unload_cert(void) {
    if (!tls_fixer_embedded_enter()) return (int)UINT32_C(0x80431001);
    int enabled = g_tls_fixer_http.state == TLS_FIXER_PROVIDER_ACTIVE && g_load_mutex >= 0;
    int rc = enabled ? sceKernelLockMutex(g_load_mutex, 1, NULL) : 0;
    if (rc < 0) { tls_fixer_embedded_leave(); return rc; }
    rc = g_tls_fixer_embedded_bindings.unload_cert();
    if (enabled && rc >= 0) {
        tls_fixer_game_ca_free();
        __atomic_store_n(&g_legacy, 0, __ATOMIC_RELEASE);
    }
    if (enabled) sceKernelUnlockMutex(g_load_mutex, 1);
    tls_fixer_embedded_leave();
    return rc;
}

static int format_time(char out[16], const mbedtls_x509_time *time) {
    return snprintf(out, 16, "%04d%02d%02d%02d%02d%02dZ", time->year, time->mon,
                    time->day, time->hour, time->min, time->sec) == 15 ? 0 : -1;
}

int tls_fixer_cert_callback_decide(void *connection, const mbedtls_x509_crt *peer,
                                 uint32_t verification, int *accepted) {
    if (connection == NULL || accepted == NULL) return -1;
    *accepted = 0;
    uintptr_t callback = tls_fixer_connection_callback_address(connection);
    if (callback == 0) { *accepted = verification == 0; return 0; }
    unsigned int slots[TLS_FIXER_NATIVE_CERT_LIMIT];
    void *certificates[TLS_FIXER_NATIVE_CERT_LIMIT];
    size_t count = 0, reserved = 0;
    for (const mbedtls_x509_crt *p = peer; p != NULL; p = p->next)
        if (++count > TLS_FIXER_NATIVE_CERT_LIMIT) return -1;
    TlsFixerNativeCertChain factory = {0};
    int rc = 0;
    if (count) {
        rc = sceKernelLockMutex(g_tls_fixer_http.registry_mutex, 1, NULL);
        if (rc < 0) return rc;
        for (unsigned int i = 0; i < TLS_FIXER_NATIVE_CERT_LIMIT && reserved < count; ++i) {
            if (!g_taken[i]) { g_taken[i] = 1; slots[reserved++] = i; }
        }
        sceKernelUnlockMutex(g_tls_fixer_http.registry_mutex, 1);
        if (reserved != count) { rc = -1; goto done; }
        rc = tls_fixer_native_cert_open_factory(&g_tls_fixer_embedded_bindings.certificates, &factory);
        if (rc != 0) goto done;
        const mbedtls_x509_crt *p = peer;
        for (size_t i = 0; i < count; ++i, p = p->next) {
            TlsFixerCertView view = {
                .serial = {p->serial.p, p->serial.len},
                .issuer = {p->issuer_raw.p, p->issuer_raw.len},
                .subject = {p->subject_raw.p, p->subject_raw.len}
            };
            if (format_time(view.not_before, &p->valid_from) < 0 || format_time(view.not_after, &p->valid_to) < 0 ||
                tls_fixer_cert_facade_init(&g_facades[slots[i]], &g_tls_fixer_embedded_bindings.certificates,
                                           factory.factory, &view) < 0) { rc = -1; goto done; }
            certificates[i] = &g_facades[slots[i]];
        }
    }
    typedef int (*Callback)(unsigned int, void *const *, int, void *);
    int result = ((Callback)callback)(verification, count ? certificates : NULL, (int)count,
        (void *)tls_fixer_connection_callback_arg_address(connection));
    *accepted = tls_fixer_cert_callback_accepted(result, verification, callback, &g_tls_fixer_http.cert_policy);
done:
    for (size_t i = 0; i < reserved; ++i) tls_fixer_cert_facade_end(&g_facades[slots[i]]);
    tls_fixer_native_cert_end(&factory);
    if (reserved) {
        int lock = sceKernelLockMutex(g_tls_fixer_http.registry_mutex, 1, NULL);
        if (lock < 0) return lock;
        for (size_t i = 0; i < reserved; ++i) g_taken[slots[i]] = 0;
        sceKernelUnlockMutex(g_tls_fixer_http.registry_mutex, 1);
    }
    return rc;
}
