#include "provider.h"
#include "cert_hooks.h"
#include "game_ca.h"
#include "ca_file.h"
#include "crypto_platform.h"
#include <mbedtls/platform.h>
#include <psa/crypto.h>
#include <psa/crypto_extra.h>
#include <psp2/kernel/threadmgr/mutex.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

TlsFixerProviderGlobal g_tls_fixer_http;
typedef int (*LoadCert)(int, const SceHttpsData **, const SceHttpsData *, const SceHttpsData *);
typedef int (*UnloadCert)(void);

static int found(const mbedtls_x509_crt *root) {
    mbedtls_x509_crt *candidates = NULL;
    assert(tls_fixer_game_ca_find(root, &candidates) == 0);
    int seen = 0;
    for (const mbedtls_x509_crt *c = candidates; c != NULL && c->raw.p != NULL; c = c->next)
        if (c->raw.len == root->raw.len && memcmp(c->raw.p, root->raw.p, c->raw.len) == 0) ++seen;
    if (candidates != NULL) { mbedtls_x509_crt_free(candidates); mbedtls_free(candidates); }
    return seen;
}

int main(int argc, char **argv) {
    assert(argc == 2);
    assert(tls_fixer_crypto_platform_init() == 0 && psa_crypto_init() == PSA_SUCCESS);
    mbedtls_x509_crt roots;
    mbedtls_x509_crt_init(&roots);
    assert(tls_fixer_load_ca_file(&roots, argv[1]) == 0 && roots.next != NULL);
    g_tls_fixer_http.registry_mutex = sceKernelCreateMutex("test CA", 0, 0, NULL);
    assert(g_tls_fixer_http.registry_mutex >= 0);
    assert(tls_fixer_cert_hooks_install() == 0);
    LoadCert load = (LoadCert)mock_hook_by_nid(0xae8d7c33);
    UnloadCert unload = (UnloadCert)mock_hook_by_nid(0x8577833f);
    SceHttpsData a = {roots.raw.p, (unsigned)roots.raw.len};
    SceHttpsData b = {roots.next->raw.p, (unsigned)roots.next->raw.len};
    const SceHttpsData *first[] = {&a}, *second[] = {&b};
    assert(!found(&roots) && !tls_fixer_legacy_certificates_loaded());
    assert(load(1, first, NULL, NULL) == 0);
    assert(found(&roots) == 1 && !found(roots.next) && !tls_fixer_legacy_certificates_loaded());
    assert(load(1, second, NULL, NULL) == 0);
    assert(found(&roots) == 1 && found(roots.next) == 1);
    /* Repeated loads add trust, but identical DER must not consume heap again. */
    assert(load(1, first, NULL, NULL) == 0 && found(&roots) == 1);
    assert(load(0, NULL, NULL, NULL) == 0 && found(&roots) == 1 && found(roots.next) == 1);
    mock_legacy_certificate_result = -71;
    assert(load(1, first, NULL, NULL) == -71 && found(roots.next) == 1);
    assert(tls_fixer_legacy_certificates_loaded());
    assert(unload() == -71 && found(roots.next) == 1);
    mock_legacy_certificate_result = 0;
    assert(load(1, first, NULL, NULL) == 0 && tls_fixer_legacy_certificates_loaded());
    assert(unload() == 0 && !tls_fixer_legacy_certificates_loaded());
    assert(!found(&roots) && !found(roots.next));
    SceHttpsData bad = {"invalid", 7};
    const SceHttpsData *partial[] = {&a, &bad};
    assert(load(2, partial, NULL, NULL) == 0);
    assert(tls_fixer_legacy_certificates_loaded() && !found(&roots) && !found(roots.next));
    /* Only unload resolves a potentially incomplete mirror of Sony's additions. */
    assert(load(1, first, NULL, NULL) == 0 && tls_fixer_legacy_certificates_loaded());
    assert(unload() == 0 && !tls_fixer_legacy_certificates_loaded());
    assert(load(1, first, NULL, NULL) == 0 && found(&roots) == 1);
    assert(load(1, first, &b, NULL) == 0 && tls_fixer_legacy_certificates_loaded());
    assert(load(1, second, NULL, NULL) == 0 && tls_fixer_legacy_certificates_loaded());
    assert(unload() == 0 && !tls_fixer_legacy_certificates_loaded());
    assert(load(1, first, NULL, NULL) == 0 && found(&roots) == 1);
    tls_fixer_cert_hooks_release();
    assert(mock_hooks_active() == 0 && !found(&roots));
    assert(sceKernelDeleteMutex(g_tls_fixer_http.registry_mutex) == 0);
    mbedtls_x509_crt_free(&roots);
    mbedtls_psa_crypto_free();
    tls_fixer_crypto_platform_free();
    puts("app CA hooks: append, deduplication, unload, rejected loads, partial parse, client identity and recovery PASS");
    return 0;
}
