#include "native_cert.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static unsigned int fail_at, calls, frees, context_frees, connection_frees;
static unsigned char identities[40];
static int crypto(void **out) { ++calls; *out = &identities[0]; return fail_at == calls ? -1 : 0; }
static const void *method(void) { return fail_at == ++calls ? NULL : &identities[1]; }
static void *create(void *a, const void *b) {
    assert(a == &identities[0] && b == &identities[1]);
    return fail_at == ++calls ? NULL : &identities[2];
}
static int property(void *ctx, int key, void *out) {
    assert(ctx == &identities[4] && key == 5);
    *(void **)out = &identities[3];
    return fail_at == ++calls ? -1 : 0;
}
static void *new_connection(void *ctx) {
    assert(ctx == &identities[2]);
    return fail_at == ++calls ? NULL : &identities[4];
}
static int parse(void *factory, int flags, int type, unsigned int length, const void *der,
                 unsigned int *consumed, void **out) {
    assert(factory == &identities[3] && flags == 0 && type == 1 && length == 2 && der != NULL);
    ++calls;
    *out = &identities[calls];
    *consumed = length;
    return fail_at == calls ? -1 : 0;
}
static int release(void *cert) { assert(cert >= (void *)&identities[5]); ++frees; return 0; }
static void free_context(void *ctx) { assert(ctx == &identities[2]); ++context_frees; }
static void free_connection(void *ctx) { assert(ctx == &identities[4]); ++connection_frees; }

int main(void) {
    const TlsFixerNativeCertApi api = {crypto, method, create, new_connection, property,
        parse, release, free_connection, free_context, NULL};
    TlsFixerNativeCertChain chain;
    const unsigned char bytes[2] = {0x30, 0};
    const TlsFixerNativeCertDer der[3] = {{bytes,2},{bytes,2},{bytes,2}};
    for (fail_at = 0; fail_at <= 8; ++fail_at) {
        calls = frees = context_frees = connection_frees = 0;
        int result = tls_fixer_native_cert_begin(&api, der, 3, &chain);
        assert((result == 0) == (fail_at == 0));
        if (result == 0) { assert(chain.count == 3); tls_fixer_native_cert_end(&chain); }
        unsigned int expected_certs = fail_at == 0 ? 3 : fail_at >= 6 ? fail_at - 5 : 0;
        assert(frees == expected_certs);
        assert(context_frees == (fail_at == 0 || fail_at >= 4));
        assert(connection_frees == (fail_at == 0 || fail_at >= 5));
        tls_fixer_native_cert_end(&chain);
        assert(frees == expected_certs);
    }
    calls = frees = context_frees = fail_at = 0;
    assert(tls_fixer_native_cert_begin(&api, NULL, 0, &chain) == 0 && calls == 0);
    tls_fixer_native_cert_end(&chain);
    assert(tls_fixer_native_cert_begin(&api, der, 33, &chain) < 0 && calls == 0);
    assert(tls_fixer_native_cert_begin(NULL, der, 1, &chain) < 0 && calls == 0);
    TlsFixerNativeCertDer invalid = {NULL, 2};
    assert(tls_fixer_native_cert_begin(&api, &invalid, 1, &chain) < 0 && calls == 0);
    puts("Native certificate conversion ownership and failure cleanup passed");
    return 0;
}
