#ifndef TLS_FIXER_AUGMENT_NATIVE_CERT_H
#define TLS_FIXER_AUGMENT_NATIVE_CERT_H

#include <stddef.h>
#include <stdint.h>

#define TLS_FIXER_NATIVE_CERT_LIMIT 32u

/* Existing SceSslInternal exports, already imported by Sony libhttp.
 * These create certificate objects only. Trust and TLS stay in Mbed TLS. */
typedef struct TlsFixerNativeCertApi {
    int (*get_crypto_context)(void **context);                 /* 2185BB05 */
    const void *(*client_method)(void);                        /* A374CD7B */
    void *(*context_create)(void *crypto, const void *method); /* E746465E */
    void *(*connection_create)(void *context);                 /* D28834E6 */
    int (*connection_property)(void *connection, int key, void *out);/* 24C6257F */
    int (*certificate_parse)(void *factory, int flags, int type, unsigned int length,
                             const void *der, unsigned int *consumed, void **certificate); /* 29AAC768 */
    int (*certificate_free)(void *certificate);                /* 144FA354 */
    void (*connection_free)(void *connection);                 /* 19B2BB58 */
    void (*context_free)(void *context);                      /* EF9EBAC7 */
    int (*integer_decode)(void *integer, int format, const void *data, unsigned int length); /* 88391E03 */
} TlsFixerNativeCertApi;

typedef struct TlsFixerNativeCertDer {
    const void *data;
    size_t length;
} TlsFixerNativeCertDer;

typedef struct TlsFixerNativeCertChain {
    const TlsFixerNativeCertApi *api;
    void *context;
    void *connection;
    void *factory;
    void *certificates[TLS_FIXER_NATIVE_CERT_LIMIT];
    size_t count;
} TlsFixerNativeCertChain;

int tls_fixer_native_cert_begin(const TlsFixerNativeCertApi *api,
    const TlsFixerNativeCertDer *der, size_t count, TlsFixerNativeCertChain *chain);
int tls_fixer_native_cert_open_factory(const TlsFixerNativeCertApi *api,
    TlsFixerNativeCertChain *chain);
void tls_fixer_native_cert_end(TlsFixerNativeCertChain *chain);

#endif
