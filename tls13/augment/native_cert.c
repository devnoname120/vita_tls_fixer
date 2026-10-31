#include "native_cert.h"

#include <limits.h>
#include <string.h>

void tls_fixer_native_cert_end(TlsFixerNativeCertChain *chain) {
    if (chain == NULL || chain->api == NULL) return;
    for (size_t i = 0; i < chain->count; ++i) {
        if (chain->certificates[i] != NULL)
            (void)chain->api->certificate_free(chain->certificates[i]);
    }
    if (chain->connection != NULL) chain->api->connection_free(chain->connection);
    if (chain->context != NULL) chain->api->context_free(chain->context);
    memset(chain, 0, sizeof(*chain));
}

int tls_fixer_native_cert_open_factory(const TlsFixerNativeCertApi *api, TlsFixerNativeCertChain *chain) {
    void *crypto = NULL;
    int result;
    if (chain == NULL) return -1;
    memset(chain, 0, sizeof(*chain));
    if (api == NULL || !api->get_crypto_context || !api->client_method || !api->context_create ||
        !api->connection_create || !api->connection_property ||
        !api->connection_free || !api->context_free) return -1;
    chain->api = api;
    result = api->get_crypto_context(&crypto);
    if (result != 0 || crypto == NULL) goto failed;
    const void *method = api->client_method();
    if (method == NULL) goto failed;
    chain->context = api->context_create(crypto, method);
    if (chain->context == NULL) goto failed;
    chain->connection = api->connection_create(chain->context);
    if (chain->connection == NULL) goto failed;
    result = api->connection_property(chain->connection, 5, &chain->factory);
    if (result != 0 || chain->factory == NULL) goto failed;
    return 0;
failed:
    tls_fixer_native_cert_end(chain);
    return -1;
}

/* Retained as a diagnostic comparison. The production inspection facade must
 * not depend on Sony accepting the complete certificate signature encoding. */
int tls_fixer_native_cert_begin(const TlsFixerNativeCertApi *api,
    const TlsFixerNativeCertDer *der, size_t count, TlsFixerNativeCertChain *chain) {
    if (chain == NULL) return -1;
    memset(chain, 0, sizeof(*chain));
    if (api == NULL || !api->certificate_parse || !api->certificate_free ||
        (der == NULL && count != 0) || count > TLS_FIXER_NATIVE_CERT_LIMIT) return -1;
    for (size_t i = 0; i < count; ++i)
        if (der[i].data == NULL || der[i].length == 0 || der[i].length > UINT_MAX) return -1;
    if (count == 0) return 0;
    if (tls_fixer_native_cert_open_factory(api, chain) != 0) return -1;
    for (size_t i = 0; i < count; ++i) {
        unsigned int consumed = 0;
        /* Sony uses flags=0/type=1 for owned DER certificate objects and frees
         * the source DER immediately afterwards. Do not add them to its CAs. */
        int result = api->certificate_parse(chain->factory, 0, 1, (unsigned int)der[i].length,
                                        der[i].data, &consumed, &chain->certificates[i]);
        chain->count = i + 1; /* Clean up even if an error returned an object. */
        if (result != 0 || chain->certificates[i] == NULL || consumed != der[i].length)
            goto failed;
    }
    return 0;
failed:
    tls_fixer_native_cert_end(chain);
    return -1;
}
