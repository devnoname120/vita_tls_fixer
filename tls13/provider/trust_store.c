#include "provider.h"
#include "crypto_platform.h"
#include "ca_file.h"

#include <psp2/io/fcntl.h>
#include <mbedtls/x509_crt.h>
#include <psa/crypto.h>
#include <psa/crypto_extra.h>

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int tls_fixer_trust_store_init(void) {
    int result;

    result = tls_fixer_crypto_platform_init();
    if (result != 0) {
        return result;
    }
    g_tls_fixer_http.crypto_initialized = 1;
    result = (int)psa_crypto_init();
    if (result != PSA_SUCCESS) {
        tls_fixer_trust_store_free();
        return result;
    }

    mbedtls_x509_crt_init(&g_tls_fixer_http.ca_chain);
    g_tls_fixer_http.ca_chain_initialized = 1;
    result = tls_fixer_load_ca_file(&g_tls_fixer_http.ca_chain, TLS_FIXER_DEFAULT_CA_PATH);
    if (result != 0) {
        tls_fixer_trust_store_free();
    }
    return result;
}

void tls_fixer_trust_store_free(void) {
    if (g_tls_fixer_http.ca_chain_initialized) {
        mbedtls_x509_crt_free(&g_tls_fixer_http.ca_chain);
        g_tls_fixer_http.ca_chain_initialized = 0;
    }
    if (g_tls_fixer_http.crypto_initialized) {
        mbedtls_psa_crypto_free();
        tls_fixer_crypto_platform_free();
        g_tls_fixer_http.crypto_initialized = 0;
    }
}
