#include "trust.h"
#include "crypto_platform.h"
#include <psa/crypto.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    assert(argc == 4);
    assert(tls_fixer_crypto_platform_init() == 0 && psa_crypto_init() == PSA_SUCCESS);
    mbedtls_x509_crt ca;
    mbedtls_x509_crt_init(&ca);
    int rc = tls_fixer_probe_load_ca(argv[1], argv[2], &ca);
    int valid = strcmp(argv[3], "valid") == 0;
    assert((rc == 0) == valid);
    if (valid) {
        assert(ca.raw.p && ca.raw.len);
        assert(tls_fixer_probe_load_ca(argv[1], argv[2], &ca) != 0);
    }
    if (strcmp(argv[3], "hash") == 0) assert(rc == TLS_FIXER_PROBE_CA_HASH_ERROR);
    if (strcmp(argv[3], "file") == 0) assert(rc == TLS_FIXER_PROBE_CA_FILE_ERROR);
    mbedtls_x509_crt_free(&ca);
    mbedtls_psa_crypto_free();
    tls_fixer_crypto_platform_free();
    printf("probe CA: %s PASS\n", argv[3]);
    return 0;
}
