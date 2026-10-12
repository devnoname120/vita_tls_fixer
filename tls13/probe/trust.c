#include "trust.h"
#include <psa/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int tls_fixer_probe_load_ca(const char *path, const char *sha256, mbedtls_x509_crt *ca) {
    if (path == NULL || sha256 == NULL || ca == NULL || ca->raw.p != NULL) return TLS_FIXER_PROBE_CA_FILE_ERROR;
    unsigned char expected[32], digest[32];
    for (size_t i = 0; i < 64; ++i) {
        unsigned char ch = (unsigned char)sha256[i];
        unsigned int value;
        if (ch >= '0' && ch <= '9') value = (unsigned int)(ch - '0');
        else if (ch >= 'a' && ch <= 'f') value = (unsigned int)(ch - 'a') + 10;
        else return TLS_FIXER_PROBE_CA_HASH_ERROR;
        if ((i & 1) == 0) expected[i / 2] = (unsigned char)(value << 4);
        else expected[i / 2] |= (unsigned char)value;
    }
    if (sha256[64] != '\0') return TLS_FIXER_PROBE_CA_HASH_ERROR;
    FILE *file = fopen(path, "rb");
    if (file == NULL) return TLS_FIXER_PROBE_CA_FILE_ERROR;
    unsigned char *pem = malloc(TLS_FIXER_PROBE_CA_LIMIT + 1);
    if (pem == NULL) { (void)fclose(file); return PSA_ERROR_INSUFFICIENT_MEMORY; }
    size_t size = fread(pem, 1, TLS_FIXER_PROBE_CA_LIMIT + 1, file);
    int failed = ferror(file);
    if (fclose(file) != 0) failed = 1;
    int rc = TLS_FIXER_PROBE_CA_FILE_ERROR;
    if (!failed && size > 0 && size <= TLS_FIXER_PROBE_CA_LIMIT) {
        size_t hashed = 0;
        rc = (int)psa_hash_compute(PSA_ALG_SHA_256, pem, size, digest, sizeof(digest), &hashed);
        if (rc == 0 && (hashed != sizeof(digest) || memcmp(digest, expected, sizeof(digest)) != 0))
            rc = TLS_FIXER_PROBE_CA_HASH_ERROR;
        if (rc == 0) {
            pem[size] = 0;
            rc = mbedtls_x509_crt_parse(ca, pem, size + 1);
            if (rc > 0) rc = TLS_FIXER_PROBE_CA_FILE_ERROR;
        }
    }
    free(pem);
    return rc;
}
