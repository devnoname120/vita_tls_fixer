/* Host test of trusting a self-signed server certificate by exact match: run_exact_trust.py makes
 * real certificates, and Mbed TLS checks one through the store index, as the providers do
 * Arguments: store file, server certificate, host name, and "exact" to apply the providers'
 * verification callback or "plain" for Mbed TLS alone; prints the resulting flags */
#include "ca_index.h"
#include "crypto_platform.h"

#include <mbedtls/x509_crt.h>
#include <psa/crypto.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The providers' callback (transport.c and the browser's backend.c), with the store alone */
static int trust_exact_self_signed(void *context, mbedtls_x509_crt *certificate, int depth,
    uint32_t *flags) {
    if (depth == 0 && (*flags & MBEDTLS_X509_BADCERT_NOT_TRUSTED) != 0 &&
        tls_fixer_ca_trusts_exact(tls_fixer_ca_index_find, context, certificate)) {
        *flags &= ~(uint32_t)MBEDTLS_X509_BADCERT_NOT_TRUSTED;
    }
    return 0;
}

/* The tls_fixer Mbed TLS build has no file functions, so the certificate is read here */
static void parse_certificate(mbedtls_x509_crt *certificate, const char *path) {
    FILE *file = fopen(path, "rb");
    assert(file != NULL && fseek(file, 0, SEEK_END) == 0);
    long size = ftell(file);
    assert(size > 0 && fseek(file, 0, SEEK_SET) == 0);
    unsigned char *data = malloc((size_t)size + 1);
    assert(data != NULL && fread(data, 1, (size_t)size, file) == (size_t)size && fclose(file) == 0);
    data[size] = '\0';
    assert(mbedtls_x509_crt_parse(certificate, data, (size_t)size + 1) == 0);
    free(data);
}

int main(int argc, char **argv) {
    TlsFixerCaIndex index;
    mbedtls_x509_crt certificate;
    uint32_t flags = 0;

    assert(argc == 5);
    assert(tls_fixer_crypto_platform_init() == 0 && psa_crypto_init() == PSA_SUCCESS);
    memset(&index, 0, sizeof(index));
    assert(tls_fixer_ca_index_build(&index, argv[1]) == 0);
    mbedtls_x509_crt_init(&certificate);
    parse_certificate(&certificate, argv[2]);
    /* The providers' profile: the default one, plus SHA-1 signatures */
    mbedtls_x509_crt_profile profile = mbedtls_x509_crt_profile_default;
    profile.allowed_mds |= MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA1);
    int exact = strcmp(argv[4], "exact") == 0;
    (void)mbedtls_x509_crt_verify_with_ca_cb(&certificate, tls_fixer_ca_index_find, &index, &profile, argv[3],
        &flags, exact ? trust_exact_self_signed : NULL, &index);
    printf("flags=%08X\n", (unsigned int)flags);

    /* Outside the verification, the helper itself: never a certificate that isn't self-signed */
    assert(tls_fixer_ca_trusts_exact(NULL, &index, &certificate) == 0);
    mbedtls_x509_crt_free(&certificate);
    tls_fixer_ca_index_free(&index);
    tls_fixer_crypto_platform_free();
    return 0;
}
