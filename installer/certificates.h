#ifndef TLS_FIXER_INSTALLER_CERTIFICATES_H
#define TLS_FIXER_INSTALLER_CERTIFICATES_H

#include <stddef.h>

#define TLS_FIXER_CA_UPDATE_URL "https://curl.se/ca/cacert.pem"
#define TLS_FIXER_CA_BUNDLE_LIMIT (4u * 1024u * 1024u)

typedef struct TlsFixerCertificateBundle {
    unsigned char *data;
    size_t size;
    size_t sony_count, mozilla_count, combined_count;
    int downloaded;
    int download_error;
    long http_status;
    const char *failure_stage;
    int failure_errno;
    unsigned long failure_crypto_error;
} TlsFixerCertificateBundle;

/* URL is NULL when networking is unavailable. Inputs always come from the VPK. */
int tls_fixer_prepare_certificates(const char *sony_path, const char *mozilla_path,
    const char *url, long timeout_seconds, TlsFixerCertificateBundle *bundle);
void tls_fixer_free_certificates(TlsFixerCertificateBundle *bundle);

#endif
