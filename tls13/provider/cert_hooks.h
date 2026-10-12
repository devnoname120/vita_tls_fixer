#ifndef TLS_FIXER_CERT_HOOKS_H
#define TLS_FIXER_CERT_HOOKS_H

#include <stdint.h>

#include <mbedtls/x509_crt.h>

int tls_fixer_cert_hooks_install(void);
void tls_fixer_cert_hooks_release(void);
int tls_fixer_cert_hooks_active(void);
int tls_fixer_legacy_certificates_loaded(void);
int tls_fixer_cert_callback_decide(
    void *sony_connection,
    const mbedtls_x509_crt *peer_chain,
    uint32_t verification_detail,
    int *accepted);

#endif
