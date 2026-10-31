#ifndef TLS_FIXER_NATIVE_HELLO_PROFILE_H
#define TLS_FIXER_NATIVE_HELLO_PROFILE_H
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_ciphersuites.h>

/* Audited Sony 3.74 ClientHello offer, independently captured on the Vita.
 * The experimental serializer can offer the three legacy IDs; selecting an
 * unimplemented suite still fails. This is not a general cipher implementation. */
static inline int tls_fixer_native_hello_profile(mbedtls_ssl_config *config) {
    static const int suites[] = {0x003d,0x003c,0x0035,0x002f,0x000a,0x0005,0x0004,0};
    static const uint16_t signatures[] = {0x0401,0x0601,0x0501,0x0201,0};
    if (mbedtls_ssl_ciphersuite_from_id(0x003c) == NULL) return MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
    mbedtls_ssl_conf_min_tls_version(config, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_max_tls_version(config, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_ciphersuites(config, suites);
    mbedtls_ssl_conf_sig_algs(config, signatures);
    mbedtls_ssl_conf_extended_master_secret(config, MBEDTLS_SSL_EXTENDED_MS_DISABLED);
    mbedtls_ssl_conf_encrypt_then_mac(config, MBEDTLS_SSL_ETM_DISABLED);
    mbedtls_ssl_conf_session_tickets(config, MBEDTLS_SSL_SESSION_TICKETS_DISABLED);
    return 0;
}
#endif
