#ifndef TLS_FIXER_PROBE_TRUST_H
#define TLS_FIXER_PROBE_TRUST_H
#include <mbedtls/x509_crt.h>
#define TLS_FIXER_PROBE_CA_LIMIT 65536u
#define TLS_FIXER_PROBE_CA_FILE_ERROR (-100005)
#define TLS_FIXER_PROBE_CA_HASH_ERROR (-100006)
int tls_fixer_probe_load_ca(const char *path, const char *sha256, mbedtls_x509_crt *ca);
#endif
