#ifndef TLS_FIXER_GAME_CA_H
#define TLS_FIXER_GAME_CA_H

#include <mbedtls/x509_crt.h>
#include <psp2/net/http.h>

/* Caller serializes certificate-loading APIs. Append only after Sony accepts a load. */
int tls_fixer_game_ca_load(int count, const SceHttpsData **certificates);
void tls_fixer_game_ca_free(void);
int tls_fixer_game_ca_find(const mbedtls_x509_crt *child, mbedtls_x509_crt **candidates);

#endif
