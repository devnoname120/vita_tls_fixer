#ifndef TLS_FIXER_SONY_SSL_POOL_H
#define TLS_FIXER_SONY_SSL_POOL_H
#include "shared_ssl_pool.h"
int tls_fixer_sony_ssl_pool_prepare(const void *get_crypto_import);
int tls_fixer_sony_ssl_pool_read(void *context, TlsFixerSslPoolView *view);
#endif
