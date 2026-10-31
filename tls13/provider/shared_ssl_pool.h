#ifndef TLS_FIXER_SHARED_SSL_POOL_H
#define TLS_FIXER_SHARED_SSL_POOL_H
#include <stdint.h>

typedef struct TlsFixerSslPoolView {
    void *heap;
    int32_t block;
} TlsFixerSslPoolView;
typedef int (*TlsFixerSslPoolRead)(void *context, TlsFixerSslPoolView *view);

/* Borrowed from sceSslInit. These functions never create or destroy that heap. */
int tls_fixer_user_runtime_bind_ssl(TlsFixerSslPoolRead read, void *context);
int tls_fixer_user_runtime_pool_alive(void);
#endif
