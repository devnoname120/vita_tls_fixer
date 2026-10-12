#ifndef TLS_FIXER_BROWSER_BACKEND_H
#define TLS_FIXER_BROWSER_BACKEND_H

#include "tls_fixer/browser_abi.h"

#include <stddef.h>
#include <stdint.h>

typedef struct TlsFixerBrowserOps {
    int (*timeleft)(void *easy, void *now, int during_connect);
    int (*socket_wait)(int read_fd, int read_fd2, int write_fd, int timeout_ms);
    TlsFixerBrowserContextCallbackValidator is_default_ctx_callback;
    const char *default_ciphers;
    const char *default_ca_path;
} TlsFixerBrowserOps;

typedef int (*TlsFixerBrowserRecv)(void *connection, int index, void *data,
    unsigned int length, int *error);
typedef int (*TlsFixerBrowserSend)(void *connection, int index, const void *data,
    unsigned int length, int *error);

int tls_fixer_browser_init(const TlsFixerBrowserOps *ops);
void tls_fixer_browser_enable(int enabled);
int tls_fixer_browser_destroy(void);
size_t tls_fixer_browser_connection_count(void);
int tls_fixer_browser_connect(void *connection, int index, unsigned char nonblocking,
    unsigned char *done, int *handled);
int tls_fixer_browser_pending(void *connection, int index, int *handled);
int tls_fixer_browser_check(void *connection, int *handled);
int tls_fixer_browser_close(void *connection, int index, int *handled);
int tls_fixer_browser_recv(void *connection, int index, void *data,
    unsigned int length, int *error);
int tls_fixer_browser_send(void *connection, int index, const void *data,
    unsigned int length, int *error);

#endif
