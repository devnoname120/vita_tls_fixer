#ifndef TLS_FIXER_CLIENT_HELLO_TRACE_H
#define TLS_FIXER_CLIENT_HELLO_TRACE_H
#include <stddef.h>
#include <stdint.h>

typedef struct { unsigned int format, version; size_t bytes; } TlsFixerHelloView;

/* Outgoing first-write capture only. Reject incomplete or non-ClientHello
 * frames rather than accidentally recording later encrypted/application data. */
static inline int tls_fixer_hello_view(const unsigned char *p, size_t length, TlsFixerHelloView *view) {
    if (p == NULL || view == NULL || length < 11 || length > 4096) return 0;
    if (p[0] == 22 && p[1] == 3 && p[5] == 1) {
        size_t record = ((size_t)p[3] << 8) | p[4];
        size_t handshake = ((size_t)p[6] << 16) | ((size_t)p[7] << 8) | p[8];
        if (record < 4 || record + 5 > length || handshake + 4 != record) return 0;
        view->format = 3; view->version = ((unsigned int)p[9] << 8) | p[10]; view->bytes = record + 5;
        return 1;
    }
    if ((p[0] & 0x80) != 0 && p[2] == 1) {
        size_t record = ((size_t)(p[0] & 0x7f) << 8) | p[1];
        size_t ciphers = ((size_t)p[5] << 8) | p[6];
        size_t session = ((size_t)p[7] << 8) | p[8];
        size_t challenge = ((size_t)p[9] << 8) | p[10];
        if (record + 2 > length || ciphers % 3 != 0 || record != 9 + ciphers + session + challenge) return 0;
        view->format = 2; view->version = ((unsigned int)p[3] << 8) | p[4]; view->bytes = record + 2;
        return 1;
    }
    return 0;
}
#endif
