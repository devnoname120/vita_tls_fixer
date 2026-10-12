#ifndef TLS_FIXER_PROBE_NONCE_H
#define TLS_FIXER_PROBE_NONCE_H

#include <stddef.h>

#define TLS_FIXER_PROBE_NONCE_BYTES 16u
#define TLS_FIXER_PROBE_NONCE_TEXT 33u

typedef int (*TlsFixerProbeRandom)(void *, unsigned char *, size_t);
int tls_fixer_probe_generate_nonce(TlsFixerProbeRandom random, void *context, char *output, size_t capacity);
int tls_fixer_probe_vita_nonce(char *output, size_t capacity);

#endif
