#ifndef TLS_FIXER_PROBE_PROTOCOL_H
#define TLS_FIXER_PROBE_PROTOCOL_H

#include <stddef.h>

#define TLS_FIXER_PROBE_REQUEST_LIMIT 1024u
#define TLS_FIXER_PROBE_RESPONSE_LIMIT 4096u
#define TLS_FIXER_PROBE_NONCE_SIZE 32u

int tls_fixer_probe_dns_name(const char *name);
int tls_fixer_probe_nonce_valid(const char *nonce);
int tls_fixer_probe_request(const char *name, unsigned int port, const char *nonce,
    char *output, size_t capacity);
int tls_fixer_probe_response(const unsigned char *data, size_t size, const char *nonce,
    size_t *complete_size);

#endif
