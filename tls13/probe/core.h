#ifndef TLS_FIXER_PROBE_CORE_H
#define TLS_FIXER_PROBE_CORE_H

#include "protocol.h"
#include <mbedtls/x509_crt.h>
#include <stdint.h>

#define TLS_FIXER_PROBE_DEADLINE_MS UINT64_C(15000)
#define TLS_FIXER_PROBE_INVALID (-100001)
#define TLS_FIXER_PROBE_FRAMING (-100002)
#define TLS_FIXER_PROBE_EOF (-100003)
#define TLS_FIXER_PROBE_CLOCK (-100004)

typedef struct TlsFixerProbeIo {
    void *context;
    int (*start)(void *, const char *, unsigned int);
    int (*finish_connect)(void *);
    int (*wait)(void *, int, unsigned int);
    int (*send)(void *, const unsigned char *, size_t);
    int (*recv)(void *, unsigned char *, size_t);
    int (*close)(void *);
    int (*native_error)(void *);
    uint64_t (*now_ms)(void *);
} TlsFixerProbeIo;

typedef struct TlsFixerProbeResult {
    const char *stage;
    char negotiated[24];
    char cipher[96];
    uint64_t elapsed_ms;
    uint32_t verify_flags;
    int error, native_error, cleanup_error;
    int handshake_complete, peer_verified, exchange_complete;
    unsigned int requested_version;
} TlsFixerProbeResult;

int tls_fixer_probe_run(const TlsFixerProbeIo *io, mbedtls_x509_crt *ca, const char *address,
    const char *name, unsigned int port, unsigned int version, const char *nonce,
    TlsFixerProbeResult *result);

#endif
