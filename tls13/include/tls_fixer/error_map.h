#ifndef TLS_FIXER_ERROR_MAP_H
#define TLS_FIXER_ERROR_MAP_H

#include <stdint.h>

#include "tls_fixer/sony_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum TlsFixerOutcome {
    TLS_FIXER_OUTCOME_OK = 0,
    TLS_FIXER_OUTCOME_WANT_READ,
    TLS_FIXER_OUTCOME_WANT_WRITE,
    TLS_FIXER_OUTCOME_CLOSE_NOTIFY,
    TLS_FIXER_OUTCOME_EOF,
    TLS_FIXER_OUTCOME_TIMEOUT,
    TLS_FIXER_OUTCOME_CERTIFICATE,
    TLS_FIXER_OUTCOME_HANDSHAKE,
    TLS_FIXER_OUTCOME_IO,
    TLS_FIXER_OUTCOME_NO_MEMORY,
    TLS_FIXER_OUTCOME_INTERNAL
} TlsFixerOutcome;

#define TLS_FIXER_CERT_INVALID UINT32_C(0x01)
#define TLS_FIXER_CERT_HOSTNAME UINT32_C(0x02)
#define TLS_FIXER_CERT_EXPIRED UINT32_C(0x04)
#define TLS_FIXER_CERT_FUTURE UINT32_C(0x08)
#define TLS_FIXER_CERT_UNKNOWN_CA UINT32_C(0x10)
#define TLS_FIXER_CERT_INTERNAL UINT32_C(0x20)

typedef struct TlsFixerMappedError {
    int32_t hook_result;
    int32_t ssl_error;
    uint32_t detail;
    uint8_t fatal;
} TlsFixerMappedError;

uint32_t tls_fixer_map_certificate_detail(uint32_t provider_flags);
uint32_t tls_fixer_filter_certificate_flags(uint32_t provider_flags, uint32_t https_options);
TlsFixerMappedError tls_fixer_map_outcome(TlsFixerOutcome outcome, uint32_t detail);

#ifdef __cplusplus
}
#endif

#endif
