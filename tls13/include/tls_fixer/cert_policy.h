#ifndef TLS_FIXER_CERT_POLICY_H
#define TLS_FIXER_CERT_POLICY_H

#include <stddef.h>
#include <stdint.h>

typedef struct TlsFixerCertPolicy {
    int (*is_game_program)(void);
    int (*is_system_callback)(void *address);
    uint32_t (*compatibility_version)(void);
    int (*system_parameter)(int selector, int *value);
} TlsFixerCertPolicy;

int tls_fixer_cert_callback_accepted(int result, uint32_t verification_detail,
                                uintptr_t callback, const TlsFixerCertPolicy *policy);
int tls_fixer_cert_policy_bind(TlsFixerCertPolicy *policy, const void *text, size_t text_size);

#endif
