#ifndef TLS_FIXER_MODULE_GATE_H
#define TLS_FIXER_MODULE_GATE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct TlsFixerMaskedSignature {
    const char *name;
    size_t offset;
    const uint8_t *bytes;
    const char *mask;
    size_t length;
} TlsFixerMaskedSignature;

typedef struct TlsFixerModuleDescriptor {
    size_t text_size;
    const TlsFixerMaskedSignature *signatures;
    size_t signature_count;
} TlsFixerModuleDescriptor;

typedef enum TlsFixerModuleGateResult {
    TLS_FIXER_MODULE_GATE_OK = 0,
    TLS_FIXER_MODULE_GATE_INVALID_ARGUMENT = -1,
    TLS_FIXER_MODULE_GATE_TEXT_SIZE_MISMATCH = -2,
    TLS_FIXER_MODULE_GATE_SIGNATURE_BOUNDS = -3,
    TLS_FIXER_MODULE_GATE_SIGNATURE_MASK = -4,
    TLS_FIXER_MODULE_GATE_SIGNATURE_MISMATCH = -5
} TlsFixerModuleGateResult;

int tls_fixer_validate_module_text(
    const uint8_t *text,
    size_t text_size,
    const TlsFixerModuleDescriptor *descriptor,
    size_t *failed_signature_index,
    size_t *failed_byte_index);

#ifdef __cplusplus
}
#endif

#endif
