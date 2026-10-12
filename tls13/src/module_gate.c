#include "tls_fixer/module_gate.h"

#include <stddef.h>

int tls_fixer_validate_module_text(
    const uint8_t *text,
    size_t text_size,
    const TlsFixerModuleDescriptor *descriptor,
    size_t *failed_signature_index,
    size_t *failed_byte_index) {
    size_t signature_index;

    if (failed_signature_index != NULL) {
        *failed_signature_index = SIZE_MAX;
    }
    if (failed_byte_index != NULL) {
        *failed_byte_index = SIZE_MAX;
    }

    if (text == NULL || descriptor == NULL ||
        (descriptor->signature_count != 0 && descriptor->signatures == NULL)) {
        return TLS_FIXER_MODULE_GATE_INVALID_ARGUMENT;
    }

    if (text_size != descriptor->text_size) {
        return TLS_FIXER_MODULE_GATE_TEXT_SIZE_MISMATCH;
    }

    for (signature_index = 0; signature_index < descriptor->signature_count; ++signature_index) {
        const TlsFixerMaskedSignature *signature = &descriptor->signatures[signature_index];
        size_t byte_index;

        if (signature->bytes == NULL || signature->mask == NULL || signature->length == 0) {
            if (failed_signature_index != NULL) {
                *failed_signature_index = signature_index;
            }
            return TLS_FIXER_MODULE_GATE_INVALID_ARGUMENT;
        }

        if (signature->offset > text_size || signature->length > text_size - signature->offset) {
            if (failed_signature_index != NULL) {
                *failed_signature_index = signature_index;
            }
            return TLS_FIXER_MODULE_GATE_SIGNATURE_BOUNDS;
        }

        for (byte_index = 0; byte_index < signature->length; ++byte_index) {
            const char mask = signature->mask[byte_index];

            if (mask != 'x' && mask != '?') {
                if (failed_signature_index != NULL) {
                    *failed_signature_index = signature_index;
                }
                if (failed_byte_index != NULL) {
                    *failed_byte_index = byte_index;
                }
                return TLS_FIXER_MODULE_GATE_SIGNATURE_MASK;
            }

            if (mask == 'x' && text[signature->offset + byte_index] != signature->bytes[byte_index]) {
                if (failed_signature_index != NULL) {
                    *failed_signature_index = signature_index;
                }
                if (failed_byte_index != NULL) {
                    *failed_byte_index = byte_index;
                }
                return TLS_FIXER_MODULE_GATE_SIGNATURE_MISMATCH;
            }
        }
    }

    return TLS_FIXER_MODULE_GATE_OK;
}
