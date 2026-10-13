#ifndef TLS_FIXER_HTTP_MAPPED_SIGNATURE_H
#define TLS_FIXER_HTTP_MAPPED_SIGNATURE_H

#include <stddef.h>
#include <stdint.h>

/* Only the immediate fields of MOVW/MOVT may change during SCE relocation.
 * Opcode, destination R8, PUSH/SUB and the subsequent LDR remain invariant. */
static inline int tls_fixer_http_create_mov_pair_valid(const uint8_t *code, size_t size) {
    if (code == NULL || size < 18) return 0;
    uint16_t movw1 = (uint16_t)(code[6] | ((uint16_t)code[7] << 8));
    uint16_t movw2 = (uint16_t)(code[8] | ((uint16_t)code[9] << 8));
    uint16_t movt1 = (uint16_t)(code[10] | ((uint16_t)code[11] << 8));
    uint16_t movt2 = (uint16_t)(code[12] | ((uint16_t)code[13] << 8));
    return (movw1 & 0xFBF0u) == 0xF240u && (movw2 & 0x8F00u) == 0x0800u &&
           (movt1 & 0xFBF0u) == 0xF2C0u && (movt2 & 0x8F00u) == 0x0800u;
}

#endif
