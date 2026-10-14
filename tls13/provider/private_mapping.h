#ifndef TLS_FIXER_PRIVATE_MAPPING_H
#define TLS_FIXER_PRIVATE_MAPPING_H
#include <stddef.h>
#include <stdint.h>

/* Allocator-confirmed private main-memory code/data types. Shared kernel/user
 * allocations (0320/03F0...) are deliberately outside this allowlist. */
static inline int tls_fixer_private_mapping_contains(uintptr_t address, size_t length,
    uintptr_t base, size_t capacity, uint32_t type, uint32_t access, int executable) {
    const uint32_t expected_type = executable ? UINT32_C(0x0C20D050) : UINT32_C(0x0C20D060);
    /* The RX type carries execution permission. Retail 3.60's public info API
     * reports R=4 for ordinary executable mappings, omitting the X access bit. */
    const int access_valid = executable ? (access & 6u) == 4u : (access & 7u) == 6u;
    return address >= UINT32_C(0x80000000) && address < UINT32_C(0xE0000000) &&
        base >= UINT32_C(0x80000000) && base <= address && length != 0 &&
        capacity != 0 && capacity <= UINT32_C(0xE0000000) - base &&
        address - base < capacity && length <= capacity - (address - base) &&
        type == expected_type && access_valid;
}

int tls_fixer_require_private_mapping(const void *address, size_t length, int executable);
#endif
