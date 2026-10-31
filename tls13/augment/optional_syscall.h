#ifndef TLS_FIXER_OPTIONAL_SYSCALL_H
#define TLS_FIXER_OPTIONAL_SYSCALL_H
#include <stdint.h>

/* Modulemgr emits MOVW ip,#ordinal; SVC #0; BX lr for a bound syscall.
 * An unresolved weak import is rewritten to SUB ip,pc,#8; MOV pc,#0,
 * so the SDK's harmless on-disk placeholder cannot be used as a runtime guard. */
static inline int tls_fixer_syscall_stub_bound(const volatile uint32_t *code) {
    return code != 0 &&
        (code[0] & UINT32_C(0xfffff000)) == UINT32_C(0xe300c000) &&
        code[1] == UINT32_C(0xef000000) && code[2] == UINT32_C(0xe12fff1e);
}

/* The same native emitter uses MOVW/MOVT ip,#target; BX ip for user imports.
 * Check the complete instruction form before calling optional native getters. */
static inline int tls_fixer_user_stub_bound(const volatile uint32_t *code) {
    if (code == 0 ||
        (code[0] & UINT32_C(0xfff0f000)) != UINT32_C(0xe300c000) ||
        (code[1] & UINT32_C(0xfff0f000)) != UINT32_C(0xe340c000) ||
        code[2] != UINT32_C(0xe12fff1c)) return 0;
    uint32_t low = (code[0] & 0xfffu) | ((code[0] >> 4) & 0xf000u);
    uint32_t high = (code[1] & 0xfffu) | ((code[1] >> 4) & 0xf000u);
    uint32_t target = low | (high << 16);
    return target >= UINT32_C(0x80000000) && target < UINT32_C(0xf0000000);
}
#endif
