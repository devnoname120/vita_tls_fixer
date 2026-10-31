#ifndef TLS_FIXER_ENTRY_GATE_H
#define TLS_FIXER_ENTRY_GATE_H

#include <stdint.h>

#define TLS_FIXER_GATE_CLOSED UINT32_C(0x80000000)
#define TLS_FIXER_GATE_COUNT UINT32_C(0x7fffffff)

/* Closing and admitting a call use the same atomic word. A zero count alone
 * cannot authorize freeing the runtime while another thread enters it. */
static inline int tls_fixer_gate_enter(uint32_t *gate) {
    uint32_t value = __atomic_load_n(gate, __ATOMIC_ACQUIRE);
    while (!(value & TLS_FIXER_GATE_CLOSED) && (value & TLS_FIXER_GATE_COUNT) != TLS_FIXER_GATE_COUNT) {
        if (__atomic_compare_exchange_n(gate, &value, value + 1, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) return 1;
    }
    return 0;
}
static inline void tls_fixer_gate_leave(uint32_t *gate) {
    __atomic_sub_fetch(gate, 1, __ATOMIC_RELEASE);
}
static inline uint32_t tls_fixer_gate_close(uint32_t *gate) {
    return __atomic_fetch_or(gate, TLS_FIXER_GATE_CLOSED, __ATOMIC_ACQ_REL) & TLS_FIXER_GATE_COUNT;
}
static inline uint32_t tls_fixer_gate_count(const uint32_t *gate) {
    return __atomic_load_n(gate, __ATOMIC_ACQUIRE) & TLS_FIXER_GATE_COUNT;
}
/* Reopen after a rejected stop without losing already-admitted references. */
static inline void tls_fixer_gate_reopen(uint32_t *gate) {
    __atomic_fetch_and(gate, TLS_FIXER_GATE_COUNT, __ATOMIC_RELEASE);
}
static inline void tls_fixer_gate_open(uint32_t *gate) {
    __atomic_store_n(gate, 0, __ATOMIC_RELEASE);
}

#endif
