#include "entry_gate.h"
#include <assert.h>
#include <stdio.h>

int main(void) {
    uint32_t gate = TLS_FIXER_GATE_CLOSED;
    assert(!tls_fixer_gate_enter(&gate));
    tls_fixer_gate_open(&gate);
    assert(tls_fixer_gate_enter(&gate));
    assert(tls_fixer_gate_enter(&gate));
    assert(tls_fixer_gate_close(&gate) == 2);
    assert(!tls_fixer_gate_enter(&gate));
    tls_fixer_gate_leave(&gate);
    assert(tls_fixer_gate_close(&gate) == 1);
    tls_fixer_gate_leave(&gate);
    assert(tls_fixer_gate_close(&gate) == 0);
    assert(!tls_fixer_gate_enter(&gate));
    tls_fixer_gate_open(&gate);
    assert(tls_fixer_gate_enter(&gate));
    tls_fixer_gate_leave(&gate);
    assert(tls_fixer_gate_close(&gate) == 0);
    gate = TLS_FIXER_GATE_COUNT;
    assert(!tls_fixer_gate_enter(&gate));
    puts("TLS entry admission closes atomically and drains before cleanup");
    return 0;
}
