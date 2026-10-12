#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>

static _Alignas(4) uint8_t code[36];
static uintptr_t export_address;
static int lookup_result;

int module_get_export_func(int32_t pid, const char *module, uint32_t library,
    uint32_t function, uintptr_t *address) {
    assert(pid == 0x10005 && strcmp(module, "SceKernelThreadMgr") == 0);
    assert(library == UINT32_C(0xe2c40624) && function == UINT32_C(0xd74f66bd));
    *address = export_address;
    return lookup_result;
}

#include "../../../kernel/stack_probe.c"

static uint32_t free_bytes;
static uint32_t mock_native_probe(void) { return free_bytes; }

int main(void) {
    static const uint8_t expected[] = {
        0x1d,0xee,0x90,0x3f,0x5b,0xb1,0xd3,0xf8,0x74,0x00,0x85,0x45,0x07,0xdd,
        0xd3,0xf8,0x78,0x30,0xbd,0xeb,0x00,0x00,0x83,0x42,0xd8,0xbf,0x00,0x20,
        0x70,0x47,0x00,0x20,0x70,0x47};
    assert(tls_fixer_stack_probe_read() == UINT32_MAX);
    memcpy(code, expected, sizeof(expected));
    lookup_result = -7;
    export_address = (uintptr_t)code | 1;
    assert(tls_fixer_stack_probe_init() < 0);
    lookup_result = 0;
    export_address = 0;
    assert(tls_fixer_stack_probe_init() < 0);
    export_address = (uintptr_t)code;
    assert(tls_fixer_stack_probe_init() < 0);
    export_address |= 1;
    for (size_t i = 0; i < sizeof(expected); ++i) {
        code[i] ^= 1;
        assert(tls_fixer_stack_probe_init() < 0);
        assert(tls_fixer_stack_probe_read() == UINT32_MAX);
        code[i] ^= 1;
    }
    assert(tls_fixer_stack_probe_init() == 0);
    assert((uintptr_t)native_stack_remaining == export_address);
    assert(tls_fixer_stack_probe_init() < 0);
    native_stack_remaining = mock_native_probe;
    free_bytes = 4096;
    assert(tls_fixer_stack_probe_read() == 4096);
    free_bytes = 0;
    assert(tls_fixer_stack_probe_read() == 0);
    puts("exact native kernel-stack probe export validation: PASS");
    return 0;
}
