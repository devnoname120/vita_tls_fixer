#include "stack_probe.h"
#include <stddef.h>
#include <psp2kern/kernel/sysclib.h>

int module_get_export_func(int32_t pid, const char *module, uint32_t library,
    uint32_t function, uintptr_t *address);

static uint32_t (*native_stack_remaining)(void);

int tls_fixer_stack_probe_init(void) {
    static const uint8_t expected[] = {
        0x1d,0xee,0x90,0x3f,0x5b,0xb1,0xd3,0xf8,0x74,0x00,0x85,0x45,0x07,0xdd,
        0xd3,0xf8,0x78,0x30,0xbd,0xeb,0x00,0x00,0x83,0x42,0xd8,0xbf,0x00,0x20,
        0x70,0x47,0x00,0x20,0x70,0x47};
    uintptr_t address = 0;
    if (native_stack_remaining != NULL) return -1;
    int result = module_get_export_func(INT32_C(0x10005), "SceKernelThreadMgr",
        UINT32_C(0xe2c40624), UINT32_C(0xd74f66bd), &address);
    if (result < 0 || address <= 1 || (address & 1) == 0) return -1;
    /* An unmatched implementation is not a validated stack measurement. */
    if (memcmp((const void *)(address & ~(uintptr_t)1), expected, sizeof(expected)) != 0) return -1;
    native_stack_remaining = (uint32_t (*)(void))address;
    return 0;
}

uint32_t tls_fixer_stack_probe_read(void) {
    return native_stack_remaining != NULL ? native_stack_remaining() : UINT32_MAX;
}
