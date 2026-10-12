#include "code_snapshot.h"
#include "boot_trace.h"
#include <psp2kern/kernel/sysmem.h>
#include <stdint.h>

int tls_fixer_code_snapshot(SceUID pid, const SceKernelModuleInfo *module,
    size_t offset, const char *stage) {
    unsigned char bytes[16] = {0};
    if (pid <= 0 || module == NULL || stage == NULL) return -1;
    const SceKernelSegmentInfo *segment = &module->segments[0];
    uintptr_t base = (uintptr_t)segment->vaddr;
    if (base == 0 || base > UINT32_MAX || offset > segment->filesz ||
        sizeof(bytes) > segment->filesz - offset || offset > segment->memsz ||
        sizeof(bytes) > segment->memsz - offset || offset > UINT32_MAX - base ||
        sizeof(bytes) - 1 > UINT32_MAX - base - offset) return -1;
    uintptr_t address = base + offset;
    if (tls_fixer_boot_trace_event("code.copy.enter", pid, (int32_t)address, sizeof(bytes)) < 0) return -1;
    int copied = ksceKernelCopyFromUserProc(pid, bytes, (const void *)address, sizeof(bytes));
    if (tls_fixer_boot_trace_event("code.copy.return", pid, (int32_t)address, copied) < 0 || copied != 0)
        return -1;
    for (unsigned int i = 0; i < sizeof(bytes); i += 4) {
        uint32_t word = (uint32_t)bytes[i] | (uint32_t)bytes[i + 1] << 8 |
            (uint32_t)bytes[i + 2] << 16 | (uint32_t)bytes[i + 3] << 24;
        if (tls_fixer_boot_trace_event(stage, pid, (int32_t)(address + i), (int32_t)word) < 0) return -1;
    }
    return 0;
}
