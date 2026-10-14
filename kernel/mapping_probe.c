#include "mapping_probe.h"
#include "boot_trace.h"
#include <psp2kern/kernel/sysmem.h>
#include <stdint.h>

/* Read-only inspection of a live target mapping; no memory contents are read. */
void tls_fixer_mapping_probe_record(const char *stage, int32_t pid, const void *address) {
    unsigned int type = 0;
    void *base = NULL;
    /* A nonzero size requires an exact allocation-base/size match. Size zero
     * asks the native lookup for the allocation containing this address. */
    SceUID block = ksceKernelFindMemBlockByAddrForPid(pid, address, 0);
    (void)tls_fixer_boot_trace_event("map.block", pid, (int32_t)(uintptr_t)address, block);
    if (block < 0) return;
    int result = ksceKernelGetMemBlockType(block, &type);
    (void)tls_fixer_boot_trace_event(stage, pid, (int32_t)type, result);
    result = ksceKernelGetMemBlockBase(block, &base);
    (void)tls_fixer_boot_trace_event("map.base", pid, (int32_t)(uintptr_t)base, result);
}
