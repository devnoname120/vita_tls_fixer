#include "private_mapping.h"
#include "diagnostics.h"
#include <psp2/kernel/sysmem.h>
#include <string.h>

int tls_fixer_require_private_mapping(const void *address, size_t length, int executable) {
    SceKernelMemBlockInfo info;
    memset(&info, 0, sizeof(info));
    info.size = sizeof(info);
    int result = sceKernelGetMemBlockInfoByAddr((void *)address, &info);
    TLS_FIXER_LOG("event=mapping.gate address=%08X length=%u rc=%08X base=%08X size=%u type=%08X access=%08X",
        (unsigned int)(uintptr_t)address, (unsigned int)length, result,
        (unsigned int)(uintptr_t)info.mappedBase, info.mappedSize, info.type, info.access);
    return result == 0 && tls_fixer_private_mapping_contains((uintptr_t)address, length,
        (uintptr_t)info.mappedBase, info.mappedSize, (uint32_t)info.type, info.access, executable)
        ? 0 : -1;
}
