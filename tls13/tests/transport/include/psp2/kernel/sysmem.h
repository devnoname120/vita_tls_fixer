#ifndef TLS_FIXER_MOCK_SYSMEM_H
#define TLS_FIXER_MOCK_SYSMEM_H

#include <vita_mock.h>

typedef struct SceKernelMemBlockInfo {
    SceSize size;
    void *mappedBase;
    SceSize mappedSize;
    int memoryType;
    uint32_t access;
    int type;
} SceKernelMemBlockInfo;

enum {
    SCE_KERNEL_MEMORY_ACCESS_X = 0x01,
    SCE_KERNEL_MEMORY_ACCESS_W = 0x02,
    SCE_KERNEL_MEMORY_ACCESS_R = 0x04
};

int sceKernelGetMemBlockInfoByAddr(void *base, SceKernelMemBlockInfo *info);

#endif
