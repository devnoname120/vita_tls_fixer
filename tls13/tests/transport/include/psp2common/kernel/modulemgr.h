#ifndef TLS_FIXER_MOCK_MODULEMGR_H
#define TLS_FIXER_MOCK_MODULEMGR_H
#include <vita_mock.h>

#define SCE_KERNEL_START_SUCCESS 0
#define SCE_KERNEL_START_NO_RESIDENT 1
#define SCE_KERNEL_START_FAILED 2
#define SCE_KERNEL_STOP_SUCCESS 0
#define SCE_KERNEL_STOP_FAIL 1

typedef struct {
    SceSize size;
    uint32_t perms;
    void *vaddr;
    uint32_t filesz;
    uint32_t memsz;
} SceKernelSegmentInfo;

typedef struct {
    SceSize size;
    SceUID modid;
    uint16_t modattr;
    uint8_t modver[2];
    char module_name[28];
    void *start_entry;
    char path[256];
    SceKernelSegmentInfo segments[4];
} SceKernelModuleInfo;

int sceKernelGetModuleInfo(SceUID modid, SceKernelModuleInfo *info);
#endif
