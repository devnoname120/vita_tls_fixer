#ifndef TLS_FIXER_KERNEL_MOCK_H
#define TLS_FIXER_KERNEL_MOCK_H
#include <vita_mock.h>
#include <psp2common/kernel/modulemgr.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef struct { uint64_t size; } SceIoStat;
typedef struct { unsigned int kind; } SceSha256Context;
#define SCE_SHA256_DIGEST_SIZE 32
#define SCE_KERNEL_MEMBLOCK_TYPE_KERNEL_RW 0x1020D006
#define SCE_KERNEL_MEMBLOCK_TYPE_USER_RW 0x0C20D060
#define SCE_KERNEL_ALLOC_MEMBLOCK_ATTR_HAS_PID 0x80
typedef struct {
    uint32_t size, field_4, attr, field_C, paddr, alignment, extraLow, extraHigh;
    uint32_t mirror_blockid;
    SceUID pid;
    uint32_t reserved[12];
} SceKernelAllocMemBlockKernelOpt;
#ifndef SCE_O_RDWR
#define SCE_O_RDWR 3
#endif
typedef int64_t SceOff;

int ksceIoOpen(const char *, int, int);
SceUID ksceIoOpenForPid(SceUID, const char *, int, unsigned int);
int ksceIoGetstatByFd(SceUID, SceIoStat *);
int ksceIoRead(int, void *, unsigned int);
int ksceIoClose(int);
int ksceIoGetstat(const char *, SceIoStat *);
int ksceIoPwrite(SceUID, const void *, SceSize, SceOff);
SceOff ksceIoLseek(SceUID, SceOff, int);
int ksceIoSync(const char *, unsigned int);
SceUID ksceKernelAllocMemBlock(const char *, int, SceSize, const void *);
int ksceKernelGetMemBlockBase(SceUID, void **);
int ksceKernelFreeMemBlock(SceUID);
int ksceKernelCopyToUserProc(SceUID, void *, const void *, SceSize);
int ksceKernelCopyFromUserProc(SceUID, void *, const void *, SceSize);
int ksceSha256BlockInit(SceSha256Context *);
int ksceSha256BlockUpdate(SceSha256Context *, const void *, SceSize);
int ksceSha256BlockResult(SceSha256Context *, uint8_t *);
int timingsafe_memcmp(const void *, const void *, size_t);
SceUID ksceKernelCreateMutex(const char *, unsigned int, int, const void *);
int ksceKernelDeleteMutex(SceUID);
int ksceKernelLockMutex(SceUID, int, unsigned int *);
int ksceKernelUnlockMutex(SceUID, int);
int ksceKernelGetModuleList(SceUID, unsigned int, unsigned int, SceUID *, SceSize *);
int ksceKernelGetModuleInfo(SceUID, SceUID, SceKernelModuleInfo *);
int ksceKernelGetModuleIsSharedByAddr(SceUID, void *);
SceUID ksceKernelLoadStartModuleForPid(SceUID, const char *, SceSize, const void *, int, const void *, int *);
int ksceKernelUnloadModuleForPid(SceUID, SceUID, int, const void *);
SceUID ksceKernelGetProcessId(void);
int ksceKernelRunWithStack(SceSize, int (*)(void *), void *);
int ksceKernelGetThreadId(void);
int64_t ksceKernelGetSystemTimeWide(void);
typedef int (*SceKernelThreadEntry)(SceSize, void *);
typedef struct { unsigned int size; } SceKernelThreadOptParam;
SceUID ksceKernelCreateThread(const char *, SceKernelThreadEntry, int, SceSize, SceUInt, int,
    const SceKernelThreadOptParam *);
int ksceKernelStartThread(SceUID, SceSize, void *);
int ksceKernelWaitThreadEnd(SceUID, int *, SceUInt *);
int ksceKernelDeleteThread(SceUID);
int ksceKernelDelayThread(SceUInt);
SceUID ksceKernelSysrootGetShellPid(void);
SceUID ksceKernelSearchModuleByName(const char *);
int ksceDebugPrintf(const char *, ...);
#endif
