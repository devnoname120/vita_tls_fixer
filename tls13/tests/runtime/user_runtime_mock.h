#ifndef TLS_FIXER_USER_RUNTIME_MOCK_H
#define TLS_FIXER_USER_RUNTIME_MOCK_H
#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
typedef int SceUID;
typedef unsigned int SceSize;
typedef void *SceClibMspace;
typedef struct { SceSize capacity, unk, peak_in_use, current_in_use; } SceClibMspaceStats;
#define SCE_KERNEL_MEMBLOCK_TYPE_USER_RW 1
SceUID sceKernelAllocMemBlock(const char *, int, SceSize, const void *);
int sceKernelGetMemBlockBase(SceUID, void **);
int sceKernelFreeMemBlock(SceUID);
SceUID sceKernelCreateMutex(const char *, unsigned, int, const void *);
int sceKernelLockMutex(SceUID, int, unsigned *);
int sceKernelUnlockMutex(SceUID, int);
int sceKernelDeleteMutex(SceUID);
SceClibMspace sceClibMspaceCreate(void *, SceSize);
void sceClibMspaceDestroy(SceClibMspace);
void sceClibMspaceMallocStats(SceClibMspace, SceClibMspaceStats *);
int sceClibMspaceIsHeapEmpty(SceClibMspace);
void *sceClibMspaceMalloc(SceClibMspace, SceSize);
void *sceClibMspaceRealloc(SceClibMspace, void *, SceSize);
void sceClibMspaceFree(SceClibMspace, void *);
void *sceClibMemchr(const void *, int, SceSize);
int sceClibMemcmp(const void *, const void *, SceSize);
void *sceClibMemcpy(void *, const void *, SceSize);
void *sceClibMemmove(void *, const void *, SceSize);
void *sceClibMemset(void *, int, SceSize);
char *sceClibStrchr(const char *, int);
int sceClibStrcmp(const char *, const char *);
SceSize sceClibStrnlen(const char *, SceSize);
char *sceClibStrstr(const char *, const char *);
int sceClibVsnprintf(char *, SceSize, const char *, va_list);
int sceClibVprintf(const char *, va_list);
int sceClibPrintf(const char *, ...);
#endif
