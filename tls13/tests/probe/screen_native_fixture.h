#ifndef TLS_FIXER_PROBE_SCREEN_NATIVE_FIXTURE_H
#define TLS_FIXER_PROBE_SCREEN_NATIVE_FIXTURE_H

#include <stddef.h>
#include <stdint.h>
#define SCE_KERNEL_MEMBLOCK_TYPE_USER_CDRAM_RW 0x09408060
#define SCE_DISPLAY_PIXELFORMAT_A8B8G8R8 0
#define SCE_DISPLAY_SETBUF_NEXTFRAME 1

typedef struct {
    size_t size;
    uint32_t attr;
    size_t alignment;
} SceKernelAllocMemBlockOpt;
typedef struct {
    size_t size;
    void *base;
    unsigned int pitch, pixelformat, width, height;
} SceDisplayFrameBuf;

int sceKernelAllocMemBlock(const char *, int, unsigned int, SceKernelAllocMemBlockOpt *);
int sceKernelGetMemBlockBase(int, void **);
int sceKernelFreeMemBlock(int);
int sceDisplaySetFrameBuf(const SceDisplayFrameBuf *, int);
int sceDisplayWaitSetFrameBuf(void);

#endif
