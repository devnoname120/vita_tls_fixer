#define _POSIX_C_SOURCE 200809L
#include "user_runtime.h"
#include "user_runtime_mock.h"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct Block { void *base; unsigned bytes, used, peak; int live, heap; } Block;
typedef union MockHeader { struct { Block *owner; size_t bytes; } info; max_align_t alignment; } MockHeader;
static Block blocks[64];
static int failure, fail_allocate, fail_free_once, mutex_live;
static unsigned block_live, console_calls, first_reservation;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static Block *block_from_heap(SceClibMspace heap) {
    Block *b = heap; assert(b >= blocks && b < blocks + 64 && b->live && b->heap); return b;
}
SceUID sceKernelAllocMemBlock(const char *name, int type, SceSize size, const void *options) {
    (void)name; (void)options; assert(type == SCE_KERNEL_MEMBLOCK_TYPE_USER_RW);
    if (failure == 1) return -17;
    for (unsigned i = 0; i < 64; ++i) if (!blocks[i].live) {
        Block *b = &blocks[i]; *b = (Block){.base = malloc(size), .bytes = size, .live = 1};
        assert(b->base); if (!block_live) first_reservation = size; ++block_live; return (SceUID)i + 1;
    }
    return -20;
}
int sceKernelGetMemBlockBase(SceUID id, void **out) {
    assert(id > 0 && id <= 64 && blocks[id-1].live);
    if (failure == 2) return -18;
    *out = blocks[id-1].base; return 0;
}
int sceKernelFreeMemBlock(SceUID id) {
    assert(id > 0 && id <= 64); Block *b = &blocks[id-1]; assert(b->live && !b->heap && !b->used);
    if (fail_free_once) { fail_free_once = 0; return -23; }
    free(b->base); *b = (Block){0}; --block_live; return 0;
}
SceUID sceKernelCreateMutex(const char *name, unsigned attrs, int count, const void *options) {
    (void)name; (void)attrs; (void)count; (void)options;
    if (failure == 3) return -19;
    assert(!mutex_live); mutex_live = 1; return 99;
}
int sceKernelLockMutex(SceUID id, int count, unsigned *timeout) {
    (void)count; (void)timeout; assert(id == 99 && mutex_live); return pthread_mutex_lock(&lock);
}
int sceKernelUnlockMutex(SceUID id, int count) { (void)count; assert(id == 99); return pthread_mutex_unlock(&lock); }
int sceKernelDeleteMutex(SceUID id) { assert(id == 99 && mutex_live); mutex_live = 0; return 0; }
SceClibMspace sceClibMspaceCreate(void *base, SceSize bytes) {
    assert((uintptr_t)base % 16u == 0);
    for (unsigned i = 0; i < 64; ++i) if (blocks[i].live && (unsigned char *)base >= (unsigned char *)blocks[i].base && (unsigned char *)base < (unsigned char *)blocks[i].base + blocks[i].bytes) {
        Block *b = &blocks[i]; assert(bytes <= b->bytes && !b->heap);
        if (failure == 4) return NULL;
        b->heap = 1; return b;
    }
    abort();
}
void sceClibMspaceDestroy(SceClibMspace heap) { Block *b = block_from_heap(heap); assert(!b->used); b->heap = 0; }
int sceClibMspaceIsHeapEmpty(SceClibMspace heap) { return block_from_heap(heap)->used == 0; }
void sceClibMspaceMallocStats(SceClibMspace heap, SceClibMspaceStats *out) {
    Block *b = block_from_heap(heap); *out = (SceClibMspaceStats){b->bytes,b->bytes,b->peak,b->used};
}
void *sceClibMspaceMalloc(SceClibMspace heap, SceSize size) {
    Block *b = block_from_heap(heap);
    if (fail_allocate || size > b->bytes - b->used) return NULL;
    MockHeader *h = malloc(sizeof(*h) + size); assert(h);
    h->info.owner = b; h->info.bytes = size; b->used += size;
    if (b->used > b->peak) b->peak = b->used;
    return h + 1;
}
void sceClibMspaceFree(SceClibMspace heap, void *pointer) {
    Block *b = block_from_heap(heap); MockHeader *h = (MockHeader *)pointer - 1;
    assert(h->info.owner == b && h->info.bytes <= b->used);
    b->used -= (unsigned)h->info.bytes; free(h);
}
void *sceClibMspaceRealloc(SceClibMspace heap, void *pointer, SceSize size) {
    Block *b = block_from_heap(heap); MockHeader *h = (MockHeader *)pointer - 1;
    assert(h->info.owner == b);
    if (fail_allocate || size > b->bytes - b->used + h->info.bytes) return NULL;
    size_t old = h->info.bytes; h = realloc(h, sizeof(*h) + size); assert(h);
    h->info.bytes = size; b->used = b->used - (unsigned)old + size;
    if (b->used > b->peak) b->peak = b->used;
    return h + 1;
}
void *sceClibMemchr(const void *p, int v, SceSize n) { return memchr(p,v,n); }
int sceClibMemcmp(const void *a, const void *b, SceSize n) { return memcmp(a,b,n); }
void *sceClibMemcpy(void *a, const void *b, SceSize n) { return memcpy(a,b,n); }
void *sceClibMemmove(void *a, const void *b, SceSize n) { return memmove(a,b,n); }
void *sceClibMemset(void *a, int v, SceSize n) { return memset(a,v,n); }
char *sceClibStrchr(const char *s, int v) { return strchr(s,v); }
int sceClibStrcmp(const char *a, const char *b) { return strcmp(a,b); }
SceSize sceClibStrnlen(const char *s, SceSize n) { return (SceSize)strnlen(s,n); }
char *sceClibStrstr(const char *s, const char *n) { return strstr(s,n); }
int sceClibVsnprintf(char *s, SceSize n, const char *f, va_list args) { return vsnprintf(s,n,f,args); }
int sceClibVprintf(const char *f, va_list args) { ++console_calls; return vprintf(f,args); }
int sceClibPrintf(const char *f, ...) { ++console_calls; va_list args; va_start(args,f); int n=vprintf(f,args); va_end(args); return n; }
static TlsFixerRuntimeStats stats(void) {
    TlsFixerRuntimeStats s; assert(tls_fixer_user_runtime_stats(&s) == 0); return s;
}
static void *worker(void *unused) {
    (void)unused;
    for (unsigned i = 0; i < 500; ++i) {
        unsigned char *p = __wrap_calloc(13,17); assert(p && (uintptr_t)p % _Alignof(max_align_t) == 0);
        for (unsigned j = 0; j < 221; ++j) assert(p[j] == 0);
        __wrap_free(p);
    }
    return NULL;
}
int main(void) {
    assert(!__wrap_malloc(1));
    for (failure = 1; failure <= 4; ++failure) {
        assert(tls_fixer_user_runtime_init() < 0 && !block_live && !mutex_live);
    }
    failure = 0;
    assert(tls_fixer_user_runtime_init() == 0 && block_live == 1 && first_reservation == 131072);
    assert(tls_fixer_user_runtime_init() < 0);
    assert(stats().capacity == 131072 && stats().outstanding == 0);
    assert(!__wrap_malloc(SIZE_MAX) && !__wrap_calloc(SIZE_MAX,2));

    /* The old fixed pool fails here. Active connections may outgrow the initial
     * reservation without making every HTTP initialization reserve the maximum. */
    unsigned char *a = __wrap_malloc(100 * 1024); assert(a); memset(a,0x5a,100 * 1024);
    unsigned char *b = __wrap_malloc(40 * 1024); assert(b); memset(b,0xa5,40 * 1024);
    unsigned char *c = __wrap_malloc(40 * 1024); assert(c); memset(c,0x3c,40 * 1024);
    assert(stats().capacity == 262144 && stats().outstanding == 3);
    assert(tls_fixer_user_runtime_destroy() < 0);
    a = __wrap_realloc(a,150 * 1024); assert(a);
    for (unsigned i = 0; i < 100 * 1024; ++i) assert(a[i] == 0x5a);
    assert(stats().outstanding == 3 && stats().capacity <= 524288);
    fail_allocate = 1; assert(!__wrap_realloc(b,80 * 1024)); fail_allocate = 0;
    for (unsigned i = 0; i < 40 * 1024; ++i) assert(b[i] == 0xa5 && c[i] == 0x3c);
    __wrap_free(b); __wrap_free(c); __wrap_free(a);
    assert(stats().outstanding == 0 && stats().used == 0 && stats().capacity == 131072 && block_live == 1);

    /* Demand can exceed both the old 512 KiB cap and eight-pool limit.
     * Kernel allocation failure is the limit; all extra pools are returned. */
    void *pieces[40]; unsigned count = 0;
    while (count < 40 && (pieces[count] = __wrap_malloc(60 * 1024))) {
        memset(pieces[count],(int)count,60 * 1024); ++count;
    }
    assert(count == 40 && stats().capacity > 2 * 1024 * 1024 && stats().outstanding == count);
    for (unsigned i = 0; i < count; ++i) {
        assert(((unsigned char *)pieces[i])[0] == i && ((unsigned char *)pieces[i])[60*1024-1] == i);
        __wrap_free(pieces[i]);
    }
    assert(stats().capacity == 131072 && stats().outstanding == 0 && block_live == 1);

    a = __wrap_malloc(100 * 1024); assert(a);
    failure = 1; assert(!__wrap_malloc(40 * 1024)); failure = 0;
    b = __wrap_malloc(40 * 1024); assert(b);
    fail_free_once = 1; __wrap_free(b);
    assert(block_live == 2); /* Failed kernel release remains tracked. */
    b = __wrap_malloc(1); assert(b); __wrap_free(b); __wrap_free(a);
    assert(block_live == 1 && stats().capacity == 131072);
    a = __wrap_realloc(NULL,16); assert(a); assert(!__wrap_realloc(a,0));
    __wrap_free(NULL);
    pthread_t threads[4];
    for (unsigned i = 0; i < 4; ++i) assert(!pthread_create(&threads[i],NULL,worker,NULL));
    for (unsigned i = 0; i < 4; ++i) assert(!pthread_join(threads[i],NULL));
    assert(stats().outstanding == 0 && stats().used == 0 && stats().peak > 131072 && !console_calls);
    fail_free_once = 1; assert(tls_fixer_user_runtime_destroy() < 0);
    assert(!__wrap_malloc(1) && tls_fixer_user_runtime_destroy() == 0);
    assert(tls_fixer_user_runtime_destroy() == 0 && !block_live && !mutex_live);
    assert(tls_fixer_user_runtime_init() == 0 && stats().capacity == 131072);
    assert(tls_fixer_user_runtime_destroy() == 0 && !block_live && !mutex_live);
    puts("On-demand TLS pools, bounded pressure, moving realloc, release retry and concurrency: PASS");
}
