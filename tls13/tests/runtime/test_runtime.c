#define _POSIX_C_SOURCE 200809L
#include "user_runtime.h"
#include "user_runtime_mock.h"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failure, block_live, mutex_live, heap_live, fail_allocate;
static void *block;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned used, peak;
static unsigned console_calls;
typedef union Header { size_t bytes; max_align_t alignment; } Header;
SceUID sceKernelAllocMemBlock(const char *name, int type, SceSize size, const void *options) {
    (void)name; (void)type; (void)options;
    if (failure == 1) return -17;
    assert(!block_live); block = malloc(size); assert(block); block_live = 1; return 1;
}
int sceKernelGetMemBlockBase(SceUID id, void **out) {
    assert(id == 1); if (failure == 2) return -18; *out = block; return 0;
}
int sceKernelFreeMemBlock(SceUID id) { assert(id == 1 && block_live); free(block); block_live = 0; return 0; }
SceUID sceKernelCreateMutex(const char *name, unsigned attrs, int count, const void *options) {
    (void)name; (void)attrs; (void)count; (void)options;
    if (failure == 3) return -19;
    assert(!mutex_live); mutex_live = 1; return 2;
}
int sceKernelLockMutex(SceUID id, int count, unsigned *timeout) {
    (void)count; (void)timeout; assert(id == 2 && mutex_live); return pthread_mutex_lock(&lock);
}
int sceKernelUnlockMutex(SceUID id, int count) { (void)count; assert(id == 2); return pthread_mutex_unlock(&lock); }
int sceKernelDeleteMutex(SceUID id) { assert(id == 2 && mutex_live); mutex_live = 0; return 0; }
SceClibMspace sceClibMspaceCreate(void *base, SceSize size) {
    assert(base == block && size == 2097152);
    if (failure == 4) return NULL;
    heap_live = 1; used = peak = 0; return block;
}
void sceClibMspaceDestroy(SceClibMspace heap) { assert(heap == block && heap_live && used == 0); heap_live = 0; }
int sceClibMspaceIsHeapEmpty(SceClibMspace heap) { assert(heap == block); return used == 0; }
void sceClibMspaceMallocStats(SceClibMspace heap, SceClibMspaceStats *s) {
    assert(heap == block); *s = (SceClibMspaceStats){2097152, 2097152, peak, used};
}
void *sceClibMspaceMalloc(SceClibMspace heap, SceSize size) {
    assert(heap == block && heap_live);
    if (fail_allocate || size > 2097152 - used) return NULL;
    Header *h = malloc(sizeof(*h) + size); assert(h); h->bytes = size;
    used += size; if (used > peak) peak = used; return h + 1;
}
void sceClibMspaceFree(SceClibMspace heap, void *pointer) {
    assert(heap == block); Header *h = (Header *)pointer - 1;
    used -= (unsigned)h->bytes; free(h);
}
void *sceClibMspaceRealloc(SceClibMspace heap, void *pointer, SceSize size) {
    assert(heap == block); Header *h = (Header *)pointer - 1;
    if (fail_allocate || size > 2097152 - used + h->bytes) return NULL;
    size_t old = h->bytes; h = realloc(h, sizeof(*h) + size); assert(h); h->bytes = size;
    used = used - (unsigned)old + size; if (used > peak) peak = used; return h + 1;
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
int sceClibVsnprintf(char *s, SceSize n, const char *f, va_list args) {
    /* Match the actual Vita formatter: bounded bytes, no NUL when truncated. */
    char temp[4096]; int result=vsnprintf(temp,sizeof(temp),f,args);
    if (s && n && result>=0) {
        size_t count=(size_t)result+1; if(count>n)count=n;
        assert(count<=sizeof(temp)); memcpy(s,temp,count);
    }
    return result;
}
int sceClibVprintf(const char *f, va_list args) { ++console_calls; return vprintf(f,args); }
int sceClibPrintf(const char *f, ...) { ++console_calls; va_list a; va_start(a,f); int r=vprintf(f,a); va_end(a); return r; }
static void *worker(void *unused) {
    (void)unused;
    for (int i=0;i<500;++i) {
        unsigned char *p=__wrap_calloc(13,17); assert(p && (uintptr_t)p % 8 == 0);
        for (int j=0;j<221;++j) assert(p[j]==0);
        __wrap_free(p);
    }
    return NULL;
}
int main(void) {
    assert(__wrap_malloc(1)==NULL);
    for (failure=1;failure<=4;++failure) {
        assert(tls_fixer_user_runtime_init()<0);
        assert(!block_live && !mutex_live && !heap_live);
    }
    failure=0;
    assert(tls_fixer_user_runtime_init()==0);
    assert(tls_fixer_user_runtime_init()<0);
    assert(__wrap_calloc(SIZE_MAX,2)==NULL && __wrap_malloc(SIZE_MAX)==NULL);
    char *p=__wrap_malloc(128); assert(p); memset(p,0x5a,128);
    assert(tls_fixer_user_runtime_destroy()<0);
    fail_allocate=1; assert(__wrap_realloc(p,256)==NULL && p[0]==0x5a); fail_allocate=0;
    p=__wrap_realloc(p,256); assert(p && p[127]==0x5a); __wrap_free(p);
    p=__wrap_realloc(NULL,16); assert(p); assert(__wrap_realloc(p,0)==NULL);
    __wrap_free(NULL);
    pthread_t threads[4];
    for (int i=0;i<4;++i) assert(pthread_create(&threads[i],NULL,worker,NULL)==0);
    for (int i=0;i<4;++i) assert(pthread_join(threads[i],NULL)==0);
    char text[64]; __wrap_memcpy(text,"abcdef",7); __wrap_memmove(text+1,text,6);
    text[7] = 0;
    assert(__wrap_memcmp(text,"aabcdef",7)==0);
    assert(__wrap_strcmp("hello","hello")==0 && __wrap_strlen("hello")==5);
    assert(__wrap_strchr(text,'d')==text+4 && __wrap_strstr(text,"bcd")==text+2);
    assert(__wrap_memchr(text,'f',7)==text+6);
    assert(__wrap_snprintf(text,4,"%s","abcdef")==6 && strcmp(text,"abc")==0);
    assert(__wrap_snprintf(NULL,0,"%zu/%llu",(size_t)17,1234567890123ULL)==16);
    assert(__wrap_printf("%s:%u", "quiet", 17)==8);
    assert(__wrap_puts("quiet")>=0 && console_calls==0);
    TlsFixerRuntimeStats stats;
    assert(tls_fixer_user_runtime_stats(&stats)==0 && stats.outstanding==0 && stats.used==0 && stats.peak>0);
    assert(tls_fixer_user_runtime_destroy()==0 && tls_fixer_user_runtime_destroy()==0);
    assert(!block_live && !mutex_live && !heap_live);
    puts("SceLibKernel runtime boundaries, failure cleanup and concurrent allocation: PASS");
}
