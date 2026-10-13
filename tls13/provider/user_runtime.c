#include "user_runtime.h"

#ifdef TLS_FIXER_RUNTIME_HOST_TEST
#include "user_runtime_mock.h"
#else
#include <psp2/kernel/clib.h>
#include <psp2/kernel/sysmem.h>
#include <psp2/kernel/threadmgr/mutex.h>
#endif

#include <limits.h>
#include <stdint.h>

#define TLS_FIXER_HTTP_HEAP_BYTES (2u * 1024u * 1024u)

static SceUID g_heap_block = -1, g_heap_mutex = -1;
static SceClibMspace g_heap;
static uint32_t g_outstanding;

/* Initialize before publishing hooks; release only after all users have gone. */
int tls_fixer_user_runtime_init(void) {
    void *base = NULL;
    if (g_heap != NULL || g_heap_block >= 0 || g_heap_mutex >= 0) return -1;
    g_heap_block = sceKernelAllocMemBlock("tls_fixer HTTP heap",
        SCE_KERNEL_MEMBLOCK_TYPE_USER_RW, TLS_FIXER_HTTP_HEAP_BYTES, NULL);
    if (g_heap_block < 0) return g_heap_block;
    int result = sceKernelGetMemBlockBase(g_heap_block, &base);
    if (result < 0 || base == NULL) goto failed;
    g_heap_mutex = sceKernelCreateMutex("tls_fixer HTTP heap", 0, 0, NULL);
    if (g_heap_mutex < 0) { result = g_heap_mutex; goto failed; }
    g_heap = sceClibMspaceCreate(base, TLS_FIXER_HTTP_HEAP_BYTES);
    if (g_heap == NULL) { result = -1; goto failed; }
    g_outstanding = 0;
    return 0;
failed:
    if (g_heap_mutex >= 0) (void)sceKernelDeleteMutex(g_heap_mutex);
    g_heap_mutex = -1;
    (void)sceKernelFreeMemBlock(g_heap_block);
    g_heap_block = -1;
    return result < 0 ? result : -1;
}

static int heap_lock(void) {
    if (g_heap_mutex < 0 || sceKernelLockMutex(g_heap_mutex, 1, NULL) < 0) return 0;
    if (g_heap != NULL) return 1;
    (void)sceKernelUnlockMutex(g_heap_mutex, 1);
    return 0;
}

static void heap_unlock(void) { (void)sceKernelUnlockMutex(g_heap_mutex, 1); }

int tls_fixer_user_runtime_stats(TlsFixerRuntimeStats *stats) {
    if (stats == NULL || !heap_lock()) return -1;
    SceClibMspaceStats native = {0};
    sceClibMspaceMallocStats(g_heap, &native);
    stats->capacity = native.capacity;
    stats->peak = native.peak_in_use;
    stats->used = native.current_in_use;
    stats->outstanding = g_outstanding;
    heap_unlock();
    return 0;
}

int tls_fixer_user_runtime_destroy(void) {
    if (g_heap != NULL) {
        if (!heap_lock()) return -1;
        if (g_outstanding != 0 || !sceClibMspaceIsHeapEmpty(g_heap)) {
            heap_unlock();
            return -1;
        }
        sceClibMspaceDestroy(g_heap);
        g_heap = NULL;
        heap_unlock();
    }
    if (g_heap_mutex >= 0) {
        int result = sceKernelDeleteMutex(g_heap_mutex);
        if (result < 0) return result;
        g_heap_mutex = -1;
    }
    if (g_heap_block >= 0) {
        int result = sceKernelFreeMemBlock(g_heap_block);
        if (result < 0) return result;
        g_heap_block = -1;
    }
    return 0;
}

void *__wrap_malloc(size_t size) {
    if (size > UINT_MAX || !heap_lock()) return NULL;
    void *result = sceClibMspaceMalloc(g_heap, size ? (SceSize)size : 1u);
    if (result != NULL) ++g_outstanding;
    heap_unlock();
    return result;
}

void *__wrap_calloc(size_t count, size_t size) {
    if (size != 0 && count > SIZE_MAX / size) return NULL;
    size_t bytes = count * size;
    void *result = __wrap_malloc(bytes);
    if (result != NULL && bytes != 0) (void)sceClibMemset(result, 0, (SceSize)bytes);
    return result;
}

void __wrap_free(void *pointer) {
    if (pointer == NULL || !heap_lock()) return;
    sceClibMspaceFree(g_heap, pointer);
    if (g_outstanding > 0) --g_outstanding;
    heap_unlock();
}

void *__wrap_realloc(void *pointer, size_t size) {
    if (pointer == NULL) return __wrap_malloc(size);
    if (size == 0) { __wrap_free(pointer); return NULL; }
    if (size > UINT_MAX || !heap_lock()) return NULL;
    void *result = sceClibMspaceRealloc(g_heap, pointer, (SceSize)size);
    heap_unlock();
    return result;
}

void *__wrap_memchr(const void *source, int value, size_t size) {
    return sceClibMemchr(source, value, (SceSize)size);
}
int __wrap_memcmp(const void *left, const void *right, size_t size) {
    return sceClibMemcmp(left, right, (SceSize)size);
}
void *__wrap_memcpy(void *destination, const void *source, size_t size) {
    return sceClibMemcpy(destination, source, (SceSize)size);
}
void *__wrap_memmove(void *destination, const void *source, size_t size) {
    return sceClibMemmove(destination, source, (SceSize)size);
}
void *__wrap_memset(void *destination, int value, size_t size) {
    return sceClibMemset(destination, value, (SceSize)size);
}
char *__wrap_strchr(const char *source, int value) { return sceClibStrchr(source, value); }
int __wrap_strcmp(const char *left, const char *right) { return sceClibStrcmp(left, right); }
size_t __wrap_strlen(const char *source) { return sceClibStrnlen(source, UINT_MAX); }
char *__wrap_strstr(const char *source, const char *needle) { return sceClibStrstr(source, needle); }
int __wrap_vsnprintf(char *output, size_t capacity, const char *format, va_list args) {
    if (capacity > UINT_MAX) return -1;
    int result = sceClibVsnprintf(output, (SceSize)capacity, format, args);
    /* Sony counts correctly but need not terminate a full buffer; C99 requires it. */
    if (output != NULL && capacity != 0) output[capacity - 1] = '\0';
    return result;
}
int __wrap_snprintf(char *output, size_t capacity, const char *format, ...) {
    va_list args;
    va_start(args, format);
    int result = __wrap_vsnprintf(output, capacity, format, args);
    va_end(args);
    return result;
}
int __wrap_printf(const char *format, ...) {
    va_list args;
    va_start(args, format);
    int result = sceClibVprintf(format, args);
    va_end(args);
    return result;
}
int __wrap_puts(const char *source) { return sceClibPrintf("%s\n", source); }
