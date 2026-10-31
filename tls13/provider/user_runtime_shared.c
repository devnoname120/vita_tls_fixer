#include "user_runtime.h"
#include "shared_ssl_pool.h"
#ifdef TLS_FIXER_RUNTIME_HOST_TEST
#include "user_runtime_mock.h"
#else
#include <psp2/kernel/clib.h>
#include <psp2/kernel/threadmgr/mutex.h>
#endif
#include <limits.h>

static TlsFixerSslPoolRead g_read;
static void *g_context;
static TlsFixerSslPoolView g_pool;
static SceUID g_mutex = -1;
static uint32_t g_outstanding;

int tls_fixer_user_runtime_bind_ssl(TlsFixerSslPoolRead read, void *context) {
    if (g_mutex >= 0 || g_outstanding || !read) return -1;
    g_read = read; g_context = context;
    return 0;
}
int tls_fixer_user_runtime_pool_alive(void) {
    TlsFixerSslPoolView current = {0};
    return g_mutex >= 0 && g_read && !g_read(g_context, &current) &&
        current.heap == g_pool.heap && current.block == g_pool.block;
}
static int heap_lock(void) {
    if (g_mutex < 0 || sceKernelLockMutex(g_mutex, 1, NULL) < 0) return 0;
    if (tls_fixer_user_runtime_pool_alive()) return 1;
    (void)sceKernelUnlockMutex(g_mutex, 1); return 0;
}
static void heap_unlock(void) { (void)sceKernelUnlockMutex(g_mutex, 1); }
int tls_fixer_user_runtime_init(void) {
    if (g_mutex >= 0 || !g_read) return -1;
    TlsFixerSslPoolView pool = {0};
    int rc = g_read(g_context, &pool);
    if (rc < 0 || !pool.heap || pool.block < 0) return rc < 0 ? rc : -1;
    g_mutex = sceKernelCreateMutex("tls_fixer SSL allocations", 0, 0, NULL);
    if (g_mutex < 0) return g_mutex;
    g_pool = pool; g_outstanding = 0;
    return 0;
}
int tls_fixer_user_runtime_stats(TlsFixerRuntimeStats *stats) {
    if (!stats || !heap_lock()) return -1;
    SceClibMspaceStats native = {0};
    sceClibMspaceMallocStats(g_pool.heap, &native);
    /* The reported pool usage includes Sony's allocations, as it should. */
    *stats = (TlsFixerRuntimeStats){native.capacity, native.peak_in_use,
        native.current_in_use, g_outstanding};
    heap_unlock(); return 0;
}
int tls_fixer_user_runtime_destroy(void) {
    if (g_mutex < 0) return 0;
    if (sceKernelLockMutex(g_mutex, 1, NULL) < 0) return -1;
    if (g_outstanding) { heap_unlock(); return -1; }
    heap_unlock();
    int rc = sceKernelDeleteMutex(g_mutex);
    if (rc < 0) return rc;
    g_mutex = -1;
    g_pool = (TlsFixerSslPoolView){0};
    /* Sony retains its native objects and owns sceSslTerm and the reservation. */
    return 0;
}
void *__wrap_malloc(size_t size) {
    if (size > UINT_MAX || !heap_lock()) return NULL;
    void *p = g_outstanding == UINT32_MAX ? NULL :
        sceClibMspaceMalloc(g_pool.heap, size ? (SceSize)size : 1u);
    if (p) ++g_outstanding;
    heap_unlock(); return p;
}
void *__wrap_calloc(size_t count, size_t size) {
    if (size && count > SIZE_MAX / size) return NULL;
    size_t bytes = count * size;
    void *p = __wrap_malloc(bytes);
    if (p && bytes) (void)sceClibMemset(p, 0, (SceSize)bytes);
    return p;
}
void __wrap_free(void *pointer) {
    if (!pointer || !heap_lock()) return;
    sceClibMspaceFree(g_pool.heap, pointer);
    --g_outstanding;
    heap_unlock();
}
void *__wrap_realloc(void *pointer, size_t size) {
    if (!pointer) return __wrap_malloc(size);
    if (!size) { __wrap_free(pointer); return NULL; }
    if (size > UINT_MAX || !heap_lock()) return NULL;
    void *p = sceClibMspaceRealloc(g_pool.heap, pointer, (SceSize)size);
    heap_unlock(); return p;
}
