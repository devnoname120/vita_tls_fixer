#include "user_runtime.h"

#ifdef TLS_FIXER_RUNTIME_HOST_TEST
#include "user_runtime_mock.h"
#else
#include <psp2/kernel/clib.h>
#include <psp2/kernel/sysmem.h>
#include <psp2/kernel/threadmgr/mutex.h>
#endif
#include <limits.h>

/* Reserve the normal small pool at startup. Concurrent TLS connections may
 * need more; allocate those pools only on demand and release empty extras. */
#define INITIAL_BYTES (128u * 1024u)
#define GROWTH_BYTES (64u * 1024u)
#define MAX_BYTES (512u * 1024u)
#define ARENA_COUNT 8u
#define HEADER_MAGIC UINT32_C(0x746C7366)

typedef struct Arena {
    SceUID block;
    SceClibMspace heap;
    uint32_t bytes, used, outstanding;
} Arena;
typedef union AllocationHeader {
    struct { uint32_t magic, arena; size_t requested; } info;
    max_align_t alignment;
} AllocationHeader;

static Arena g_arenas[ARENA_COUNT];
static SceUID g_mutex = -1;
static uint32_t g_outstanding, g_used, g_peak;
static int g_live;

static uint32_t capacity(void) {
    uint32_t result = 0;
    for (unsigned i = 0; i < ARENA_COUNT; ++i) result += g_arenas[i].bytes;
    return result;
}
static void refresh_usage(unsigned index) {
    Arena *arena = &g_arenas[index];
    SceClibMspaceStats stats = {0};
    if (arena->heap) sceClibMspaceMallocStats(arena->heap, &stats);
    g_used = g_used - arena->used + stats.current_in_use;
    arena->used = stats.current_in_use;
    if (g_used > g_peak) g_peak = g_used;
}
static int release_arena(unsigned index) {
    Arena *arena = &g_arenas[index];
    if (!arena->bytes) return 0;
    if (arena->outstanding) return -1;
    if (arena->heap) {
        if (!sceClibMspaceIsHeapEmpty(arena->heap)) return -1;
        sceClibMspaceDestroy(arena->heap); arena->heap = NULL;
        refresh_usage(index);
    }
    int rc = sceKernelFreeMemBlock(arena->block);
    if (rc < 0) return rc; /* Keep its UID for a later cleanup attempt. */
    *arena = (Arena){0};
    return 0;
}
static int create_arena(unsigned index, uint32_t bytes) {
    Arena *arena = &g_arenas[index];
    void *base = NULL;
    SceUID block = sceKernelAllocMemBlock(index ? "tls_fixer HTTP growth" : "tls_fixer HTTP heap",
        SCE_KERNEL_MEMBLOCK_TYPE_USER_RW, bytes, NULL);
    if (block < 0) return block;
    *arena = (Arena){.block = block, .bytes = bytes};
    int rc = sceKernelGetMemBlockBase(block, &base);
    if (rc >= 0 && base) {
        arena->heap = sceClibMspaceCreate(base, bytes);
        if (arena->heap) { refresh_usage(index); return 0; }
    }
    (void)release_arena(index);
    return rc < 0 ? rc : -1;
}
static int heap_lock(void) {
    if (g_mutex < 0 || sceKernelLockMutex(g_mutex, 1, NULL) < 0) return 0;
    if (g_live) return 1;
    (void)sceKernelUnlockMutex(g_mutex, 1); return 0;
}
static void heap_unlock(void) { (void)sceKernelUnlockMutex(g_mutex, 1); }

int tls_fixer_user_runtime_init(void) {
    if (g_mutex >= 0 || capacity()) return -1;
    g_mutex = sceKernelCreateMutex("tls_fixer HTTP heap", 0, 0, NULL);
    if (g_mutex < 0) return g_mutex;
    g_outstanding = g_used = g_peak = 0;
    int rc = create_arena(0, INITIAL_BYTES);
    if (rc < 0) { (void)tls_fixer_user_runtime_destroy(); return rc; }
    g_live = 1;
    return 0;
}
int tls_fixer_user_runtime_stats(TlsFixerRuntimeStats *stats) {
    if (!stats || !heap_lock()) return -1;
    *stats = (TlsFixerRuntimeStats){.capacity = capacity(), .peak = g_peak,
        .used = g_used, .outstanding = g_outstanding};
    heap_unlock(); return 0;
}
int tls_fixer_user_runtime_destroy(void) {
    if (g_mutex < 0) return capacity() ? -1 : 0;
    if (sceKernelLockMutex(g_mutex, 1, NULL) < 0) return -1;
    if (g_outstanding) { heap_unlock(); return -1; }
    g_live = 0;
    int result = 0;
    for (unsigned i = 0; i < ARENA_COUNT; ++i) {
        int rc = release_arena(i); if (rc < 0) result = rc;
    }
    heap_unlock();
    if (result < 0) return result;
    result = sceKernelDeleteMutex(g_mutex);
    if (result < 0) return result;
    g_mutex = -1;
    return 0;
}

static void *allocate_from(unsigned index, size_t size) {
    Arena *arena = &g_arenas[index];
    if (!arena->heap) return NULL;
    AllocationHeader *header = sceClibMspaceMalloc(arena->heap,
        (SceSize)(sizeof(*header) + (size ? size : 1)));
    if (!header) return NULL;
    header->info.magic = HEADER_MAGIC; header->info.arena = index; header->info.requested = size;
    ++arena->outstanding; ++g_outstanding; refresh_usage(index);
    return header + 1;
}
static void *allocate_locked(size_t size) {
    if (size > MAX_BYTES - sizeof(AllocationHeader) - 4096u) return NULL;
    for (unsigned i = 1; i < ARENA_COUNT; ++i)
        if (g_arenas[i].bytes && !g_arenas[i].heap) (void)release_arena(i);
    for (unsigned i = 0; i < ARENA_COUNT; ++i) {
        void *p = allocate_from(i, size); if (p) return p;
    }
    uint32_t bytes = (uint32_t)((size + sizeof(AllocationHeader) + 4096u + 4095u) & ~(size_t)4095u);
    if (bytes < GROWTH_BYTES) bytes = GROWTH_BYTES;
    if (bytes > MAX_BYTES - capacity()) return NULL;
    for (unsigned i = 1; i < ARENA_COUNT; ++i) {
        if (g_arenas[i].bytes) continue;
        if (create_arena(i, bytes) < 0) return NULL;
        void *p = allocate_from(i, size);
        if (!p) (void)release_arena(i);
        return p;
    }
    return NULL;
}
static void free_locked(void *pointer) {
    AllocationHeader *header = (AllocationHeader *)pointer - 1;
    unsigned index = header->info.arena;
    if (header->info.magic != HEADER_MAGIC || index >= ARENA_COUNT || !g_arenas[index].heap) return;
    Arena *arena = &g_arenas[index];
    header->info.magic = 0;
    sceClibMspaceFree(arena->heap, header);
    --arena->outstanding; --g_outstanding; refresh_usage(index);
    if (index && !arena->outstanding) (void)release_arena(index);
}
void *__wrap_malloc(size_t size) {
    if (!heap_lock()) return NULL;
    void *p = allocate_locked(size); heap_unlock(); return p;
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
    free_locked(pointer); heap_unlock();
}
void *__wrap_realloc(void *pointer, size_t size) {
    if (!pointer) return __wrap_malloc(size);
    if (!size) { __wrap_free(pointer); return NULL; }
    if (size > MAX_BYTES - sizeof(AllocationHeader) - 4096u || !heap_lock()) return NULL;
    AllocationHeader *old = (AllocationHeader *)pointer - 1;
    unsigned index = old->info.arena;
    if (old->info.magic != HEADER_MAGIC || index >= ARENA_COUNT || !g_arenas[index].heap) {
        heap_unlock(); return NULL;
    }
    size_t previous = old->info.requested;
    AllocationHeader *next = sceClibMspaceRealloc(g_arenas[index].heap, old,
        (SceSize)(sizeof(*next) + size));
    if (next) {
        next->info.requested = size; refresh_usage(index);
        heap_unlock(); return next + 1;
    }
    void *p = allocate_locked(size);
    if (p) {
        (void)sceClibMemcpy(p, pointer, (SceSize)(previous < size ? previous : size));
        free_locked(pointer);
    }
    heap_unlock(); return p;
}
