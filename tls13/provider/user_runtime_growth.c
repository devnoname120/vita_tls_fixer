#include "user_runtime.h"

#ifdef TLS_FIXER_RUNTIME_HOST_TEST
#include "user_runtime_mock.h"
#else
#include <psp2/kernel/clib.h>
#include <psp2/kernel/sysmem.h>
#include <psp2/kernel/threadmgr/mutex.h>
#endif
#include <limits.h>

/* Reserve a small initial pool. Further pools follow actual demand, subject to
 * kernel allocation failure rather than a separate connection/heap ceiling. */
#define INITIAL_BYTES (128u * 1024u)
#define GROWTH_BYTES (64u * 1024u)
#define HEADER_MAGIC UINT32_C(0x746C7366)

typedef struct Arena {
    struct Arena *next;
    SceUID block;
    SceClibMspace heap;
    uint32_t bytes, used, outstanding;
} Arena;
typedef union ArenaHeader { Arena arena; max_align_t alignment; } ArenaHeader;
#define ARENA_PREFIX_BYTES ((sizeof(ArenaHeader) + 15u) & ~(size_t)15u)
typedef union AllocationHeader {
    struct { uint32_t magic; Arena *owner; size_t requested; } info;
    max_align_t alignment;
} AllocationHeader;

static Arena g_initial;
static SceUID g_mutex = -1, g_pending_block = -1;
static uint32_t g_capacity, g_outstanding, g_used, g_peak;
static int g_live;

static void refresh_usage(Arena *arena) {
    SceClibMspaceStats stats = {0};
    if (arena->heap) sceClibMspaceMallocStats(arena->heap, &stats);
    g_used = g_used - arena->used + stats.current_in_use;
    arena->used = stats.current_in_use;
    if (g_used > g_peak) g_peak = g_used;
}
/* A failed kernel release keeps the descriptor alive for a later retry. */
static int release_arena(Arena **link) {
    Arena *arena = *link;
    if (!arena || !arena->bytes) return 0;
    if (arena->outstanding) return -1;
    if (arena->heap) {
        if (!sceClibMspaceIsHeapEmpty(arena->heap)) return -1;
        sceClibMspaceDestroy(arena->heap); arena->heap = NULL;
        refresh_usage(arena);
    }
    Arena *next = arena->next;
    uint32_t bytes = arena->bytes;
    int initial = arena == &g_initial;
    int rc = sceKernelFreeMemBlock(arena->block);
    if (rc < 0) return rc;
    g_capacity -= bytes;
    if (initial) g_initial = (Arena){0};
    else *link = next; /* The extra descriptor was inside the freed block. */
    return 0;
}
static int retry_pending(void) {
    if (g_pending_block < 0) return 0;
    int rc = sceKernelFreeMemBlock(g_pending_block);
    if (rc >= 0) g_pending_block = -1;
    return rc;
}
static int create_arena(uint32_t bytes, int initial, Arena **out) {
    void *base = NULL;
    if (retry_pending() < 0 || bytes > UINT32_MAX - g_capacity) return -1;
    SceUID block = sceKernelAllocMemBlock(initial ? "tls_fixer HTTP heap" : "tls_fixer HTTP growth",
        SCE_KERNEL_MEMBLOCK_TYPE_USER_RW, bytes, NULL);
    if (block < 0) return block;
    int rc = sceKernelGetMemBlockBase(block, &base);
    if (rc < 0 || !base) {
        g_pending_block = block;
        (void)retry_pending();
        return rc < 0 ? rc : -1;
    }
    Arena *arena = initial ? &g_initial : &((ArenaHeader *)base)->arena;
    size_t prefix = initial ? 0 : ARENA_PREFIX_BYTES;
    *arena = (Arena){.block = block, .bytes = bytes};
    arena->heap = sceClibMspaceCreate((unsigned char *)base + prefix, bytes - (SceSize)prefix);
    if (initial) {
        g_capacity += bytes;
    } else {
        arena->next = g_initial.next;
        g_initial.next = arena;
        g_capacity += bytes;
    }
    if (!arena->heap) {
        if (initial) { Arena *first = &g_initial; (void)release_arena(&first); }
        else (void)release_arena(&g_initial.next);
        return -1;
    }
    refresh_usage(arena);
    *out = arena;
    return 0;
}
static int heap_lock(void) {
    if (g_mutex < 0 || sceKernelLockMutex(g_mutex, 1, NULL) < 0) return 0;
    if (g_live) return 1;
    (void)sceKernelUnlockMutex(g_mutex, 1); return 0;
}
static void heap_unlock(void) { (void)sceKernelUnlockMutex(g_mutex, 1); }

int tls_fixer_user_runtime_init(void) {
    if (g_mutex >= 0 || g_capacity || g_pending_block >= 0) return -1;
    g_mutex = sceKernelCreateMutex("tls_fixer HTTP heap", 0, 0, NULL);
    if (g_mutex < 0) return g_mutex;
    g_outstanding = g_used = g_peak = 0;
    Arena *arena = NULL;
    int rc = create_arena(INITIAL_BYTES, 1, &arena);
    if (rc < 0) { (void)tls_fixer_user_runtime_destroy(); return rc; }
    g_live = 1;
    return 0;
}
int tls_fixer_user_runtime_stats(TlsFixerRuntimeStats *stats) {
    if (!stats || !heap_lock()) return -1;
    *stats = (TlsFixerRuntimeStats){.capacity = g_capacity, .peak = g_peak,
        .used = g_used, .outstanding = g_outstanding};
    heap_unlock(); return 0;
}
int tls_fixer_user_runtime_destroy(void) {
    if (g_mutex < 0) return (g_capacity || g_pending_block >= 0) ? -1 : 0;
    if (sceKernelLockMutex(g_mutex, 1, NULL) < 0) return -1;
    if (g_outstanding) { heap_unlock(); return -1; }
    g_live = 0;
    int result = retry_pending();
    Arena **link = &g_initial.next;
    while (*link) {
        int rc = release_arena(link);
        if (rc < 0) { result = rc; link = &(*link)->next; }
    }
    if (!g_initial.next) {
        Arena *first = &g_initial;
        int rc = release_arena(&first); if (rc < 0) result = rc;
    }
    heap_unlock();
    if (result < 0) return result;
    result = sceKernelDeleteMutex(g_mutex);
    if (result < 0) return result;
    g_mutex = -1;
    return 0;
}

static void *allocate_from(Arena *arena, size_t size) {
    if (!arena->heap) return NULL;
    AllocationHeader *header = sceClibMspaceMalloc(arena->heap,
        (SceSize)(sizeof(*header) + (size ? size : 1)));
    if (!header) return NULL;
    header->info.magic = HEADER_MAGIC; header->info.owner = arena; header->info.requested = size;
    ++arena->outstanding; ++g_outstanding; refresh_usage(arena);
    return header + 1;
}
static int valid_size(size_t size) {
    return size <= UINT32_MAX - sizeof(AllocationHeader) - ARENA_PREFIX_BYTES - 8192u;
}
static void *allocate_locked(size_t size) {
    if (!valid_size(size) || g_outstanding == UINT32_MAX) return NULL;
    Arena **link = &g_initial.next;
    while (*link) {
        if (!(*link)->heap && release_arena(link) >= 0) continue;
        link = &(*link)->next;
    }
    for (Arena *arena = &g_initial; arena; arena = arena->next) {
        void *p = allocate_from(arena, size); if (p) return p;
    }
    uint32_t bytes = (uint32_t)((size + sizeof(AllocationHeader) + ARENA_PREFIX_BYTES + 4096u + 4095u) & ~(size_t)4095u);
    if (bytes < GROWTH_BYTES) bytes = GROWTH_BYTES;
    Arena *arena = NULL;
    if (create_arena(bytes, 0, &arena) < 0) return NULL;
    void *p = allocate_from(arena, size);
    if (!p) (void)release_arena(&g_initial.next);
    return p;
}
static void free_locked(void *pointer) {
    AllocationHeader *header = (AllocationHeader *)pointer - 1;
    if (header->info.magic != HEADER_MAGIC) return;
    Arena *arena = header->info.owner;
    header->info.magic = 0;
    sceClibMspaceFree(arena->heap, header);
    --arena->outstanding; --g_outstanding; refresh_usage(arena);
    if (arena != &g_initial && !arena->outstanding) {
        Arena **link = &g_initial.next;
        while (*link && *link != arena) link = &(*link)->next;
        if (*link) (void)release_arena(link);
    }
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
    if (!valid_size(size) || !heap_lock()) return NULL;
    AllocationHeader *old = (AllocationHeader *)pointer - 1;
    if (old->info.magic != HEADER_MAGIC) { heap_unlock(); return NULL; }
    Arena *arena = old->info.owner;
    size_t previous = old->info.requested;
    AllocationHeader *next = sceClibMspaceRealloc(arena->heap, old,
        (SceSize)(sizeof(*next) + size));
    if (next) {
        next->info.requested = size; refresh_usage(arena);
        heap_unlock(); return next + 1;
    }
    void *p = allocate_locked(size);
    if (p) {
        (void)sceClibMemcpy(p, pointer, (SceSize)(previous < size ? previous : size));
        free_locked(pointer);
    }
    heap_unlock(); return p;
}
