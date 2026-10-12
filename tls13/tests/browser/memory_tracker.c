#include "memory_tracker.h"

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define TRACKER_SLOT_COUNT ((size_t)131072)
#define TRACKER_TOMBSTONE ((uintptr_t)1)

typedef struct AllocationSlot {
    uintptr_t key;
    size_t size;
} AllocationSlot;

static pthread_mutex_t tracker_mutex = PTHREAD_MUTEX_INITIALIZER;
static AllocationSlot tracker_slots[TRACKER_SLOT_COUNT];
static TlsFixerMemoryStats tracker_stats;
static int tracker_enabled;

void *__real_malloc(size_t size);
void *__real_calloc(size_t count, size_t size);
void *__real_realloc(void *pointer, size_t size);
void __real_free(void *pointer);

static size_t pointer_hash(uintptr_t key) {
    key ^= key >> 17;
    key *= (uintptr_t)0xed5ad4bbUL;
    key ^= key >> 11;
    return (size_t)key & (TRACKER_SLOT_COUNT - 1);
}

static void insert_locked(void *pointer, size_t size) {
    const uintptr_t key = (uintptr_t)pointer;
    size_t index = pointer_hash(key);
    size_t tombstone = TRACKER_SLOT_COUNT;

    for (size_t attempt = 0; attempt < TRACKER_SLOT_COUNT; ++attempt) {
        AllocationSlot *slot = &tracker_slots[index];
        if (slot->key == key) {
            if (tracker_stats.current_bytes < slot->size ||
                SIZE_MAX - (tracker_stats.current_bytes - slot->size) < size) {
                tracker_stats.overflow = 1;
                return;
            }
            tracker_stats.current_bytes = tracker_stats.current_bytes - slot->size + size;
            slot->size = size;
            if (tracker_stats.current_bytes > tracker_stats.peak_bytes)
                tracker_stats.peak_bytes = tracker_stats.current_bytes;
            return;
        }
        if (slot->key == TRACKER_TOMBSTONE && tombstone == TRACKER_SLOT_COUNT)
            tombstone = index;
        if (slot->key == 0) {
            if (tombstone != TRACKER_SLOT_COUNT) slot = &tracker_slots[tombstone];
            if (SIZE_MAX - tracker_stats.current_bytes < size) {
                tracker_stats.overflow = 1;
                return;
            }
            slot->key = key;
            slot->size = size;
            tracker_stats.current_bytes += size;
            ++tracker_stats.live_allocations;
            ++tracker_stats.total_allocations;
            if (tracker_stats.current_bytes > tracker_stats.peak_bytes)
                tracker_stats.peak_bytes = tracker_stats.current_bytes;
            if (tracker_stats.live_allocations > tracker_stats.peak_allocations)
                tracker_stats.peak_allocations = tracker_stats.live_allocations;
            return;
        }
        index = (index + 1) & (TRACKER_SLOT_COUNT - 1);
    }
    tracker_stats.overflow = 1;
}

static int remove_locked(void *pointer, size_t *size) {
    const uintptr_t key = (uintptr_t)pointer;
    size_t index = pointer_hash(key);

    for (size_t attempt = 0; attempt < TRACKER_SLOT_COUNT; ++attempt) {
        AllocationSlot *slot = &tracker_slots[index];
        if (slot->key == 0) return 0;
        if (slot->key == key) {
            *size = slot->size;
            slot->key = TRACKER_TOMBSTONE;
            slot->size = 0;
            if (tracker_stats.current_bytes < *size || tracker_stats.live_allocations == 0) {
                tracker_stats.overflow = 1;
                return 0;
            }
            tracker_stats.current_bytes -= *size;
            --tracker_stats.live_allocations;
            return 1;
        }
        index = (index + 1) & (TRACKER_SLOT_COUNT - 1);
    }
    tracker_stats.overflow = 1;
    return 0;
}

void tls_fixer_memory_tracker_reset(void) {
    const int saved_errno = errno;
    (void)pthread_mutex_lock(&tracker_mutex);
    memset(tracker_slots, 0, sizeof(tracker_slots));
    memset(&tracker_stats, 0, sizeof(tracker_stats));
    tracker_enabled = 1;
    (void)pthread_mutex_unlock(&tracker_mutex);
    errno = saved_errno;
}

TlsFixerMemoryStats tls_fixer_memory_tracker_snapshot(void) {
    TlsFixerMemoryStats result;
    const int saved_errno = errno;
    (void)pthread_mutex_lock(&tracker_mutex);
    result = tracker_stats;
    (void)pthread_mutex_unlock(&tracker_mutex);
    errno = saved_errno;
    return result;
}

void *__wrap_malloc(size_t size) {
    void *result = __real_malloc(size);
    const int saved_errno = errno;
    if (result != NULL && tracker_enabled) {
        (void)pthread_mutex_lock(&tracker_mutex);
        insert_locked(result, size);
        (void)pthread_mutex_unlock(&tracker_mutex);
    }
    errno = saved_errno;
    return result;
}

void *__wrap_calloc(size_t count, size_t size) {
    void *result = __real_calloc(count, size);
    const int saved_errno = errno;
    size_t requested = 0;
    if (count != 0 && size > SIZE_MAX / count) requested = SIZE_MAX;
    else requested = count * size;
    if (result != NULL && tracker_enabled) {
        (void)pthread_mutex_lock(&tracker_mutex);
        insert_locked(result, requested);
        (void)pthread_mutex_unlock(&tracker_mutex);
    }
    errno = saved_errno;
    return result;
}

void *__wrap_realloc(void *pointer, size_t size) {
    void *result = __real_realloc(pointer, size);
    const int saved_errno = errno;
    if (tracker_enabled) {
        (void)pthread_mutex_lock(&tracker_mutex);
        if (pointer != NULL && (result != NULL || size == 0)) {
            size_t old_size = 0;
            (void)remove_locked(pointer, &old_size);
        }
        if (result != NULL) insert_locked(result, size);
        (void)pthread_mutex_unlock(&tracker_mutex);
    }
    errno = saved_errno;
    return result;
}

void __wrap_free(void *pointer) {
    const int saved_errno = errno;
    if (pointer != NULL && tracker_enabled) {
        (void)pthread_mutex_lock(&tracker_mutex);
        size_t size = 0;
        (void)remove_locked(pointer, &size);
        (void)pthread_mutex_unlock(&tracker_mutex);
    }
    __real_free(pointer);
    errno = saved_errno;
}
