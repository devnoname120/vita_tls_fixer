#ifndef TLS_FIXER_REGISTRY_H
#define TLS_FIXER_REGISTRY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef TLS_FIXER_REGISTRY_CAPACITY
#define TLS_FIXER_REGISTRY_CAPACITY 32
#endif

typedef enum TlsFixerSlotState {
    TLS_FIXER_SLOT_FREE = 0,
    TLS_FIXER_SLOT_ACTIVE,
    TLS_FIXER_SLOT_REMOVING
} TlsFixerSlotState;

typedef enum TlsFixerRegistryResult {
    TLS_FIXER_REGISTRY_OK = 0,
    TLS_FIXER_REGISTRY_INVALID_ARGUMENT = -1,
    TLS_FIXER_REGISTRY_NOT_INITIALIZED = -2,
    TLS_FIXER_REGISTRY_DUPLICATE = -3,
    TLS_FIXER_REGISTRY_FULL = -4,
    TLS_FIXER_REGISTRY_NOT_FOUND = -5,
    TLS_FIXER_REGISTRY_STALE_HANDLE = -6,
    TLS_FIXER_REGISTRY_BUSY = -7
} TlsFixerRegistryResult;

typedef void (*TlsFixerRegistryLockFn)(void *context);
typedef void (*TlsFixerRegistryCleanupFn)(void *context, void *payload);

typedef struct TlsFixerRegistryOps {
    TlsFixerRegistryLockFn lock;
    TlsFixerRegistryLockFn unlock;
    TlsFixerRegistryCleanupFn cleanup;
    void *context;
} TlsFixerRegistryOps;

typedef struct TlsFixerRegistrySlot {
    uintptr_t key;
    void *payload;
    uint32_t generation;
    uint32_t references;
    TlsFixerSlotState state;
} TlsFixerRegistrySlot;

typedef struct TlsFixerRegistryHandle {
    size_t index;
    uint32_t generation;
    void *payload;
} TlsFixerRegistryHandle;

typedef struct TlsFixerRegistry {
    TlsFixerRegistrySlot slots[TLS_FIXER_REGISTRY_CAPACITY];
    TlsFixerRegistryOps ops;
    size_t cleanup_inflight;
    uint8_t initialized;
    uint8_t stopping;
} TlsFixerRegistry;

int tls_fixer_registry_init(TlsFixerRegistry *registry, const TlsFixerRegistryOps *ops);
int tls_fixer_registry_insert(TlsFixerRegistry *registry, uintptr_t key, void *payload);
int tls_fixer_registry_replace(TlsFixerRegistry *registry, uintptr_t key, void *payload);
int tls_fixer_registry_acquire(
    TlsFixerRegistry *registry,
    uintptr_t key,
    TlsFixerRegistryHandle *handle);
int tls_fixer_registry_release(TlsFixerRegistry *registry, TlsFixerRegistryHandle *handle);
int tls_fixer_registry_remove(TlsFixerRegistry *registry, uintptr_t key);
int tls_fixer_registry_begin_stop_if_empty(TlsFixerRegistry *registry);
int tls_fixer_registry_destroy(TlsFixerRegistry *registry);
size_t tls_fixer_registry_count(TlsFixerRegistry *registry);

#ifdef __cplusplus
}
#endif

#endif
