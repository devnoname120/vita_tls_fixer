#ifndef TLS_FIXER_CERT_REGISTRY_H
#define TLS_FIXER_CERT_REGISTRY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TLS_FIXER_CERT_WRAPPER_CAPACITY ((size_t)32)
#define TLS_FIXER_NAME_WRAPPER_CAPACITY ((size_t)64)
#define TLS_FIXER_CERT_WRAPPER_MAGIC UINT32_C(0x49544352)
#define TLS_FIXER_NAME_WRAPPER_MAGIC UINT32_C(0x49544E52)
#define TLS_FIXER_WRAPPER_VERSION UINT32_C(1)

typedef void (*TlsFixerCertRegistryLockFn)(void *context);
typedef void (*TlsFixerCertRegistryUnlockFn)(void *context);

typedef struct TlsFixerCertRegistryOps {
    TlsFixerCertRegistryLockFn lock;
    TlsFixerCertRegistryUnlockFn unlock;
    void *context;
} TlsFixerCertRegistryOps;

typedef struct TlsFixerCertWrapperSlot {
    uint32_t magic;
    uint32_t version;
    uint32_t generation;
    const void *payload;
    uint8_t active;
} TlsFixerCertWrapperSlot;

typedef struct TlsFixerNameWrapperSlot {
    uint32_t magic;
    uint32_t version;
    uint32_t generation;
    const void *payload;
    uint8_t active;
} TlsFixerNameWrapperSlot;

typedef struct TlsFixerCertRegistry {
    TlsFixerCertRegistryOps ops;
    TlsFixerCertWrapperSlot certificates[TLS_FIXER_CERT_WRAPPER_CAPACITY];
    TlsFixerNameWrapperSlot names[TLS_FIXER_NAME_WRAPPER_CAPACITY];
    uint32_t next_generation;
    uint8_t initialized;
} TlsFixerCertRegistry;

typedef enum TlsFixerWrapperLookupResult {
    TLS_FIXER_WRAPPER_FOREIGN = 0,
    TLS_FIXER_WRAPPER_ACTIVE = 1,
    TLS_FIXER_WRAPPER_STALE = 2,
    TLS_FIXER_WRAPPER_INVALID_ARGUMENT = -1
} TlsFixerWrapperLookupResult;

typedef enum TlsFixerCertRegistryResult {
    TLS_FIXER_CERT_REGISTRY_OK = 0,
    TLS_FIXER_CERT_REGISTRY_INVALID_ARGUMENT = -1,
    TLS_FIXER_CERT_REGISTRY_NOT_INITIALIZED = -2,
    TLS_FIXER_CERT_REGISTRY_FULL = -3,
    TLS_FIXER_CERT_REGISTRY_STALE = -4,
    TLS_FIXER_CERT_REGISTRY_BUSY = -5
} TlsFixerCertRegistryResult;

int tls_fixer_cert_registry_init(
    TlsFixerCertRegistry *registry,
    const TlsFixerCertRegistryOps *ops);
int tls_fixer_cert_registry_destroy(TlsFixerCertRegistry *registry);
int tls_fixer_cert_registry_begin(
    TlsFixerCertRegistry *registry,
    const void *const *certificates,
    size_t certificate_count,
    void **wrappers,
    uint32_t *generation);
void tls_fixer_cert_registry_end(TlsFixerCertRegistry *registry, uint32_t generation);
TlsFixerWrapperLookupResult tls_fixer_cert_registry_lookup_certificate(
    TlsFixerCertRegistry *registry,
    const void *wrapper,
    const void **certificate,
    uint32_t *generation);
int tls_fixer_cert_registry_create_name(
    TlsFixerCertRegistry *registry,
    const void *certificate_wrapper,
    const void *name,
    void **name_wrapper);
TlsFixerWrapperLookupResult tls_fixer_cert_registry_lookup_name(
    TlsFixerCertRegistry *registry,
    const void *wrapper,
    const void **name,
    uint32_t *generation);
int tls_fixer_cert_registry_release_name(
    TlsFixerCertRegistry *registry,
    const void *wrapper);

#ifdef __cplusplus
}
#endif

#endif
