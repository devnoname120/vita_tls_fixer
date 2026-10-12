#include "tls_fixer/cert_registry.h"

#include <stdint.h>
#include <string.h>

#define TLS_FIXER_WRAPPER_TAG_MASK UINT32_C(0x03)
#define TLS_FIXER_CERT_HANDLE_TAG UINT32_C(0x01)
#define TLS_FIXER_NAME_HANDLE_TAG UINT32_C(0x03)
#define TLS_FIXER_WRAPPER_INDEX_SHIFT 2
#define TLS_FIXER_WRAPPER_INDEX_MASK UINT32_C(0x3F)
#define TLS_FIXER_WRAPPER_GENERATION_SHIFT 8
#define TLS_FIXER_WRAPPER_GENERATION_MAX UINT32_C(0x00FFFFFF)

_Static_assert(TLS_FIXER_CERT_WRAPPER_CAPACITY <= 64, "certificate handle index overflow");
_Static_assert(TLS_FIXER_NAME_WRAPPER_CAPACITY <= 64, "name handle index overflow");

static void registry_lock(TlsFixerCertRegistry *registry) {
    if (registry->ops.lock != NULL) {
        registry->ops.lock(registry->ops.context);
    }
}

static void registry_unlock(TlsFixerCertRegistry *registry) {
    if (registry->ops.unlock != NULL) {
        registry->ops.unlock(registry->ops.context);
    }
}

static void *encode_wrapper_handle(uint32_t tag, size_t index, uint32_t generation) {
    const uint32_t value =
        (generation << TLS_FIXER_WRAPPER_GENERATION_SHIFT) |
        ((uint32_t)index << TLS_FIXER_WRAPPER_INDEX_SHIFT) |
        tag;

    return (void *)(uintptr_t)value;
}

static int decode_wrapper_handle(
    const void *wrapper,
    uint32_t expected_tag,
    size_t capacity,
    size_t *index,
    uint32_t *generation) {
    const uintptr_t address = (uintptr_t)wrapper;
    uint32_t value;
    size_t decoded_index;
    uint32_t decoded_generation;

    if (address > UINT32_MAX) {
        return 0;
    }
    value = (uint32_t)address;
    if ((value & TLS_FIXER_WRAPPER_TAG_MASK) != expected_tag) {
        return 0;
    }

    decoded_index =
        (size_t)((value >> TLS_FIXER_WRAPPER_INDEX_SHIFT) & TLS_FIXER_WRAPPER_INDEX_MASK);
    decoded_generation = value >> TLS_FIXER_WRAPPER_GENERATION_SHIFT;
    if (decoded_index >= capacity || decoded_generation == 0) {
        return -1;
    }

    *index = decoded_index;
    *generation = decoded_generation;
    return 1;
}

static uint32_t next_generation(TlsFixerCertRegistry *registry) {
    if (registry->next_generation >= TLS_FIXER_WRAPPER_GENERATION_MAX) {
        return 0;
    }
    ++registry->next_generation;
    return registry->next_generation;
}

int tls_fixer_cert_registry_init(
    TlsFixerCertRegistry *registry,
    const TlsFixerCertRegistryOps *ops) {
    if (registry == NULL || ops == NULL ||
        (ops->lock == NULL) != (ops->unlock == NULL)) {
        return TLS_FIXER_CERT_REGISTRY_INVALID_ARGUMENT;
    }

    memset(registry, 0, sizeof(*registry));
    registry->ops = *ops;
    registry->initialized = 1;
    return TLS_FIXER_CERT_REGISTRY_OK;
}

int tls_fixer_cert_registry_destroy(TlsFixerCertRegistry *registry) {
    size_t index;

    if (registry == NULL) {
        return TLS_FIXER_CERT_REGISTRY_INVALID_ARGUMENT;
    }
    if (!registry->initialized) {
        return TLS_FIXER_CERT_REGISTRY_NOT_INITIALIZED;
    }

    registry_lock(registry);
    for (index = 0; index < TLS_FIXER_CERT_WRAPPER_CAPACITY; ++index) {
        if (registry->certificates[index].active) {
            registry_unlock(registry);
            return TLS_FIXER_CERT_REGISTRY_BUSY;
        }
    }
    for (index = 0; index < TLS_FIXER_NAME_WRAPPER_CAPACITY; ++index) {
        if (registry->names[index].active) {
            registry_unlock(registry);
            return TLS_FIXER_CERT_REGISTRY_BUSY;
        }
    }
    registry_unlock(registry);
    memset(registry, 0, sizeof(*registry));
    return TLS_FIXER_CERT_REGISTRY_OK;
}

int tls_fixer_cert_registry_begin(
    TlsFixerCertRegistry *registry,
    const void *const *certificates,
    size_t certificate_count,
    void **wrappers,
    uint32_t *generation) {
    size_t free_count = 0;
    size_t certificate_index = 0;
    size_t slot_index;
    uint32_t current_generation;

    if (registry == NULL || certificates == NULL || wrappers == NULL ||
        generation == NULL || certificate_count == 0 ||
        certificate_count > TLS_FIXER_CERT_WRAPPER_CAPACITY) {
        return TLS_FIXER_CERT_REGISTRY_INVALID_ARGUMENT;
    }
    if (!registry->initialized) {
        return TLS_FIXER_CERT_REGISTRY_NOT_INITIALIZED;
    }
    for (certificate_index = 0; certificate_index < certificate_count; ++certificate_index) {
        if (certificates[certificate_index] == NULL) {
            return TLS_FIXER_CERT_REGISTRY_INVALID_ARGUMENT;
        }
    }

    registry_lock(registry);
    for (slot_index = 0; slot_index < TLS_FIXER_CERT_WRAPPER_CAPACITY; ++slot_index) {
        if (!registry->certificates[slot_index].active) {
            ++free_count;
        }
    }
    if (free_count < certificate_count) {
        registry_unlock(registry);
        return TLS_FIXER_CERT_REGISTRY_FULL;
    }

    current_generation = next_generation(registry);
    if (current_generation == 0) {
        registry_unlock(registry);
        return TLS_FIXER_CERT_REGISTRY_FULL;
    }
    certificate_index = 0;
    for (slot_index = 0;
         slot_index < TLS_FIXER_CERT_WRAPPER_CAPACITY && certificate_index < certificate_count;
         ++slot_index) {
        TlsFixerCertWrapperSlot *slot = &registry->certificates[slot_index];

        if (slot->active) {
            continue;
        }
        slot->magic = TLS_FIXER_CERT_WRAPPER_MAGIC;
        slot->version = TLS_FIXER_WRAPPER_VERSION;
        slot->generation = current_generation;
        slot->payload = certificates[certificate_index];
        slot->active = 1;
        wrappers[certificate_index] = encode_wrapper_handle(
            TLS_FIXER_CERT_HANDLE_TAG,
            slot_index,
            current_generation);
        ++certificate_index;
    }
    *generation = current_generation;
    registry_unlock(registry);
    return TLS_FIXER_CERT_REGISTRY_OK;
}

void tls_fixer_cert_registry_end(TlsFixerCertRegistry *registry, uint32_t generation) {
    size_t index;

    if (registry == NULL || !registry->initialized || generation == 0) {
        return;
    }

    registry_lock(registry);
    for (index = 0; index < TLS_FIXER_CERT_WRAPPER_CAPACITY; ++index) {
        TlsFixerCertWrapperSlot *slot = &registry->certificates[index];
        if (slot->active && slot->generation == generation) {
            slot->active = 0;
            slot->payload = NULL;
        }
    }
    registry_unlock(registry);
}

TlsFixerWrapperLookupResult tls_fixer_cert_registry_lookup_certificate(
    TlsFixerCertRegistry *registry,
    const void *wrapper,
    const void **certificate,
    uint32_t *generation) {
    TlsFixerCertWrapperSlot *slot;
    TlsFixerWrapperLookupResult result;
    size_t index = 0;
    uint32_t decoded_generation = 0;
    int decoded;

    if (registry == NULL || wrapper == NULL || certificate == NULL) {
        return TLS_FIXER_WRAPPER_INVALID_ARGUMENT;
    }
    if (!registry->initialized) {
        return TLS_FIXER_WRAPPER_FOREIGN;
    }

    registry_lock(registry);
    decoded = decode_wrapper_handle(
        wrapper,
        TLS_FIXER_CERT_HANDLE_TAG,
        TLS_FIXER_CERT_WRAPPER_CAPACITY,
        &index,
        &decoded_generation);
    if (decoded == 0) {
        result = TLS_FIXER_WRAPPER_FOREIGN;
    } else if (decoded < 0) {
        result = TLS_FIXER_WRAPPER_STALE;
    } else {
        slot = &registry->certificates[index];
        if (!slot->active || slot->magic != TLS_FIXER_CERT_WRAPPER_MAGIC ||
            slot->version != TLS_FIXER_WRAPPER_VERSION ||
            slot->generation != decoded_generation) {
            result = TLS_FIXER_WRAPPER_STALE;
        } else {
            *certificate = slot->payload;
            if (generation != NULL) {
                *generation = slot->generation;
            }
            result = TLS_FIXER_WRAPPER_ACTIVE;
        }
    }
    registry_unlock(registry);
    return result;
}

int tls_fixer_cert_registry_create_name(
    TlsFixerCertRegistry *registry,
    const void *certificate_wrapper,
    const void *name,
    void **name_wrapper) {
    TlsFixerCertWrapperSlot *certificate_slot;
    size_t index;
    size_t certificate_index = 0;
    uint32_t certificate_generation = 0;
    uint32_t name_generation;
    int decoded;

    if (registry == NULL || certificate_wrapper == NULL || name == NULL ||
        name_wrapper == NULL) {
        return TLS_FIXER_CERT_REGISTRY_INVALID_ARGUMENT;
    }
    if (!registry->initialized) {
        return TLS_FIXER_CERT_REGISTRY_NOT_INITIALIZED;
    }

    registry_lock(registry);
    decoded = decode_wrapper_handle(
        certificate_wrapper,
        TLS_FIXER_CERT_HANDLE_TAG,
        TLS_FIXER_CERT_WRAPPER_CAPACITY,
        &certificate_index,
        &certificate_generation);
    if (decoded <= 0) {
        registry_unlock(registry);
        return TLS_FIXER_CERT_REGISTRY_STALE;
    }
    certificate_slot = &registry->certificates[certificate_index];
    if (!certificate_slot->active ||
        certificate_slot->magic != TLS_FIXER_CERT_WRAPPER_MAGIC ||
        certificate_slot->version != TLS_FIXER_WRAPPER_VERSION ||
        certificate_slot->generation != certificate_generation) {
        registry_unlock(registry);
        return TLS_FIXER_CERT_REGISTRY_STALE;
    }

    for (index = 0; index < TLS_FIXER_NAME_WRAPPER_CAPACITY; ++index) {
        TlsFixerNameWrapperSlot *slot = &registry->names[index];
        if (slot->active) {
            continue;
        }
        name_generation = next_generation(registry);
        if (name_generation == 0) {
            registry_unlock(registry);
            return TLS_FIXER_CERT_REGISTRY_FULL;
        }
        slot->magic = TLS_FIXER_NAME_WRAPPER_MAGIC;
        slot->version = TLS_FIXER_WRAPPER_VERSION;
        slot->generation = name_generation;
        slot->payload = name;
        slot->active = 1;
        *name_wrapper = encode_wrapper_handle(
            TLS_FIXER_NAME_HANDLE_TAG,
            index,
            name_generation);
        registry_unlock(registry);
        return TLS_FIXER_CERT_REGISTRY_OK;
    }

    registry_unlock(registry);
    return TLS_FIXER_CERT_REGISTRY_FULL;
}

TlsFixerWrapperLookupResult tls_fixer_cert_registry_lookup_name(
    TlsFixerCertRegistry *registry,
    const void *wrapper,
    const void **name,
    uint32_t *generation) {
    TlsFixerNameWrapperSlot *slot;
    TlsFixerWrapperLookupResult result;
    size_t index = 0;
    uint32_t decoded_generation = 0;
    int decoded;

    if (registry == NULL || wrapper == NULL || name == NULL) {
        return TLS_FIXER_WRAPPER_INVALID_ARGUMENT;
    }
    if (!registry->initialized) {
        return TLS_FIXER_WRAPPER_FOREIGN;
    }

    registry_lock(registry);
    decoded = decode_wrapper_handle(
        wrapper,
        TLS_FIXER_NAME_HANDLE_TAG,
        TLS_FIXER_NAME_WRAPPER_CAPACITY,
        &index,
        &decoded_generation);
    if (decoded == 0) {
        result = TLS_FIXER_WRAPPER_FOREIGN;
    } else if (decoded < 0) {
        result = TLS_FIXER_WRAPPER_STALE;
    } else {
        slot = &registry->names[index];
        if (!slot->active || slot->magic != TLS_FIXER_NAME_WRAPPER_MAGIC ||
            slot->version != TLS_FIXER_WRAPPER_VERSION ||
            slot->generation != decoded_generation) {
            result = TLS_FIXER_WRAPPER_STALE;
        } else {
            *name = slot->payload;
            if (generation != NULL) {
                *generation = slot->generation;
            }
            result = TLS_FIXER_WRAPPER_ACTIVE;
        }
    }
    registry_unlock(registry);
    return result;
}

int tls_fixer_cert_registry_release_name(
    TlsFixerCertRegistry *registry,
    const void *wrapper) {
    TlsFixerNameWrapperSlot *slot;
    size_t index = 0;
    uint32_t decoded_generation = 0;
    int decoded;

    if (registry == NULL || wrapper == NULL) {
        return TLS_FIXER_CERT_REGISTRY_INVALID_ARGUMENT;
    }
    if (!registry->initialized) {
        return TLS_FIXER_CERT_REGISTRY_NOT_INITIALIZED;
    }

    registry_lock(registry);
    decoded = decode_wrapper_handle(
        wrapper,
        TLS_FIXER_NAME_HANDLE_TAG,
        TLS_FIXER_NAME_WRAPPER_CAPACITY,
        &index,
        &decoded_generation);
    if (decoded <= 0) {
        registry_unlock(registry);
        return TLS_FIXER_CERT_REGISTRY_STALE;
    }
    slot = &registry->names[index];
    if (!slot->active || slot->magic != TLS_FIXER_NAME_WRAPPER_MAGIC ||
        slot->version != TLS_FIXER_WRAPPER_VERSION ||
        slot->generation != decoded_generation) {
        registry_unlock(registry);
        return TLS_FIXER_CERT_REGISTRY_STALE;
    }
    slot->active = 0;
    slot->payload = NULL;
    registry_unlock(registry);
    return TLS_FIXER_CERT_REGISTRY_OK;
}
