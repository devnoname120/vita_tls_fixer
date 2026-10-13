#include "cert_hooks.h"

#include "diagnostics.h"
#include "provider.h"
#include "tls_fixer/x509_names.h"

#include <psp2/libssl.h>
#include <psp2/net/http.h>
#include <psp2/rtc.h>

#include <mbedtls/oid.h>

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define TLS_FIXER_SCE_SSL_LIBRARY_NID UINT32_C(0xCAF5F2E9)
#define TLS_FIXER_SCE_HTTP_LIBRARY_NID UINT32_C(0xE8F15CDE)
#define TLS_FIXER_NID_SSL_FREE_NAME UINT32_C(0xC73687E4)
#define TLS_FIXER_NID_SSL_GET_ISSUER UINT32_C(0x412711E5)
#define TLS_FIXER_NID_SSL_GET_NAME_COUNT UINT32_C(0x95E14CA6)
#define TLS_FIXER_NID_SSL_GET_NAME_INFO UINT32_C(0x2A857867)
#define TLS_FIXER_NID_SSL_GET_NOT_AFTER UINT32_C(0xF5ED7B68)
#define TLS_FIXER_NID_SSL_GET_NOT_BEFORE UINT32_C(0x70DEA174)
#define TLS_FIXER_NID_SSL_GET_SERIAL UINT32_C(0x901C5C15)
#define TLS_FIXER_NID_SSL_GET_SUBJECT UINT32_C(0x9B2F1BC1)
#define TLS_FIXER_NID_HTTPS_LOAD_CERT UINT32_C(0xAE8D7C33)
#define TLS_FIXER_NID_HTTPS_UNLOAD_CERT UINT32_C(0x8577833F)

typedef enum TlsFixerCertHookIndex {
    TLS_FIXER_CERT_HOOK_FREE_NAME = 0,
    TLS_FIXER_CERT_HOOK_GET_ISSUER,
    TLS_FIXER_CERT_HOOK_GET_NAME_COUNT,
    TLS_FIXER_CERT_HOOK_GET_NAME_INFO,
    TLS_FIXER_CERT_HOOK_GET_NOT_AFTER,
    TLS_FIXER_CERT_HOOK_GET_NOT_BEFORE,
    TLS_FIXER_CERT_HOOK_GET_SERIAL,
    TLS_FIXER_CERT_HOOK_GET_SUBJECT,
    TLS_FIXER_CERT_HOOK_COUNT
} TlsFixerCertHookIndex;

typedef int (*TlsFixerHttpsCallback)(
    unsigned int verification_error,
    void *const certificates[],
    int certificate_count,
    void *user_argument);

typedef int (*TlsFixerGetSerialContinuation)(
    SceSslCert *certificate,
    const char **data,
    unsigned int *length);
typedef int (*TlsFixerGetTimeContinuation)(SceSslCert *certificate, SceRtcTick *tick);
typedef int (*TlsFixerGetNameCountContinuation)(SceSslCertName *name);
typedef int (*TlsFixerGetNameInfoContinuation)(
    SceSslCertName *name,
    int entry_number,
    char *oid_name,
    unsigned int oid_name_capacity,
    char *value,
    unsigned int value_capacity,
    unsigned int *value_length);
typedef SceSslCertName *(*TlsFixerGetNameContinuation)(SceSslCert *certificate);
typedef int (*TlsFixerFreeNameContinuation)(SceSslCertName *name);

typedef struct TlsFixerCertHookDescriptor {
    uint32_t nid;
    const void *function;
} TlsFixerCertHookDescriptor;

static int g_cert_hook_ids[TLS_FIXER_CERT_HOOK_COUNT];
static tai_hook_ref_t g_cert_hook_refs[TLS_FIXER_CERT_HOOK_COUNT];
static int g_https_load_cert_hook_id = -1;
static int g_https_unload_cert_hook_id = -1;
static tai_hook_ref_t g_https_load_cert_hook_ref;
static tai_hook_ref_t g_https_unload_cert_hook_ref;
static int g_cert_hooks_active;
static uint32_t g_legacy_certificates_loaded;

static void *next_hook_function(tai_hook_ref_t reference) {
    struct _tai_hook_user *current = (struct _tai_hook_user *)reference;
    struct _tai_hook_user *next = (struct _tai_hook_user *)current->next;

    return next == NULL ? current->old : next->func;
}

static TlsFixerWrapperLookupResult lookup_certificate(
    const void *wrapper,
    const mbedtls_x509_crt **certificate) {
    const void *payload = NULL;
    TlsFixerWrapperLookupResult result = tls_fixer_cert_registry_lookup_certificate(
        &g_tls_fixer_http.cert_registry,
        wrapper,
        &payload,
        NULL);

    if (result == TLS_FIXER_WRAPPER_ACTIVE) {
        *certificate = (const mbedtls_x509_crt *)payload;
    }
    return result;
}

static TlsFixerWrapperLookupResult lookup_name(
    const void *wrapper,
    const mbedtls_x509_name **name) {
    const void *payload = NULL;
    TlsFixerWrapperLookupResult result = tls_fixer_cert_registry_lookup_name(
        &g_tls_fixer_http.cert_registry,
        wrapper,
        &payload,
        NULL);

    if (result == TLS_FIXER_WRAPPER_ACTIVE) {
        *name = (const mbedtls_x509_name *)payload;
    }
    return result;
}

static int certificate_time_to_tick(const mbedtls_x509_time *source, SceRtcTick *tick) {
    SceDateTime date_time;
    int result;

    if (source == NULL || tick == NULL) {
        return TLS_FIXER_SCE_SSL_ERROR_INVALID_VALUE;
    }

    memset(&date_time, 0, sizeof(date_time));
    date_time.year = (SceUInt16)source->year;
    date_time.month = (SceUInt16)source->mon;
    date_time.day = (SceUInt16)source->day;
    date_time.hour = (SceUInt16)source->hour;
    date_time.minute = (SceUInt16)source->min;
    date_time.second = (SceUInt16)source->sec;
    result = sceRtcCheckValid(&date_time);
    if (result < 0) {
        return TLS_FIXER_SCE_SSL_ERROR_INVALID_FORMAT;
    }
    result = sceRtcGetTick(&date_time, tick);
    return result < 0 ? result : 0;
}

static const mbedtls_x509_name *name_entry_at(
    const mbedtls_x509_name *name,
    int entry_number) {
    int index = 0;

    if (entry_number < 0) {
        return NULL;
    }
    while (name != NULL) {
        if (name->oid.p != NULL && name->oid.len != 0) {
            if (index == entry_number) {
                return name;
            }
            ++index;
        }
        name = name->next;
    }
    return NULL;
}

static void copy_string(char *destination, unsigned int capacity, const char *source) {
    size_t length;

    if (capacity == 0) {
        return;
    }
    length = strlen(source);
    if (length >= capacity) {
        length = capacity - 1;
    }
    memcpy(destination, source, length);
    destination[length] = '\0';
}

static int hook_get_serial(
    SceSslCert *wrapper,
    const char **data,
    unsigned int *length) {
    const mbedtls_x509_crt *certificate = NULL;
    TlsFixerWrapperLookupResult lookup = lookup_certificate(wrapper, &certificate);

    if (lookup == TLS_FIXER_WRAPPER_FOREIGN) {
        return ((TlsFixerGetSerialContinuation)next_hook_function(
            g_cert_hook_refs[TLS_FIXER_CERT_HOOK_GET_SERIAL]))(wrapper, data, length);
    }
    if (lookup != TLS_FIXER_WRAPPER_ACTIVE || data == NULL || length == NULL) {
        return TLS_FIXER_SCE_SSL_ERROR_INVALID_VALUE;
    }
    *data = (const char *)certificate->serial.p;
    *length = (unsigned int)certificate->serial.len;
    return 0;
}

static mbedtls_x509_name *copy_certificate_name(const mbedtls_x509_name *source) {
    const mbedtls_x509_name *entry;
    mbedtls_x509_name *copy;
    unsigned char *bytes;
    size_t count = 0, byte_count = 0, index = 0;

    for (entry = source; entry != NULL; entry = entry->next) {
        if (++count > 256 || entry->oid.len > 65536 || entry->val.len > 65536 ||
            (entry->oid.len != 0 && entry->oid.p == NULL) ||
            (entry->val.len != 0 && entry->val.p == NULL)) {
            return NULL;
        }
        byte_count += entry->oid.len + entry->val.len;
        if (byte_count > 65536) {
            return NULL;
        }
    }
    if (count == 0) {
        return NULL;
    }
    copy = calloc(1, count * sizeof(*copy) + byte_count);
    if (copy == NULL) {
        return NULL;
    }
    bytes = (unsigned char *)(copy + count);
    for (entry = source; entry != NULL; entry = entry->next, ++index) {
        copy[index] = *entry;
        copy[index].oid.p = bytes;
        if (entry->oid.len != 0) {
            memcpy(bytes, entry->oid.p, entry->oid.len);
            bytes += entry->oid.len;
        }
        copy[index].val.p = bytes;
        if (entry->val.len != 0) {
            memcpy(bytes, entry->val.p, entry->val.len);
            bytes += entry->val.len;
        }
        copy[index].next = index + 1 < count ? &copy[index + 1] : NULL;
    }
    return copy;
}

static SceSslCertName *create_name_wrapper(
    SceSslCert *wrapper,
    const mbedtls_x509_name *name) {
    void *name_wrapper = NULL;
    mbedtls_x509_name *owned_name = copy_certificate_name(name);

    if (owned_name == NULL) {
        return NULL;
    }

    if (tls_fixer_cert_registry_create_name(
            &g_tls_fixer_http.cert_registry,
            wrapper,
            owned_name,
            &name_wrapper) != TLS_FIXER_CERT_REGISTRY_OK) {
        free(owned_name);
        return NULL;
    }
    return (SceSslCertName *)name_wrapper;
}

static SceSslCertName *hook_get_subject(SceSslCert *wrapper) {
    const mbedtls_x509_crt *certificate = NULL;
    TlsFixerWrapperLookupResult lookup = lookup_certificate(wrapper, &certificate);

    if (lookup == TLS_FIXER_WRAPPER_FOREIGN) {
        return ((TlsFixerGetNameContinuation)next_hook_function(
            g_cert_hook_refs[TLS_FIXER_CERT_HOOK_GET_SUBJECT]))(wrapper);
    }
    if (lookup != TLS_FIXER_WRAPPER_ACTIVE) {
        return NULL;
    }
    return create_name_wrapper(wrapper, &certificate->subject);
}

static SceSslCertName *hook_get_issuer(SceSslCert *wrapper) {
    const mbedtls_x509_crt *certificate = NULL;
    TlsFixerWrapperLookupResult lookup = lookup_certificate(wrapper, &certificate);

    if (lookup == TLS_FIXER_WRAPPER_FOREIGN) {
        return ((TlsFixerGetNameContinuation)next_hook_function(
            g_cert_hook_refs[TLS_FIXER_CERT_HOOK_GET_ISSUER]))(wrapper);
    }
    if (lookup != TLS_FIXER_WRAPPER_ACTIVE) {
        return NULL;
    }
    return create_name_wrapper(wrapper, &certificate->issuer);
}

static int hook_free_name(SceSslCertName *wrapper) {
    const mbedtls_x509_name *name = NULL;
    TlsFixerWrapperLookupResult lookup = lookup_name(wrapper, &name);

    (void)name;
    if (lookup == TLS_FIXER_WRAPPER_FOREIGN) {
        return ((TlsFixerFreeNameContinuation)next_hook_function(
            g_cert_hook_refs[TLS_FIXER_CERT_HOOK_FREE_NAME]))(wrapper);
    }
    if (lookup != TLS_FIXER_WRAPPER_ACTIVE) {
        return TLS_FIXER_SCE_SSL_ERROR_INVALID_VALUE;
    }
    if (tls_fixer_cert_registry_release_name(&g_tls_fixer_http.cert_registry, wrapper) !=
        TLS_FIXER_CERT_REGISTRY_OK) {
        return TLS_FIXER_SCE_SSL_ERROR_INVALID_VALUE;
    }
    free((void *)name);
    return 0;
}

static int hook_get_not_before(SceSslCert *wrapper, SceRtcTick *tick) {
    const mbedtls_x509_crt *certificate = NULL;
    TlsFixerWrapperLookupResult lookup = lookup_certificate(wrapper, &certificate);

    if (lookup == TLS_FIXER_WRAPPER_FOREIGN) {
        return ((TlsFixerGetTimeContinuation)next_hook_function(
            g_cert_hook_refs[TLS_FIXER_CERT_HOOK_GET_NOT_BEFORE]))(wrapper, tick);
    }
    if (lookup != TLS_FIXER_WRAPPER_ACTIVE) {
        return TLS_FIXER_SCE_SSL_ERROR_INVALID_VALUE;
    }
    return certificate_time_to_tick(&certificate->valid_from, tick);
}

static int hook_get_not_after(SceSslCert *wrapper, SceRtcTick *tick) {
    const mbedtls_x509_crt *certificate = NULL;
    TlsFixerWrapperLookupResult lookup = lookup_certificate(wrapper, &certificate);

    if (lookup == TLS_FIXER_WRAPPER_FOREIGN) {
        return ((TlsFixerGetTimeContinuation)next_hook_function(
            g_cert_hook_refs[TLS_FIXER_CERT_HOOK_GET_NOT_AFTER]))(wrapper, tick);
    }
    if (lookup != TLS_FIXER_WRAPPER_ACTIVE) {
        return TLS_FIXER_SCE_SSL_ERROR_INVALID_VALUE;
    }
    return certificate_time_to_tick(&certificate->valid_to, tick);
}

static int hook_get_name_count(SceSslCertName *wrapper) {
    const mbedtls_x509_name *name = NULL;
    TlsFixerWrapperLookupResult lookup = lookup_name(wrapper, &name);
    int count = 0;

    if (lookup == TLS_FIXER_WRAPPER_FOREIGN) {
        return ((TlsFixerGetNameCountContinuation)next_hook_function(
            g_cert_hook_refs[TLS_FIXER_CERT_HOOK_GET_NAME_COUNT]))(wrapper);
    }
    if (lookup != TLS_FIXER_WRAPPER_ACTIVE) {
        return TLS_FIXER_SCE_SSL_ERROR_INVALID_VALUE;
    }
    while (name != NULL) {
        if (name->oid.p != NULL && name->oid.len != 0) {
            ++count;
        }
        name = name->next;
    }
    return count;
}

static int hook_get_name_info(
    SceSslCertName *wrapper,
    int entry_number,
    char *oid_name,
    unsigned int oid_name_capacity,
    char *value,
    unsigned int value_capacity,
    unsigned int *value_length) {
    const mbedtls_x509_name *name = NULL;
    const mbedtls_x509_name *entry;
    char numeric_oid[96];
    const char *display_name;
    size_t copy_length;
    int oid_result;
    TlsFixerWrapperLookupResult lookup = lookup_name(wrapper, &name);

    if (lookup == TLS_FIXER_WRAPPER_FOREIGN) {
        return ((TlsFixerGetNameInfoContinuation)next_hook_function(
            g_cert_hook_refs[TLS_FIXER_CERT_HOOK_GET_NAME_INFO]))(
                wrapper,
                entry_number,
                oid_name,
                oid_name_capacity,
                value,
                value_capacity,
                value_length);
    }
    if (lookup != TLS_FIXER_WRAPPER_ACTIVE || oid_name == NULL || value == NULL ||
        value_length == NULL) {
        return TLS_FIXER_SCE_SSL_ERROR_INVALID_VALUE;
    }

    entry = name_entry_at(name, entry_number);
    if (entry == NULL) {
        return TLS_FIXER_SCE_SSL_ERROR_INVALID_FORMAT;
    }

    display_name = tls_fixer_x509_attribute_name(entry->oid.p, entry->oid.len);
    if (display_name == NULL) {
        oid_result = mbedtls_oid_get_numeric_string(
            numeric_oid,
            sizeof(numeric_oid),
            &entry->oid);
        if (oid_result < 0) {
            return TLS_FIXER_SCE_SSL_ERROR_INVALID_FORMAT;
        }
        display_name = numeric_oid;
    }
    copy_string(oid_name, oid_name_capacity, display_name);

    *value_length = (unsigned int)entry->val.len;
    copy_length = entry->val.len;
    if (copy_length > value_capacity) {
        copy_length = value_capacity;
    }
    if (copy_length != 0) {
        memcpy(value, entry->val.p, copy_length);
    }
    return 0;
}

static const TlsFixerCertHookDescriptor g_cert_hook_descriptors[TLS_FIXER_CERT_HOOK_COUNT] = {
    {TLS_FIXER_NID_SSL_FREE_NAME, hook_free_name},
    {TLS_FIXER_NID_SSL_GET_ISSUER, hook_get_issuer},
    {TLS_FIXER_NID_SSL_GET_NAME_COUNT, hook_get_name_count},
    {TLS_FIXER_NID_SSL_GET_NAME_INFO, hook_get_name_info},
    {TLS_FIXER_NID_SSL_GET_NOT_AFTER, hook_get_not_after},
    {TLS_FIXER_NID_SSL_GET_NOT_BEFORE, hook_get_not_before},
    {TLS_FIXER_NID_SSL_GET_SERIAL, hook_get_serial},
    {TLS_FIXER_NID_SSL_GET_SUBJECT, hook_get_subject},
};

static int hook_https_load_cert(
    int certificate_count,
    const SceHttpsData **certificates,
    const SceHttpsData *client_certificate,
    const SceHttpsData *private_key) {
    typedef int (*Continuation)(
        int,
        const SceHttpsData **,
        const SceHttpsData *,
        const SceHttpsData *);
    int result = ((Continuation)next_hook_function(g_https_load_cert_hook_ref))(
        certificate_count,
        certificates,
        client_certificate,
        private_key);

    if (result >= 0 &&
        ((certificate_count > 0 && certificates != NULL) ||
         client_certificate != NULL || private_key != NULL)) {
        __atomic_store_n(&g_legacy_certificates_loaded, 1, __ATOMIC_RELEASE);
        TLS_FIXER_LOG("custom certificate material loaded; new connections use BSAFE");
    }
    return result;
}

static int hook_https_unload_cert(void) {
    typedef int (*Continuation)(void);
    int result = ((Continuation)next_hook_function(g_https_unload_cert_hook_ref))();

    if (result >= 0) {
        __atomic_store_n(&g_legacy_certificates_loaded, 0, __ATOMIC_RELEASE);
        TLS_FIXER_LOG("custom certificate material unloaded; provider connections enabled");
    }
    return result;
}

int tls_fixer_cert_hooks_install(void) {
    size_t index;

    for (index = 0; index < TLS_FIXER_CERT_HOOK_COUNT; ++index) {
        g_cert_hook_ids[index] = -1;
        memset(&g_cert_hook_refs[index], 0, sizeof(g_cert_hook_refs[index]));
    }
    g_cert_hooks_active = 0;
    g_https_load_cert_hook_id = -1;
    g_https_unload_cert_hook_id = -1;
    memset(&g_https_load_cert_hook_ref, 0, sizeof(g_https_load_cert_hook_ref));
    memset(&g_https_unload_cert_hook_ref, 0, sizeof(g_https_unload_cert_hook_ref));
    __atomic_store_n(&g_legacy_certificates_loaded, 0, __ATOMIC_RELEASE);

    for (index = 0; index < TLS_FIXER_CERT_HOOK_COUNT; ++index) {
        int hook_id = taiHookFunctionExport(
            &g_cert_hook_refs[index],
            "SceLibSsl",
            TLS_FIXER_SCE_SSL_LIBRARY_NID,
            g_cert_hook_descriptors[index].nid,
            g_cert_hook_descriptors[index].function);
        TLS_FIXER_LOG("event=hook.install kind=certificate index=%u nid=%08X rc=%08X",
            (unsigned int)index, g_cert_hook_descriptors[index].nid, hook_id);
        if (hook_id < 0) {
            tls_fixer_cert_hooks_release();
            return hook_id;
        }
        g_cert_hook_ids[index] = hook_id;
    }

    g_https_load_cert_hook_id = taiHookFunctionExport(
        &g_https_load_cert_hook_ref,
        "SceLibHttp",
        TLS_FIXER_SCE_HTTP_LIBRARY_NID,
        TLS_FIXER_NID_HTTPS_LOAD_CERT,
        hook_https_load_cert);
    TLS_FIXER_LOG("event=hook.install kind=load_cert nid=%08X rc=%08X",
        TLS_FIXER_NID_HTTPS_LOAD_CERT, g_https_load_cert_hook_id);
    if (g_https_load_cert_hook_id < 0) {
        tls_fixer_cert_hooks_release();
        return g_https_load_cert_hook_id;
    }

    g_https_unload_cert_hook_id = taiHookFunctionExport(
        &g_https_unload_cert_hook_ref,
        "SceLibHttp",
        TLS_FIXER_SCE_HTTP_LIBRARY_NID,
        TLS_FIXER_NID_HTTPS_UNLOAD_CERT,
        hook_https_unload_cert);
    TLS_FIXER_LOG("event=hook.install kind=unload_cert nid=%08X rc=%08X",
        TLS_FIXER_NID_HTTPS_UNLOAD_CERT, g_https_unload_cert_hook_id);
    if (g_https_unload_cert_hook_id < 0) {
        tls_fixer_cert_hooks_release();
        return g_https_unload_cert_hook_id;
    }

    g_cert_hooks_active = 1;
    return 0;
}

void tls_fixer_cert_hooks_release(void) {
    size_t index = TLS_FIXER_CERT_HOOK_COUNT;

    g_cert_hooks_active = 0;
    __atomic_store_n(&g_legacy_certificates_loaded, 0, __ATOMIC_RELEASE);
    if (g_https_unload_cert_hook_id >= 0) {
        taiHookRelease(g_https_unload_cert_hook_id, g_https_unload_cert_hook_ref);
        g_https_unload_cert_hook_id = -1;
        memset(&g_https_unload_cert_hook_ref, 0, sizeof(g_https_unload_cert_hook_ref));
    }
    if (g_https_load_cert_hook_id >= 0) {
        taiHookRelease(g_https_load_cert_hook_id, g_https_load_cert_hook_ref);
        g_https_load_cert_hook_id = -1;
        memset(&g_https_load_cert_hook_ref, 0, sizeof(g_https_load_cert_hook_ref));
    }
    while (index > 0) {
        --index;
        if (g_cert_hook_ids[index] >= 0) {
            taiHookRelease(g_cert_hook_ids[index], g_cert_hook_refs[index]);
            g_cert_hook_ids[index] = -1;
            memset(&g_cert_hook_refs[index], 0, sizeof(g_cert_hook_refs[index]));
        }
    }
}

int tls_fixer_cert_hooks_active(void) {
    return g_cert_hooks_active;
}

int tls_fixer_legacy_certificates_loaded(void) {
    return __atomic_load_n(&g_legacy_certificates_loaded, __ATOMIC_ACQUIRE) != 0;
}

int tls_fixer_cert_callback_decide(
    void *sony_connection,
    const mbedtls_x509_crt *peer_chain,
    uint32_t verification_detail,
    int *accepted) {
    const void *certificates[TLS_FIXER_CERT_WRAPPER_CAPACITY];
    void *wrappers[TLS_FIXER_CERT_WRAPPER_CAPACITY];
    uintptr_t callback_address;
    uintptr_t callback_argument;
    uint32_t generation = 0;
    size_t certificate_count = 0;
    int callback_result;

    if (sony_connection == NULL || accepted == NULL) {
        return TLS_FIXER_CERT_REGISTRY_INVALID_ARGUMENT;
    }
    *accepted = 0;
    callback_address = tls_fixer_connection_callback_address(sony_connection);
    if (callback_address == 0) {
        *accepted = verification_detail == 0;
        return 0;
    }
    if (!tls_fixer_cert_hooks_active()) {
        return TLS_FIXER_CERT_REGISTRY_NOT_INITIALIZED;
    }

    while (peer_chain != NULL) {
        if (certificate_count == TLS_FIXER_CERT_WRAPPER_CAPACITY) {
            return TLS_FIXER_CERT_REGISTRY_FULL;
        }
        certificates[certificate_count] = peer_chain;
        ++certificate_count;
        peer_chain = peer_chain->next;
    }

    if (certificate_count != 0 &&
        tls_fixer_cert_registry_begin(
            &g_tls_fixer_http.cert_registry,
            certificates,
            certificate_count,
            wrappers,
            &generation) != TLS_FIXER_CERT_REGISTRY_OK) {
        return TLS_FIXER_CERT_REGISTRY_FULL;
    }

    callback_argument = tls_fixer_connection_callback_arg_address(sony_connection);
    callback_result = ((TlsFixerHttpsCallback)callback_address)(
        verification_detail,
        certificate_count == 0 ? NULL : wrappers,
        (int)certificate_count,
        (void *)callback_argument);
    if (generation != 0) {
        tls_fixer_cert_registry_end(&g_tls_fixer_http.cert_registry, generation);
    }
    *accepted = tls_fixer_cert_callback_accepted(
        callback_result, verification_detail, callback_address, &g_tls_fixer_http.cert_policy);
    return 0;
}
