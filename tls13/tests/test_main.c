#include "tls_fixer/cert_registry.h"
#include "tls_fixer/error_map.h"
#include "tls_fixer/module_gate.h"
#include "tls_fixer/path.h"
#include "tls_fixer/registry.h"
#include "tls_fixer/sony_abi.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned int g_assertions;
static unsigned int g_failures;

#define CHECK(expression)                                                                 \
    do {                                                                                  \
        ++g_assertions;                                                                   \
        if (!(expression)) {                                                              \
            ++g_failures;                                                                 \
            fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, #expression); \
        }                                                                                 \
    } while (0)

#define CHECK_EQ_INT(expected, actual)                                                     \
    do {                                                                                  \
        const int64_t check_expected = (int64_t)(expected);                              \
        const int64_t check_actual = (int64_t)(actual);                                  \
        ++g_assertions;                                                                   \
        if (check_expected != check_actual) {                                             \
            ++g_failures;                                                                 \
            fprintf(                                                                      \
                stderr,                                                                   \
                "%s:%d: expected %" PRId64 ", got %" PRId64 "\n",                    \
                __FILE__,                                                                 \
                __LINE__,                                                                 \
                check_expected,                                                           \
                check_actual);                                                            \
        }                                                                                 \
    } while (0)

static void test_path_helpers(void) {
    CHECK(tls_fixer_path_equals("vs0:sys/external/libhttp.suprx", "vs0:sys/external/libhttp.suprx", 64));
    CHECK(!tls_fixer_path_equals("vs0:sys/external/libhttp.suprx.old", "vs0:sys/external/libhttp.suprx", 64));
    CHECK(tls_fixer_path_has_suffix("vs0:/data/external/webcore/ScePsp2Compat.suprx", "webcore/ScePsp2Compat.suprx", 64));
    CHECK(!tls_fixer_path_has_suffix("x", "webcore/ScePsp2Compat.suprx", 64));
    CHECK(!tls_fixer_path_has_suffix(NULL, "x", 64));
    CHECK(!tls_fixer_path_has_suffix("unterminated", "ated", 4));
}

static void test_sony_abi(void) {
    uint8_t request[0x140] = {0};
    uint8_t connection[0x168] = {0};
    uint32_t value;

    value = UINT32_C(0x12345678);
    memcpy(request + TLS_FIXER_REQUEST_FALLBACK_CONNECTION_OFFSET, &value, sizeof(value));
    CHECK_EQ_INT(UINT32_C(0x12345678), tls_fixer_resolve_connection_address(request));

    value = UINT32_C(0x87654321);
    memcpy(request + TLS_FIXER_REQUEST_PRIMARY_CONNECTION_OFFSET, &value, sizeof(value));
    CHECK_EQ_INT(UINT32_C(0x87654321), tls_fixer_resolve_connection_address(request));

    CHECK_EQ_INT(0, tls_fixer_request_is_nonblocking(request));
    value = UINT32_C(1);
    memcpy(request + TLS_FIXER_REQUEST_NONBLOCK_OFFSET, &value, sizeof(value));
    CHECK_EQ_INT(1, tls_fixer_request_is_nonblocking(request));

    value = UINT32_C(42);
    memcpy(connection + TLS_FIXER_CONNECTION_SOCKET_OFFSET, &value, sizeof(value));
    CHECK_EQ_INT(42, tls_fixer_connection_socket(connection));

    value = UINT32_C(0x10203040);
    memcpy(connection + TLS_FIXER_CONNECTION_HOSTNAME_OFFSET, &value, sizeof(value));
    CHECK_EQ_INT(UINT32_C(0x10203040), tls_fixer_connection_hostname_address(connection));

    value = UINT32_C(0x11223344);
    memcpy(connection + TLS_FIXER_CONNECTION_CALLBACK_OFFSET, &value, sizeof(value));
    CHECK_EQ_INT(UINT32_C(0x11223344), tls_fixer_connection_callback_address(connection));

    value = UINT32_C(0x55667788);
    memcpy(connection + TLS_FIXER_CONNECTION_CALLBACK_ARG_OFFSET, &value, sizeof(value));
    CHECK_EQ_INT(UINT32_C(0x55667788), tls_fixer_connection_callback_arg_address(connection));

    value = UINT32_C(3);
    memcpy(connection + TLS_FIXER_CONNECTION_HTTPS_OPTIONS_OFFSET, &value, sizeof(value));
    CHECK_EQ_INT(
        UINT32_C(0x65),
        tls_fixer_connection_effective_https_options(connection, UINT32_C(0x65)));

    value = UINT32_C(0x80000025);
    memcpy(connection + TLS_FIXER_CONNECTION_HTTPS_OPTIONS_OFFSET, &value, sizeof(value));
    CHECK_EQ_INT(
        UINT32_C(0x25),
        tls_fixer_connection_effective_https_options(connection, UINT32_C(0x65)));

    tls_fixer_store_ssl_error(
        connection,
        TLS_FIXER_SCE_HTTPS_ERROR_HANDSHAKE,
        TLS_FIXER_SCE_HTTPS_DETAIL_INTERNAL);
    CHECK_EQ_INT(
        (uint32_t)TLS_FIXER_SCE_HTTPS_ERROR_HANDSHAKE,
        tls_fixer_read_u32(connection, TLS_FIXER_CONNECTION_SSL_ERROR_OFFSET));
    CHECK_EQ_INT(
        TLS_FIXER_SCE_HTTPS_DETAIL_INTERNAL,
        tls_fixer_read_u32(connection, TLS_FIXER_CONNECTION_SSL_DETAIL_OFFSET));
}

static void test_error_map(void) {
    TlsFixerMappedError mapped;
    uint32_t provider_flags =
        TLS_FIXER_CERT_INVALID |
        TLS_FIXER_CERT_HOSTNAME |
        TLS_FIXER_CERT_EXPIRED |
        TLS_FIXER_CERT_FUTURE |
        TLS_FIXER_CERT_UNKNOWN_CA |
        TLS_FIXER_CERT_INTERNAL;

    CHECK_EQ_INT(
        TLS_FIXER_SCE_HTTPS_DETAIL_INTERNAL |
            TLS_FIXER_SCE_HTTPS_DETAIL_INVALID_CERT |
            TLS_FIXER_SCE_HTTPS_DETAIL_CN_CHECK |
            TLS_FIXER_SCE_HTTPS_DETAIL_NOT_AFTER |
            TLS_FIXER_SCE_HTTPS_DETAIL_NOT_BEFORE |
            TLS_FIXER_SCE_HTTPS_DETAIL_UNKNOWN_CA,
        tls_fixer_map_certificate_detail(provider_flags));

    CHECK_EQ_INT(
        0,
        tls_fixer_filter_certificate_flags(provider_flags, 0));
    CHECK_EQ_INT(
        TLS_FIXER_CERT_INVALID | TLS_FIXER_CERT_INTERNAL,
        tls_fixer_filter_certificate_flags(
            provider_flags,
            TLS_FIXER_SCE_HTTPS_OPTION_SERVER_VERIFY));
    CHECK_EQ_INT(
        TLS_FIXER_CERT_INVALID |
            TLS_FIXER_CERT_INTERNAL |
            TLS_FIXER_CERT_HOSTNAME |
            TLS_FIXER_CERT_EXPIRED |
            TLS_FIXER_CERT_FUTURE |
            TLS_FIXER_CERT_UNKNOWN_CA,
        tls_fixer_filter_certificate_flags(
            provider_flags,
            TLS_FIXER_SCE_HTTPS_OPTION_SERVER_VERIFY |
                TLS_FIXER_SCE_HTTPS_OPTION_CN_CHECK |
                TLS_FIXER_SCE_HTTPS_OPTION_NOT_AFTER |
                TLS_FIXER_SCE_HTTPS_OPTION_NOT_BEFORE |
                TLS_FIXER_SCE_HTTPS_OPTION_KNOWN_CA));

    mapped = tls_fixer_map_outcome(TLS_FIXER_OUTCOME_WANT_READ, UINT32_C(0xAA));
    CHECK_EQ_INT(TLS_FIXER_SCE_HTTP_ERROR_EAGAIN, mapped.hook_result);
    CHECK_EQ_INT(0, mapped.ssl_error);
    CHECK_EQ_INT(0, mapped.fatal);

    mapped = tls_fixer_map_outcome(TLS_FIXER_OUTCOME_WANT_WRITE, 0);
    CHECK_EQ_INT(TLS_FIXER_SCE_HTTP_ERROR_EAGAIN, mapped.hook_result);
    CHECK_EQ_INT(0, mapped.fatal);

    mapped = tls_fixer_map_outcome(TLS_FIXER_OUTCOME_CLOSE_NOTIFY, 0);
    CHECK_EQ_INT(0, mapped.hook_result);
    CHECK_EQ_INT(0, mapped.fatal);

    mapped = tls_fixer_map_outcome(TLS_FIXER_OUTCOME_CERTIFICATE, provider_flags);
    CHECK_EQ_INT(TLS_FIXER_SCE_HTTP_ERROR_SSL, mapped.hook_result);
    CHECK_EQ_INT(TLS_FIXER_SCE_HTTPS_ERROR_CERT, mapped.ssl_error);
    CHECK_EQ_INT(UINT32_C(0x3F), mapped.detail);
    CHECK_EQ_INT(1, mapped.fatal);

    mapped = tls_fixer_map_outcome(TLS_FIXER_OUTCOME_HANDSHAKE, UINT32_C(0x1234));
    CHECK_EQ_INT(TLS_FIXER_SCE_HTTP_ERROR_SSL, mapped.hook_result);
    CHECK_EQ_INT(TLS_FIXER_SCE_HTTPS_ERROR_HANDSHAKE, mapped.ssl_error);
    CHECK_EQ_INT(UINT32_C(0x1234), mapped.detail);

    mapped = tls_fixer_map_outcome(TLS_FIXER_OUTCOME_IO, UINT32_C(0x55));
    CHECK_EQ_INT(TLS_FIXER_SCE_HTTP_ERROR_SSL, mapped.hook_result);
    CHECK_EQ_INT(TLS_FIXER_SCE_HTTPS_ERROR_IO, mapped.ssl_error);

    mapped = tls_fixer_map_outcome(TLS_FIXER_OUTCOME_EOF, 0);
    CHECK_EQ_INT(TLS_FIXER_SCE_HTTP_ERROR_SSL, mapped.hook_result);
    CHECK_EQ_INT(TLS_FIXER_SCE_HTTPS_ERROR_IO, mapped.ssl_error);

    mapped = tls_fixer_map_outcome(TLS_FIXER_OUTCOME_TIMEOUT, 0);
    CHECK_EQ_INT(TLS_FIXER_SCE_HTTP_ERROR_TIMEOUT, mapped.hook_result);
    CHECK_EQ_INT(0, mapped.ssl_error);
    CHECK_EQ_INT(0, mapped.fatal);

    mapped = tls_fixer_map_outcome(TLS_FIXER_OUTCOME_NO_MEMORY, 0);
    CHECK_EQ_INT(TLS_FIXER_SCE_HTTP_ERROR_OUT_OF_MEMORY, mapped.hook_result);
    CHECK_EQ_INT(TLS_FIXER_SCE_HTTPS_ERROR_INTERNAL, mapped.ssl_error);

    mapped = tls_fixer_map_outcome(TLS_FIXER_OUTCOME_INTERNAL, UINT32_C(0xDEAD));
    CHECK_EQ_INT(TLS_FIXER_SCE_HTTP_ERROR_SSL, mapped.hook_result);
    CHECK_EQ_INT(TLS_FIXER_SCE_HTTPS_ERROR_INTERNAL, mapped.ssl_error);
    CHECK_EQ_INT(UINT32_C(0xDEAD), mapped.detail);
}

static void test_module_gate(void) {
    uint8_t text[32];
    const uint8_t bytes[] = {0x10, 0x20, 0x30, 0x40};
    const TlsFixerMaskedSignature signature = {
        .name = "test",
        .offset = 8,
        .bytes = bytes,
        .mask = "x?xx",
        .length = sizeof(bytes),
    };
    const TlsFixerModuleDescriptor descriptor = {
        .text_size = sizeof(text),
        .signatures = &signature,
        .signature_count = 1,
    };
    size_t failed_signature = 0;
    size_t failed_byte = 0;
    TlsFixerMaskedSignature invalid_signature = signature;
    TlsFixerModuleDescriptor invalid_descriptor = descriptor;

    memset(text, 0, sizeof(text));
    memcpy(text + signature.offset, bytes, sizeof(bytes));
    CHECK_EQ_INT(
        TLS_FIXER_MODULE_GATE_OK,
        tls_fixer_validate_module_text(
            text,
            sizeof(text),
            &descriptor,
            &failed_signature,
            &failed_byte));
    CHECK_EQ_INT(SIZE_MAX, failed_signature);
    CHECK_EQ_INT(SIZE_MAX, failed_byte);

    text[signature.offset + 1] ^= UINT8_C(0xFF);
    CHECK_EQ_INT(
        TLS_FIXER_MODULE_GATE_OK,
        tls_fixer_validate_module_text(text, sizeof(text), &descriptor, NULL, NULL));

    text[signature.offset + 2] ^= UINT8_C(0xFF);
    CHECK_EQ_INT(
        TLS_FIXER_MODULE_GATE_SIGNATURE_MISMATCH,
        tls_fixer_validate_module_text(
            text,
            sizeof(text),
            &descriptor,
            &failed_signature,
            &failed_byte));
    CHECK_EQ_INT(0, failed_signature);
    CHECK_EQ_INT(2, failed_byte);

    CHECK_EQ_INT(
        TLS_FIXER_MODULE_GATE_TEXT_SIZE_MISMATCH,
        tls_fixer_validate_module_text(text, sizeof(text) - 1, &descriptor, NULL, NULL));

    invalid_signature.offset = sizeof(text) - 1;
    invalid_descriptor.signatures = &invalid_signature;
    CHECK_EQ_INT(
        TLS_FIXER_MODULE_GATE_SIGNATURE_BOUNDS,
        tls_fixer_validate_module_text(text, sizeof(text), &invalid_descriptor, NULL, NULL));

    invalid_signature = signature;
    invalid_signature.mask = "x!xx";
    invalid_descriptor.signatures = &invalid_signature;
    CHECK_EQ_INT(
        TLS_FIXER_MODULE_GATE_SIGNATURE_MASK,
        tls_fixer_validate_module_text(text, sizeof(text), &invalid_descriptor, NULL, NULL));
}

typedef struct RegistryTestContext {
    unsigned int lock_depth;
    unsigned int cleanup_count;
    uintptr_t last_cleaned_payload;
} RegistryTestContext;

static void registry_test_lock(void *context) {
    RegistryTestContext *test = context;
    CHECK_EQ_INT(0, test->lock_depth);
    ++test->lock_depth;
}

static void registry_test_unlock(void *context) {
    RegistryTestContext *test = context;
    CHECK_EQ_INT(1, test->lock_depth);
    --test->lock_depth;
}

static void registry_test_cleanup(void *context, void *payload) {
    RegistryTestContext *test = context;
    CHECK_EQ_INT(0, test->lock_depth);
    ++test->cleanup_count;
    test->last_cleaned_payload = (uintptr_t)payload;
}

static TlsFixerRegistryOps registry_test_ops(RegistryTestContext *context) {
    TlsFixerRegistryOps ops = {
        .lock = registry_test_lock,
        .unlock = registry_test_unlock,
        .cleanup = registry_test_cleanup,
        .context = context,
    };
    return ops;
}

static TlsFixerCertRegistryOps cert_registry_test_ops(RegistryTestContext *context) {
    TlsFixerCertRegistryOps ops = {
        .lock = registry_test_lock,
        .unlock = registry_test_unlock,
        .context = context,
    };
    return ops;
}

static void test_certificate_wrapper_registry(void) {
    TlsFixerCertRegistry registry;
    RegistryTestContext context = {0};
    TlsFixerCertRegistryOps ops = cert_registry_test_ops(&context);
    const void *certificates[] = {
        (const void *)(uintptr_t)UINT32_C(0x1000),
        (const void *)(uintptr_t)UINT32_C(0x2000),
    };
    void *wrappers[2] = {0};
    void *name_wrapper = NULL;
    void *replacement_wrapper = NULL;
    void *replacement_name_wrapper = NULL;
    const void *payload = NULL;
    const void *replacement_certificate =
        (const void *)(uintptr_t)UINT32_C(0x5000);
    uint32_t generation = 0;
    uint32_t lookup_generation = 0;
    uint32_t replacement_generation = 0;

    CHECK_EQ_INT(
        TLS_FIXER_CERT_REGISTRY_OK,
        tls_fixer_cert_registry_init(&registry, &ops));
    CHECK_EQ_INT(
        TLS_FIXER_CERT_REGISTRY_OK,
        tls_fixer_cert_registry_begin(
            &registry,
            certificates,
            sizeof(certificates) / sizeof(certificates[0]),
            wrappers,
            &generation));
    CHECK(generation != 0);
    CHECK(wrappers[0] != NULL);
    CHECK(wrappers[1] != NULL);
    CHECK(wrappers[0] != wrappers[1]);

    CHECK_EQ_INT(
        TLS_FIXER_WRAPPER_ACTIVE,
        tls_fixer_cert_registry_lookup_certificate(
            &registry,
            wrappers[0],
            &payload,
            &lookup_generation));
    CHECK_EQ_INT((uintptr_t)certificates[0], (uintptr_t)payload);
    CHECK_EQ_INT(generation, lookup_generation);
    CHECK_EQ_INT(
        TLS_FIXER_WRAPPER_FOREIGN,
        tls_fixer_cert_registry_lookup_certificate(
            &registry,
            (const void *)(uintptr_t)UINT32_C(0xDEADBEEF),
            &payload,
            NULL));

    CHECK_EQ_INT(
        TLS_FIXER_CERT_REGISTRY_OK,
        tls_fixer_cert_registry_create_name(
            &registry,
            wrappers[0],
            (const void *)(uintptr_t)UINT32_C(0x3000),
            &name_wrapper));
    CHECK(name_wrapper != NULL);
    CHECK_EQ_INT(
        TLS_FIXER_WRAPPER_ACTIVE,
        tls_fixer_cert_registry_lookup_name(
            &registry,
            name_wrapper,
            &payload,
            &lookup_generation));
    CHECK_EQ_INT(UINT32_C(0x3000), (uintptr_t)payload);
    CHECK(lookup_generation != 0 && lookup_generation != generation);
    CHECK_EQ_INT(
        TLS_FIXER_CERT_REGISTRY_OK,
        tls_fixer_cert_registry_release_name(&registry, name_wrapper));
    CHECK_EQ_INT(
        TLS_FIXER_WRAPPER_STALE,
        tls_fixer_cert_registry_lookup_name(&registry, name_wrapper, &payload, NULL));
    CHECK_EQ_INT(
        TLS_FIXER_CERT_REGISTRY_STALE,
        tls_fixer_cert_registry_release_name(&registry, name_wrapper));

    CHECK_EQ_INT(TLS_FIXER_CERT_REGISTRY_OK,
        tls_fixer_cert_registry_create_name(&registry, wrappers[0],
            (const void *)(uintptr_t)UINT32_C(0x3100), &replacement_name_wrapper));
    CHECK(replacement_name_wrapper != name_wrapper);
    CHECK_EQ_INT(TLS_FIXER_CERT_REGISTRY_STALE,
        tls_fixer_cert_registry_release_name(&registry, name_wrapper));
    CHECK_EQ_INT(TLS_FIXER_CERT_REGISTRY_OK,
        tls_fixer_cert_registry_release_name(&registry, replacement_name_wrapper));

    tls_fixer_cert_registry_end(&registry, generation);
    CHECK_EQ_INT(
        TLS_FIXER_WRAPPER_STALE,
        tls_fixer_cert_registry_lookup_certificate(
            &registry,
            wrappers[0],
            &payload,
            NULL));
    CHECK_EQ_INT(
        TLS_FIXER_CERT_REGISTRY_STALE,
        tls_fixer_cert_registry_create_name(
            &registry,
            wrappers[0],
            (const void *)(uintptr_t)UINT32_C(0x4000),
            &name_wrapper));

    CHECK_EQ_INT(
        TLS_FIXER_CERT_REGISTRY_OK,
        tls_fixer_cert_registry_begin(
            &registry,
            &replacement_certificate,
            1,
            &replacement_wrapper,
            &replacement_generation));
    CHECK(replacement_wrapper != wrappers[0]);
    CHECK_EQ_INT(
        TLS_FIXER_WRAPPER_STALE,
        tls_fixer_cert_registry_lookup_certificate(
            &registry,
            wrappers[0],
            &payload,
            NULL));
    CHECK_EQ_INT(
        TLS_FIXER_WRAPPER_ACTIVE,
        tls_fixer_cert_registry_lookup_certificate(
            &registry,
            replacement_wrapper,
            &payload,
            NULL));
    CHECK_EQ_INT((uintptr_t)replacement_certificate, (uintptr_t)payload);
    CHECK_EQ_INT(
        TLS_FIXER_CERT_REGISTRY_OK,
        tls_fixer_cert_registry_create_name(
            &registry,
            replacement_wrapper,
            (const void *)(uintptr_t)UINT32_C(0x6000),
            &replacement_name_wrapper));
    CHECK(replacement_name_wrapper != name_wrapper);
    CHECK_EQ_INT(
        TLS_FIXER_WRAPPER_STALE,
        tls_fixer_cert_registry_lookup_name(
            &registry,
            name_wrapper,
            &payload,
            NULL));
    tls_fixer_cert_registry_end(&registry, replacement_generation);
    CHECK_EQ_INT(TLS_FIXER_WRAPPER_ACTIVE,
        tls_fixer_cert_registry_lookup_name(&registry, replacement_name_wrapper, &payload, NULL));
    CHECK_EQ_INT(TLS_FIXER_CERT_REGISTRY_BUSY, tls_fixer_cert_registry_destroy(&registry));
    CHECK_EQ_INT(TLS_FIXER_CERT_REGISTRY_OK,
        tls_fixer_cert_registry_release_name(&registry, replacement_name_wrapper));
    CHECK_EQ_INT(
        TLS_FIXER_CERT_REGISTRY_OK,
        tls_fixer_cert_registry_destroy(&registry));
}

static void test_certificate_wrapper_parallel_generations(void) {
    TlsFixerCertRegistry registry;
    RegistryTestContext context = {0};
    TlsFixerCertRegistryOps ops = cert_registry_test_ops(&context);
    const void *first_certificate = (const void *)(uintptr_t)UINT32_C(0x1000);
    const void *second_certificate = (const void *)(uintptr_t)UINT32_C(0x2000);
    void *first_wrapper = NULL;
    void *second_wrapper = NULL;
    const void *payload = NULL;
    uint32_t first_generation = 0;
    uint32_t second_generation = 0;

    CHECK_EQ_INT(
        TLS_FIXER_CERT_REGISTRY_OK,
        tls_fixer_cert_registry_init(&registry, &ops));
    CHECK_EQ_INT(
        TLS_FIXER_CERT_REGISTRY_OK,
        tls_fixer_cert_registry_begin(
            &registry,
            &first_certificate,
            1,
            &first_wrapper,
            &first_generation));
    CHECK_EQ_INT(
        TLS_FIXER_CERT_REGISTRY_OK,
        tls_fixer_cert_registry_begin(
            &registry,
            &second_certificate,
            1,
            &second_wrapper,
            &second_generation));
    CHECK(first_generation != second_generation);

    tls_fixer_cert_registry_end(&registry, first_generation);
    CHECK_EQ_INT(
        TLS_FIXER_WRAPPER_STALE,
        tls_fixer_cert_registry_lookup_certificate(
            &registry,
            first_wrapper,
            &payload,
            NULL));
    CHECK_EQ_INT(
        TLS_FIXER_WRAPPER_ACTIVE,
        tls_fixer_cert_registry_lookup_certificate(
            &registry,
            second_wrapper,
            &payload,
            NULL));
    CHECK_EQ_INT((uintptr_t)second_certificate, (uintptr_t)payload);
    CHECK_EQ_INT(
        TLS_FIXER_CERT_REGISTRY_BUSY,
        tls_fixer_cert_registry_destroy(&registry));
    tls_fixer_cert_registry_end(&registry, second_generation);
    CHECK_EQ_INT(
        TLS_FIXER_CERT_REGISTRY_OK,
        tls_fixer_cert_registry_destroy(&registry));
}

static void test_registry_basic(void) {
    TlsFixerRegistry registry;
    RegistryTestContext context = {0};
    TlsFixerRegistryOps ops = registry_test_ops(&context);
    TlsFixerRegistryHandle handle = {0};

    CHECK_EQ_INT(TLS_FIXER_REGISTRY_OK, tls_fixer_registry_init(&registry, &ops));
    CHECK_EQ_INT(
        TLS_FIXER_REGISTRY_INVALID_ARGUMENT,
        tls_fixer_registry_insert(&registry, 0, (void *)(uintptr_t)1));
    CHECK_EQ_INT(
        TLS_FIXER_REGISTRY_OK,
        tls_fixer_registry_insert(&registry, UINT32_C(0x1000), (void *)(uintptr_t)UINT32_C(0x2000)));
    CHECK_EQ_INT(1, tls_fixer_registry_count(&registry));
    CHECK_EQ_INT(
        TLS_FIXER_REGISTRY_DUPLICATE,
        tls_fixer_registry_insert(&registry, UINT32_C(0x1000), (void *)(uintptr_t)UINT32_C(0x3000)));
    CHECK_EQ_INT(
        TLS_FIXER_REGISTRY_OK,
        tls_fixer_registry_acquire(&registry, UINT32_C(0x1000), &handle));
    CHECK_EQ_INT(UINT32_C(0x2000), (uintptr_t)handle.payload);
    CHECK_EQ_INT(
        TLS_FIXER_REGISTRY_OK,
        tls_fixer_registry_remove(&registry, UINT32_C(0x1000)));
    CHECK_EQ_INT(1, tls_fixer_registry_count(&registry));
    CHECK_EQ_INT(0, context.cleanup_count);
    CHECK_EQ_INT(
        TLS_FIXER_REGISTRY_BUSY,
        tls_fixer_registry_acquire(&registry, UINT32_C(0x1000), &(TlsFixerRegistryHandle){0}));
    CHECK_EQ_INT(TLS_FIXER_REGISTRY_OK, tls_fixer_registry_release(&registry, &handle));
    CHECK_EQ_INT(1, context.cleanup_count);
    CHECK_EQ_INT(UINT32_C(0x2000), context.last_cleaned_payload);
    CHECK_EQ_INT(0, tls_fixer_registry_count(&registry));
    CHECK_EQ_INT(TLS_FIXER_REGISTRY_OK, tls_fixer_registry_destroy(&registry));
}

static void test_registry_generation_and_stale_handle(void) {
    TlsFixerRegistry registry;
    RegistryTestContext context = {0};
    TlsFixerRegistryOps ops = registry_test_ops(&context);
    TlsFixerRegistryHandle first = {0};
    TlsFixerRegistryHandle stale;
    TlsFixerRegistryHandle second = {0};

    CHECK_EQ_INT(TLS_FIXER_REGISTRY_OK, tls_fixer_registry_init(&registry, &ops));
    CHECK_EQ_INT(
        TLS_FIXER_REGISTRY_OK,
        tls_fixer_registry_insert(&registry, 1, (void *)(uintptr_t)11));
    CHECK_EQ_INT(TLS_FIXER_REGISTRY_OK, tls_fixer_registry_acquire(&registry, 1, &first));
    stale = first;
    CHECK_EQ_INT(TLS_FIXER_REGISTRY_OK, tls_fixer_registry_release(&registry, &first));
    CHECK_EQ_INT(TLS_FIXER_REGISTRY_OK, tls_fixer_registry_remove(&registry, 1));
    CHECK_EQ_INT(
        TLS_FIXER_REGISTRY_OK,
        tls_fixer_registry_insert(&registry, 2, (void *)(uintptr_t)22));
    CHECK_EQ_INT(TLS_FIXER_REGISTRY_OK, tls_fixer_registry_acquire(&registry, 2, &second));
    CHECK(second.generation != stale.generation);
    CHECK_EQ_INT(
        TLS_FIXER_REGISTRY_STALE_HANDLE,
        tls_fixer_registry_release(&registry, &stale));
    CHECK_EQ_INT(TLS_FIXER_REGISTRY_OK, tls_fixer_registry_release(&registry, &second));
    CHECK_EQ_INT(TLS_FIXER_REGISTRY_OK, tls_fixer_registry_remove(&registry, 2));
    CHECK_EQ_INT(2, context.cleanup_count);
    CHECK_EQ_INT(TLS_FIXER_REGISTRY_OK, tls_fixer_registry_destroy(&registry));
}

static void test_registry_replace(void) {
    TlsFixerRegistry registry;
    RegistryTestContext context = {0};
    TlsFixerRegistryOps ops = registry_test_ops(&context);
    TlsFixerRegistryHandle handle = {0};
    uint32_t first_generation;

    CHECK_EQ_INT(TLS_FIXER_REGISTRY_OK, tls_fixer_registry_init(&registry, &ops));
    CHECK_EQ_INT(
        TLS_FIXER_REGISTRY_NOT_FOUND,
        tls_fixer_registry_replace(&registry, 1, (void *)(uintptr_t)11));
    CHECK_EQ_INT(
        TLS_FIXER_REGISTRY_OK,
        tls_fixer_registry_insert(&registry, 1, (void *)(uintptr_t)11));
    CHECK_EQ_INT(TLS_FIXER_REGISTRY_OK, tls_fixer_registry_acquire(&registry, 1, &handle));
    first_generation = handle.generation;
    CHECK_EQ_INT(
        TLS_FIXER_REGISTRY_BUSY,
        tls_fixer_registry_replace(&registry, 1, (void *)(uintptr_t)22));
    CHECK_EQ_INT(TLS_FIXER_REGISTRY_OK, tls_fixer_registry_release(&registry, &handle));
    CHECK_EQ_INT(
        TLS_FIXER_REGISTRY_OK,
        tls_fixer_registry_replace(&registry, 1, (void *)(uintptr_t)22));
    CHECK_EQ_INT(1, context.cleanup_count);
    CHECK_EQ_INT(11, context.last_cleaned_payload);
    CHECK_EQ_INT(TLS_FIXER_REGISTRY_OK, tls_fixer_registry_acquire(&registry, 1, &handle));
    CHECK_EQ_INT(22, (uintptr_t)handle.payload);
    CHECK(handle.generation != first_generation);
    CHECK_EQ_INT(TLS_FIXER_REGISTRY_OK, tls_fixer_registry_release(&registry, &handle));
    CHECK_EQ_INT(TLS_FIXER_REGISTRY_OK, tls_fixer_registry_remove(&registry, 1));
    CHECK_EQ_INT(2, context.cleanup_count);
    CHECK_EQ_INT(TLS_FIXER_REGISTRY_OK, tls_fixer_registry_destroy(&registry));
}

static void test_registry_capacity(void) {
    TlsFixerRegistry registry;
    RegistryTestContext context = {0};
    TlsFixerRegistryOps ops = registry_test_ops(&context);
    size_t index;

    CHECK_EQ_INT(TLS_FIXER_REGISTRY_OK, tls_fixer_registry_init(&registry, &ops));
    for (index = 0; index < TLS_FIXER_REGISTRY_CAPACITY; ++index) {
        CHECK_EQ_INT(
            TLS_FIXER_REGISTRY_OK,
            tls_fixer_registry_insert(
                &registry,
                (uintptr_t)(index + 1),
                (void *)(uintptr_t)(index + 101)));
    }
    CHECK_EQ_INT(
        TLS_FIXER_REGISTRY_FULL,
        tls_fixer_registry_insert(&registry, UINT32_C(0xFFFF), (void *)(uintptr_t)1));
    CHECK_EQ_INT(TLS_FIXER_REGISTRY_CAPACITY, tls_fixer_registry_count(&registry));
    CHECK_EQ_INT(TLS_FIXER_REGISTRY_OK, tls_fixer_registry_destroy(&registry));
    CHECK_EQ_INT(TLS_FIXER_REGISTRY_CAPACITY, context.cleanup_count);
}

static void test_registry_stop_gate(void) {
    TlsFixerRegistry registry;
    RegistryTestContext context = {0};
    TlsFixerRegistryOps ops = registry_test_ops(&context);

    CHECK_EQ_INT(TLS_FIXER_REGISTRY_OK, tls_fixer_registry_init(&registry, &ops));
    CHECK_EQ_INT(
        TLS_FIXER_REGISTRY_OK,
        tls_fixer_registry_insert(&registry, 1, (void *)(uintptr_t)11));
    CHECK_EQ_INT(
        TLS_FIXER_REGISTRY_BUSY,
        tls_fixer_registry_begin_stop_if_empty(&registry));
    CHECK_EQ_INT(
        TLS_FIXER_REGISTRY_OK,
        tls_fixer_registry_insert(&registry, 2, (void *)(uintptr_t)22));
    CHECK_EQ_INT(TLS_FIXER_REGISTRY_OK, tls_fixer_registry_remove(&registry, 1));
    CHECK_EQ_INT(TLS_FIXER_REGISTRY_OK, tls_fixer_registry_remove(&registry, 2));
    CHECK_EQ_INT(
        TLS_FIXER_REGISTRY_OK,
        tls_fixer_registry_begin_stop_if_empty(&registry));
    CHECK_EQ_INT(
        TLS_FIXER_REGISTRY_BUSY,
        tls_fixer_registry_insert(&registry, 3, (void *)(uintptr_t)33));
    CHECK_EQ_INT(TLS_FIXER_REGISTRY_OK, tls_fixer_registry_destroy(&registry));
    CHECK_EQ_INT(2, context.cleanup_count);
}

static void test_registry_busy_destroy(void) {
    TlsFixerRegistry registry;
    RegistryTestContext context = {0};
    TlsFixerRegistryOps ops = registry_test_ops(&context);
    TlsFixerRegistryHandle handle = {0};

    CHECK_EQ_INT(TLS_FIXER_REGISTRY_OK, tls_fixer_registry_init(&registry, &ops));
    CHECK_EQ_INT(
        TLS_FIXER_REGISTRY_OK,
        tls_fixer_registry_insert(&registry, 7, (void *)(uintptr_t)77));
    CHECK_EQ_INT(TLS_FIXER_REGISTRY_OK, tls_fixer_registry_acquire(&registry, 7, &handle));
    CHECK_EQ_INT(TLS_FIXER_REGISTRY_BUSY, tls_fixer_registry_destroy(&registry));
    CHECK_EQ_INT(
        TLS_FIXER_REGISTRY_BUSY,
        tls_fixer_registry_insert(&registry, 8, (void *)(uintptr_t)88));
    CHECK_EQ_INT(TLS_FIXER_REGISTRY_OK, tls_fixer_registry_release(&registry, &handle));
    CHECK_EQ_INT(1, context.cleanup_count);
    CHECK_EQ_INT(TLS_FIXER_REGISTRY_OK, tls_fixer_registry_destroy(&registry));
}

int main(void) {
    test_path_helpers();
    test_sony_abi();
    test_error_map();
    test_module_gate();
    test_certificate_wrapper_registry();
    test_certificate_wrapper_parallel_generations();
    test_registry_basic();
    test_registry_generation_and_stale_handle();
    test_registry_replace();
    test_registry_capacity();
    test_registry_stop_gate();
    test_registry_busy_destroy();

    if (g_failures != 0) {
        fprintf(stderr, "%u of %u checks failed\n", g_failures, g_assertions);
        return EXIT_FAILURE;
    }

    printf("all %u checks passed\n", g_assertions);
    return EXIT_SUCCESS;
}
