#include "transport.h"

#include "cert_hooks.h"
#include "game_ca.h"
#include "diagnostics.h"
#include "provider.h"

#include <psp2/kernel/threadmgr/mutex.h>

#include <mbedtls/net_sockets.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>
#if defined(TLS_FIXER_MBEDTLS36)
#include <mbedtls/psa_util.h>
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#if TLS_FIXER_NATIVE_HELLO_EXPERIMENT || TLS_FIXER_NATIVE_HELLO_PROFILE
#include "../augment/native_hello_profile.h"
#endif
#if TLS_FIXER_EMBEDDED_HTTP
#include "../augment/embedded.h"
#endif

#define TLS_FIXER_MAX_HOSTNAME_LENGTH ((size_t)1024)

static void registry_lock(void *context) {
    const SceUID mutex = *(const SceUID *)context;
    (void)sceKernelLockMutex(mutex, 1, NULL);
}

static void registry_unlock(void *context) {
    const SceUID mutex = *(const SceUID *)context;
    (void)sceKernelUnlockMutex(mutex, 1);
}

static size_t bounded_string_length(const char *string, size_t maximum) {
    size_t length = 0;

    if (string == NULL) {
        return SIZE_MAX;
    }
    while (length < maximum && string[length] != '\0') {
        ++length;
    }
    if (length == maximum) {
        return SIZE_MAX;
    }
    return length;
}

static void connection_free(TlsFixerConnection *connection) {
    if (connection == NULL) {
        return;
    }

    if (connection->ssl_initialized) {
        mbedtls_ssl_free(&connection->ssl);
        connection->ssl_initialized = 0;
    }
    if (connection->config_initialized) {
        mbedtls_ssl_config_free(&connection->config);
        connection->config_initialized = 0;
    }
    if (connection->mutex_initialized) {
        (void)sceKernelDeleteMutex(connection->mutex);
        connection->mutex_initialized = 0;
    }
    free(connection->hostname);
    connection->hostname = NULL;
    mbedtls_platform_zeroize(connection, sizeof(*connection));
    free(connection);
}

void tls_fixer_transport_cleanup(void *context, void *payload) {
    (void)context;
    connection_free((TlsFixerConnection *)payload);
}

int tls_fixer_transport_global_init(void) {
    TlsFixerCertRegistryOps certificate_ops;
    TlsFixerRegistryOps registry_ops;
    int result;

    g_tls_fixer_http.registry_mutex = sceKernelCreateMutex(
        "tls_fixer registry",
        0,
        0,
        NULL);
    if (g_tls_fixer_http.registry_mutex < 0) {
        return g_tls_fixer_http.registry_mutex;
    }
    g_tls_fixer_http.registry_mutex_initialized = 1;

    registry_ops.lock = registry_lock;
    registry_ops.unlock = registry_unlock;
    registry_ops.cleanup = tls_fixer_transport_cleanup;
    registry_ops.context = &g_tls_fixer_http.registry_mutex;
    result = tls_fixer_registry_init(&g_tls_fixer_http.registry, &registry_ops);
    if (result != TLS_FIXER_REGISTRY_OK) {
        (void)sceKernelDeleteMutex(g_tls_fixer_http.registry_mutex);
        g_tls_fixer_http.registry_mutex_initialized = 0;
        return result;
    }

    certificate_ops.lock = registry_lock;
    certificate_ops.unlock = registry_unlock;
    certificate_ops.context = &g_tls_fixer_http.registry_mutex;
    result = tls_fixer_cert_registry_init(
        &g_tls_fixer_http.cert_registry,
        &certificate_ops);
    if (result != TLS_FIXER_CERT_REGISTRY_OK) {
        (void)tls_fixer_registry_destroy(&g_tls_fixer_http.registry);
        (void)sceKernelDeleteMutex(g_tls_fixer_http.registry_mutex);
        g_tls_fixer_http.registry_mutex_initialized = 0;
        return result;
    }

    result = tls_fixer_trust_store_init();
    if (result != 0) {
        (void)tls_fixer_cert_registry_destroy(&g_tls_fixer_http.cert_registry);
        tls_fixer_registry_destroy(&g_tls_fixer_http.registry);
        (void)sceKernelDeleteMutex(g_tls_fixer_http.registry_mutex);
        g_tls_fixer_http.registry_mutex_initialized = 0;
        return result;
    }

    return 0;
}

int tls_fixer_transport_global_destroy(void) {
    int result = TLS_FIXER_REGISTRY_OK;

    if (g_tls_fixer_http.registry.initialized) {
        result = tls_fixer_registry_destroy(&g_tls_fixer_http.registry);
        if (result == TLS_FIXER_REGISTRY_BUSY) {
            return result;
        }
    }

    if (g_tls_fixer_http.cert_registry.initialized) {
        result = tls_fixer_cert_registry_destroy(&g_tls_fixer_http.cert_registry);
        if (result == TLS_FIXER_CERT_REGISTRY_BUSY) {
            return result;
        }
    }

    tls_fixer_trust_store_free();
    if (g_tls_fixer_http.registry_mutex_initialized) {
        (void)sceKernelDeleteMutex(g_tls_fixer_http.registry_mutex);
        g_tls_fixer_http.registry_mutex_initialized = 0;
    }
    return result;
}

static uint32_t verification_flags_to_provider(uint32_t flags) {
    const uint32_t invalid_flags =
        MBEDTLS_X509_BADCERT_REVOKED |
        MBEDTLS_X509_BADCRL_EXPIRED |
        MBEDTLS_X509_BADCERT_MISSING |
        MBEDTLS_X509_BADCERT_SKIP_VERIFY |
        MBEDTLS_X509_BADCERT_OTHER |
        MBEDTLS_X509_BADCRL_FUTURE |
        MBEDTLS_X509_BADCERT_KEY_USAGE |
        MBEDTLS_X509_BADCERT_EXT_KEY_USAGE |
        MBEDTLS_X509_BADCERT_NS_CERT_TYPE |
        MBEDTLS_X509_BADCERT_BAD_MD |
        MBEDTLS_X509_BADCERT_BAD_PK |
        MBEDTLS_X509_BADCERT_BAD_KEY |
        MBEDTLS_X509_BADCRL_BAD_MD |
        MBEDTLS_X509_BADCRL_BAD_PK |
        MBEDTLS_X509_BADCRL_BAD_KEY;
    uint32_t provider = 0;

    if ((flags & invalid_flags) != 0) {
        provider |= TLS_FIXER_CERT_INVALID;
    }
    if ((flags & MBEDTLS_X509_BADCERT_CN_MISMATCH) != 0) {
        provider |= TLS_FIXER_CERT_HOSTNAME;
    }
    if ((flags & MBEDTLS_X509_BADCERT_EXPIRED) != 0) {
        provider |= TLS_FIXER_CERT_EXPIRED;
    }
    if ((flags & MBEDTLS_X509_BADCERT_FUTURE) != 0) {
        provider |= TLS_FIXER_CERT_FUTURE;
    }
    if ((flags & (MBEDTLS_X509_BADCERT_NOT_TRUSTED | MBEDTLS_X509_BADCRL_NOT_TRUSTED)) != 0) {
        provider |= TLS_FIXER_CERT_UNKNOWN_CA;
    }
    if (flags != 0 && provider == 0) {
        provider = TLS_FIXER_CERT_INTERNAL;
    }
    return provider;
}

static int store_outcome(
    TlsFixerConnection *connection,
    TlsFixerOutcome outcome,
    uint32_t detail) {
    TlsFixerMappedError mapped = tls_fixer_map_outcome(outcome, detail);
    TLS_FIXER_LOG("event=error.map connection=%08X state=%d outcome=%d detail=%08X "
        "sony_rc=%08X ssl=%08X ssl_detail=%08X", (unsigned int)(uintptr_t)connection->sony_connection,
        connection->state, outcome, detail, mapped.hook_result, mapped.ssl_error, mapped.detail);

    if (mapped.ssl_error != 0) {
        tls_fixer_store_ssl_error(
            connection->sony_connection,
            mapped.ssl_error,
            mapped.detail);
    }
    return mapped.hook_result;
}

static int store_handshake_wait(
    TlsFixerConnection *connection,
    const void *request,
    TlsFixerOutcome want_outcome) {
    if (connection->last_net_error == TLS_FIXER_SCE_NET_ERROR_EAGAIN &&
        !tls_fixer_request_is_nonblocking(request)) {
        return store_outcome(
            connection,
            TLS_FIXER_OUTCOME_TIMEOUT,
            (uint32_t)connection->last_net_error);
    }
    return store_outcome(connection, want_outcome, 0);
}

/* Bundle roots plus any CA certificates the game loaded with sceHttpsLoadCert */
static int find_trusted_issuers(void *context, const mbedtls_x509_crt *child,
    mbedtls_x509_crt **candidates) {
    const TlsFixerConnection *connection = context;
    int result = (connection->https_options & TLS_FIXER_SCE_HTTPS_OPTION_PRIVATE_SONY_CA) != 0
        ? tls_fixer_ca_index_find_sony(&g_tls_fixer_http.ca_index, child, candidates)
        : tls_fixer_ca_index_find(&g_tls_fixer_http.ca_index, child, candidates);
    if (result != 0) return result;
    return tls_fixer_game_ca_find(child, candidates);
}

/* Called by Mbed TLS for each certificate it checked: a self-signed server certificate that is
 * itself in the store, or among the game's certificates, counts as trusted; its other checks
 * (host name, dates, signature strength) still apply */
static int trust_exact_self_signed(void *context, mbedtls_x509_crt *certificate, int depth,
    uint32_t *flags) {
    if (depth == 0 && (*flags & MBEDTLS_X509_BADCERT_NOT_TRUSTED) != 0 &&
        tls_fixer_ca_trusts_exact(find_trusted_issuers, context, certificate)) {
        *flags &= ~(uint32_t)MBEDTLS_X509_BADCERT_NOT_TRUSTED;
    }
    return 0;
}

static int setup_connection(TlsFixerConnection *connection, const char *hostname) {
    size_t hostname_length;
    int result;
    mbedtls_ssl_protocol_version maximum_version = MBEDTLS_SSL_VERSION_TLS1_3;

    hostname_length = bounded_string_length(hostname, TLS_FIXER_MAX_HOSTNAME_LENGTH);
    TLS_FIXER_LOG("event=connection.setup connection=%08X socket=%d hostname_length=%u options=%08X raw_options=%08X",
        (unsigned int)(uintptr_t)connection->sony_connection, connection->socket,
        (unsigned int)hostname_length, connection->https_options,
        tls_fixer_read_u32(connection->sony_connection, TLS_FIXER_CONNECTION_HTTPS_OPTIONS_OFFSET));
    if (hostname_length == SIZE_MAX || hostname_length == 0) {
        return -1;
    }

    connection->hostname = malloc(hostname_length + 1);
    if (connection->hostname == NULL) {
        return TLS_FIXER_SCE_HTTP_ERROR_OUT_OF_MEMORY;
    }
    memcpy(connection->hostname, hostname, hostname_length + 1);
#if defined(TLS_FIXER_DIAGNOSTIC_LOWERCASE_SNI)
    for (size_t i = 0; i < hostname_length; ++i) {
        unsigned char c = (unsigned char)connection->hostname[i];
        if (c >= 'A' && c <= 'Z') connection->hostname[i] = (char)(c + ('a' - 'A'));
    }
#endif

    connection->mutex = sceKernelCreateMutex("tls_fixer connection", 0, 0, NULL);
    TLS_FIXER_LOG("event=connection.mutex rc=%08X", connection->mutex);
    if (connection->mutex < 0) {
        return connection->mutex;
    }
    connection->mutex_initialized = 1;

    mbedtls_ssl_init(&connection->ssl);
    connection->ssl_initialized = 1;
    mbedtls_ssl_config_init(&connection->config);
    connection->config_initialized = 1;

    result = mbedtls_ssl_config_defaults(
        &connection->config,
        MBEDTLS_SSL_IS_CLIENT,
        MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT);
#if defined(TLS_FIXER_MBEDTLS36)
    mbedtls_ssl_conf_rng(&connection->config, mbedtls_psa_get_random, MBEDTLS_PSA_RANDOM_STATE);
#endif
    TLS_FIXER_LOG("event=tls.defaults rc=%08X", result);
    if (result != 0) {
        return result;
    }

    connection->certificate_profile = mbedtls_x509_crt_profile_default;
    /* System endpoints such as native-vita.np.ac.playstation.net require
     * SHA-1 certificate signatures. */
    connection->certificate_profile.allowed_mds |= MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA1);
#if defined(TLS_FIXER_DIAGNOSTIC_AUTH_TLS12)
    if (strcmp(hostname, "IV0001-NPXS01001-00.auth.np.ac.playstation.net") == 0)
        maximum_version = MBEDTLS_SSL_VERSION_TLS1_2;
#endif
#if defined(TLS_FIXER_DIAGNOSTIC_AUTH_RSA)
    if (strcmp(hostname, "IV0001-NPXS01001-00.auth.np.ac.playstation.net") == 0) {
        static const int native_auth_suite[] = {MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA256, 0};
        mbedtls_ssl_conf_ciphersuites(&connection->config, native_auth_suite);
    }
#endif
    mbedtls_ssl_conf_cert_profile(&connection->config, &connection->certificate_profile);
    mbedtls_ssl_conf_min_tls_version(
        &connection->config,
        MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_max_tls_version(
        &connection->config,
        maximum_version);
#if TLS_FIXER_NATIVE_HELLO_EXPERIMENT || TLS_FIXER_NATIVE_HELLO_PROFILE
    if (connection->native_hello_profile
#if TLS_FIXER_NATIVE_HELLO_EXPERIMENT
        || strcmp(hostname, "IV0001-NPXS01001-00.auth.np.ac.playstation.net") == 0
#endif
    ) {
        result = tls_fixer_native_hello_profile(&connection->config);
        if (result != 0) return result;
        maximum_version = MBEDTLS_SSL_VERSION_TLS1_2;
        TLS_FIXER_LOG("event=tls.native_profile configured=1");
    }
#endif
    mbedtls_ssl_conf_authmode(&connection->config, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ca_cb(&connection->config, find_trusted_issuers, connection);
    mbedtls_ssl_conf_verify(&connection->config, trust_exact_self_signed, connection);

    result = mbedtls_ssl_setup(&connection->ssl, &connection->config);
    TLS_FIXER_LOG("event=tls.setup rc=%08X min=TLS1.2 max=%s", result,
        maximum_version == MBEDTLS_SSL_VERSION_TLS1_2 ? "TLS1.2" : "TLS1.3");
    if (result != 0) {
        return result;
    }
    result = mbedtls_ssl_set_hostname(&connection->ssl, connection->hostname);
    TLS_FIXER_LOG("event=tls.hostname rc=%08X hostname_length=%u hostname=%s", result,
        (unsigned int)hostname_length, connection->hostname);
    if (result != 0) {
        return result;
    }

    mbedtls_ssl_set_bio(
        &connection->ssl,
        connection,
        tls_fixer_vita_send,
        tls_fixer_vita_recv,
        NULL);
    return 0;
}

static int complete_verification(
    TlsFixerConnection *connection,
    uint32_t verify_flags) {
    uint32_t provider_flags = tls_fixer_filter_certificate_flags(
        verification_flags_to_provider(verify_flags),
        connection->https_options);
    uint32_t verification_detail = tls_fixer_map_certificate_detail(provider_flags);
    const mbedtls_x509_crt *peer_chain = mbedtls_ssl_get_peer_cert(&connection->ssl);
    int accepted = 0;
    int result = tls_fixer_cert_callback_decide(
        connection->sony_connection,
        peer_chain,
        verification_detail,
        &accepted);
    TLS_FIXER_LOG("event=certificate.decision connection=%08X verify=%08X filtered=%08X "
        "detail=%08X callback_rc=%08X accepted=%d peer_present=%d",
        (unsigned int)(uintptr_t)connection->sony_connection, verify_flags, provider_flags,
        verification_detail, result, accepted, peer_chain != NULL);

    if (result != 0) {
        connection->state = TLS_FIXER_CONNECTION_FAILED;
        TLS_FIXER_LOG(
            "certificate callback bridge failed: connection=0x%08X result=0x%08X",
            (unsigned int)(uintptr_t)connection->sony_connection,
            result);
        return store_outcome(
            connection,
            TLS_FIXER_OUTCOME_INTERNAL,
            (uint32_t)result);
    }
    if (!accepted) {
        connection->state = TLS_FIXER_CONNECTION_FAILED;
        TLS_FIXER_LOG(
            "certificate rejected: connection=0x%08X detail=0x%02X verify=0x%08X",
            (unsigned int)(uintptr_t)connection->sony_connection,
            verification_detail,
            verify_flags);
        return store_outcome(
            connection,
            TLS_FIXER_OUTCOME_CERTIFICATE,
            provider_flags);
    }

    connection->state = TLS_FIXER_CONNECTION_ACTIVE;
    tls_fixer_store_ssl_error(connection->sony_connection, 0, 0);
    TLS_FIXER_LOG(
        "handshake complete: connection=0x%08X version=%s cipher=%s",
        (unsigned int)(uintptr_t)connection->sony_connection,
        mbedtls_ssl_get_version(&connection->ssl),
        mbedtls_ssl_get_ciphersuite(&connection->ssl));
    return 0;
}

static int acquire_connection(
    void *sony_connection,
    TlsFixerRegistryHandle *handle,
    TlsFixerConnection **connection,
    int *handled) {
    int result;

    *connection = NULL;
    *handled = 0;
    result = tls_fixer_registry_acquire(
        &g_tls_fixer_http.registry,
        (uintptr_t)sony_connection,
        handle);
    TLS_FIXER_LOG("event=registry.acquire connection=%08X rc=%08X",
        (unsigned int)(uintptr_t)sony_connection, result);
    if (result == TLS_FIXER_REGISTRY_NOT_FOUND || result == TLS_FIXER_REGISTRY_NOT_INITIALIZED) {
        return 0;
    }
    *handled = 1;
    if (result != TLS_FIXER_REGISTRY_OK) {
        return TLS_FIXER_SCE_HTTP_ERROR_SSL;
    }
    *connection = (TlsFixerConnection *)handle->payload;
    /* Reentrant callbacks must neither deadlock nor switch an owned connection to BSAFE. */
    result = sceKernelTryLockMutex((*connection)->mutex, 1);
    TLS_FIXER_LOG("event=connection.lock connection=%08X rc=%08X",
        (unsigned int)(uintptr_t)sony_connection, result);
    if (result < 0) {
        tls_fixer_registry_release(&g_tls_fixer_http.registry, handle);
        *connection = NULL;
        return TLS_FIXER_SCE_HTTP_ERROR_EAGAIN;
    }
    return TLS_FIXER_REGISTRY_OK;
}

static void release_connection(
    TlsFixerRegistryHandle *handle,
    TlsFixerConnection *connection) {
    (void)sceKernelUnlockMutex(connection->mutex, 1);
    tls_fixer_registry_release(&g_tls_fixer_http.registry, handle);
}

int tls_fixer_transport_create(void *request, int socket, int *handled) {
    TlsFixerConnection *connection;
    void *sony_connection;
    const char *hostname;
    int result;
    int already_owned = 0;
    TlsFixerRegistryHandle previous;

    if (handled == NULL) {
        return TLS_FIXER_SCE_HTTP_ERROR_SSL;
    }
    *handled = 0;
    if (request == NULL) {
        *handled = 1;
        return TLS_FIXER_SCE_HTTP_ERROR_INVALID_VALUE;
    }
    sony_connection = tls_fixer_resolve_connection(request);
    if (sony_connection != NULL) {
        result = tls_fixer_registry_acquire(&g_tls_fixer_http.registry,
                                        (uintptr_t)sony_connection, &previous);
        if (result == TLS_FIXER_REGISTRY_BUSY) {
            *handled = 1;
            return TLS_FIXER_SCE_HTTP_ERROR_SSL;
        }
        if (result == TLS_FIXER_REGISTRY_OK) {
            already_owned = 1;
            *handled = 1;
            (void)tls_fixer_registry_release(&g_tls_fixer_http.registry, &previous);
        }
    }
    if (g_tls_fixer_http.state != TLS_FIXER_PROVIDER_ACTIVE) {
        TLS_FIXER_LOG("event=connection.skip reason=provider_inactive state=%d owned=%d",
            g_tls_fixer_http.state, already_owned);
        return already_owned ? TLS_FIXER_SCE_HTTP_ERROR_SSL : 0;
    }
    if (tls_fixer_legacy_certificates_loaded()) {
        TLS_FIXER_LOG("legacy certificate material active; using BSAFE");
        return already_owned ? TLS_FIXER_SCE_HTTP_ERROR_SSL : 0;
    }
    result = tls_fixer_cert_hooks_ensure_ssl();
    if (result < 0) {
        TLS_FIXER_LOG("event=connection.skip reason=certificate_hooks_unavailable rc=%08X owned=%d",
            result, already_owned);
        return already_owned ? TLS_FIXER_SCE_HTTP_ERROR_SSL : 0;
    }

    sony_connection = tls_fixer_resolve_connection(request);
    if (sony_connection == NULL || socket < 0) {
        TLS_FIXER_LOG("event=connection.skip reason=invalid_connection connection=%08X socket=%d owned=%d",
            (unsigned int)(uintptr_t)sony_connection, socket, already_owned);
        return already_owned ? TLS_FIXER_SCE_HTTP_ERROR_SSL : 0;
    }
    hostname = tls_fixer_connection_hostname(sony_connection);

    int native_profile = 0;
#if TLS_FIXER_EMBEDDED_HTTP && TLS_FIXER_NATIVE_HELLO_PROFILE
    native_profile = tls_fixer_embedded_profile_for_request(request);
    if (native_profile < 0) {
        TLS_FIXER_LOG("event=connection.skip reason=unknown_private_profile");
        return already_owned ? TLS_FIXER_SCE_HTTP_ERROR_SSL : 0;
    }
#endif

    connection = calloc(1, sizeof(*connection));
    if (connection == NULL) {
        TLS_FIXER_LOG("event=connection.skip reason=allocation_failed bytes=%u owned=%d",
            (unsigned int)sizeof(*connection), already_owned);
        return already_owned ? TLS_FIXER_SCE_HTTP_ERROR_OUT_OF_MEMORY : 0;
    }
    connection->sony_connection = sony_connection;
    connection->socket = socket;
    connection->state = TLS_FIXER_CONNECTION_INITIALIZING;
    connection->native_hello_profile = native_profile != 0;
    connection->https_options = tls_fixer_connection_effective_https_options(
        sony_connection,
        tls_fixer_read_u32(
            (const void *)g_tls_fixer_http.global_https_options_address,
            0));

    result = setup_connection(connection, hostname);
    if (result != 0) {
        TLS_FIXER_LOG(
            "connection setup failed: connection=0x%08X result=0x%08X",
            (unsigned int)(uintptr_t)sony_connection,
            result);
        connection_free(connection);
        return already_owned ? TLS_FIXER_SCE_HTTP_ERROR_SSL : 0;
    }

    connection->state = TLS_FIXER_CONNECTION_HANDSHAKING;
    result = tls_fixer_registry_insert(
        &g_tls_fixer_http.registry,
        (uintptr_t)sony_connection,
        connection);
    if (result == TLS_FIXER_REGISTRY_DUPLICATE) {
        result = tls_fixer_registry_replace(
            &g_tls_fixer_http.registry,
            (uintptr_t)sony_connection,
            connection);
    }
    if (result != TLS_FIXER_REGISTRY_OK) {
        TLS_FIXER_LOG(
            "connection registry failed: connection=0x%08X result=0x%08X",
            (unsigned int)(uintptr_t)sony_connection,
            result);
        connection_free(connection);
        if (result == TLS_FIXER_REGISTRY_BUSY || result == TLS_FIXER_REGISTRY_DUPLICATE) {
            *handled = 1;
            tls_fixer_store_ssl_error(
                sony_connection,
                TLS_FIXER_SCE_HTTPS_ERROR_INTERNAL,
                (uint32_t)result);
            return TLS_FIXER_SCE_HTTP_ERROR_SSL;
        }
        return already_owned ? TLS_FIXER_SCE_HTTP_ERROR_SSL : 0;
    }

    *handled = 1;
    tls_fixer_store_ssl_error(sony_connection, 0, 0);
    TLS_FIXER_LOG(
        "connection created: connection=0x%08X socket=%d options=0x%03X",
        (unsigned int)(uintptr_t)sony_connection,
        socket,
        connection->https_options);
    return 0;
}

int tls_fixer_transport_connect(void *request, int *handled) {
    TlsFixerRegistryHandle handle;
    TlsFixerConnection *connection;
    void *sony_connection;
    uint32_t verify_flags;
    int result;
    int mapped_result;

    if (handled == NULL) {
        return TLS_FIXER_SCE_HTTP_ERROR_SSL;
    }
    *handled = 0;
    sony_connection = tls_fixer_resolve_connection(request);
    if (sony_connection == NULL) {
        return 0;
    }
    result = acquire_connection(sony_connection, &handle, &connection, handled);
    if (result != 0 || !*handled) {
        return result;
    }

    if (connection->state == TLS_FIXER_CONNECTION_ACTIVE) {
        release_connection(&handle, connection);
        return 0;
    }
    if (connection->state == TLS_FIXER_CONNECTION_FAILED ||
        connection->state == TLS_FIXER_CONNECTION_CLOSING) {
        mapped_result = TLS_FIXER_SCE_HTTP_ERROR_SSL;
        release_connection(&handle, connection);
        return mapped_result;
    }

    connection->last_net_error = 0;
    TLS_FIXER_LOG("event=handshake.enter connection=%08X socket=%d state=%d",
        (unsigned int)(uintptr_t)sony_connection, connection->socket, connection->state);
    result = mbedtls_ssl_handshake(&connection->ssl);
    TLS_FIXER_LOG("event=handshake.return connection=%08X tls_rc=%08X net_rc=%08X",
        (unsigned int)(uintptr_t)sony_connection, result, connection->last_net_error);
    connection->last_tls_error = result;
    if (result == MBEDTLS_ERR_SSL_WANT_READ) {
        mapped_result = store_handshake_wait(
            connection,
            request,
            TLS_FIXER_OUTCOME_WANT_READ);
    } else if (result == MBEDTLS_ERR_SSL_WANT_WRITE) {
        mapped_result = store_handshake_wait(
            connection,
            request,
            TLS_FIXER_OUTCOME_WANT_WRITE);
    } else if (result == MBEDTLS_ERR_SSL_TIMEOUT) {
        mapped_result = store_outcome(
            connection,
            TLS_FIXER_OUTCOME_TIMEOUT,
            (uint32_t)connection->last_net_error);
    } else if (result != 0) {
        verify_flags = mbedtls_ssl_get_verify_result(&connection->ssl);
        connection->last_verify_flags = verify_flags;
        connection->state = TLS_FIXER_CONNECTION_FAILED;
        if (result == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED ||
            (verify_flags != UINT32_MAX && verify_flags != 0)) {
            const uint32_t provider_flags = tls_fixer_filter_certificate_flags(
                verification_flags_to_provider(verify_flags),
                connection->https_options);
            mapped_result = store_outcome(
                connection,
                TLS_FIXER_OUTCOME_CERTIFICATE,
                provider_flags);
        } else {
            mapped_result = store_outcome(
                connection,
                TLS_FIXER_OUTCOME_HANDSHAKE,
                (uint32_t)result);
        }
        TLS_FIXER_LOG(
            "handshake failed: connection=0x%08X tls=0x%08X net=0x%08X verify=0x%08X",
            (unsigned int)(uintptr_t)sony_connection,
            result,
            connection->last_net_error,
            verify_flags);
    } else {
        verify_flags = mbedtls_ssl_get_verify_result(&connection->ssl);
        connection->last_verify_flags = verify_flags;
        mapped_result = complete_verification(connection, verify_flags);
    }

    release_connection(&handle, connection);
    return mapped_result;
}

int tls_fixer_transport_map_io(void *connection, int result, int *handled) {
    TlsFixerRegistryHandle handle;
    TlsFixerConnection *provider_connection;
    int acquired;

    if (handled == NULL) {
        return TLS_FIXER_SCE_HTTPS_ERROR_INTERNAL;
    }
    *handled = 0;
    acquired = acquire_connection(connection, &handle, &provider_connection, handled);
    if (acquired != 0 || !*handled) {
        return acquired;
    }
    *handled = 1;
    release_connection(&handle, provider_connection);

    if (result >= 0) {
        return 0;
    }
    if (result == TLS_FIXER_SCE_HTTP_ERROR_EAGAIN) {
        return TLS_FIXER_SCE_HTTPS_INTERNAL_RETRY;
    }
    return result;
}

static int map_io_result(TlsFixerConnection *connection, int result, int is_read) {
    if (result > 0) {
        return result;
    }
    if (result == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
        return 0;
    }
    if (result == 0) {
        connection->state = TLS_FIXER_CONNECTION_FAILED;
        return store_outcome(connection, TLS_FIXER_OUTCOME_EOF, 0);
    }
    if (result == MBEDTLS_ERR_SSL_WANT_READ) {
        return store_outcome(connection, TLS_FIXER_OUTCOME_WANT_READ, 0);
    }
    if (result == MBEDTLS_ERR_SSL_WANT_WRITE) {
        return store_outcome(connection, TLS_FIXER_OUTCOME_WANT_WRITE, 0);
    }
    if (result == MBEDTLS_ERR_SSL_TIMEOUT) {
        return store_outcome(
            connection,
            TLS_FIXER_OUTCOME_TIMEOUT,
            (uint32_t)connection->last_net_error);
    }

    connection->state = TLS_FIXER_CONNECTION_FAILED;
    return store_outcome(
        connection,
        TLS_FIXER_OUTCOME_IO,
        connection->last_net_error != 0
            ? (uint32_t)connection->last_net_error
            : ((uint32_t)result | (is_read ? UINT32_C(0x00000000) : UINT32_C(0x80000000))));
}

int tls_fixer_transport_read(
    void *sony_connection,
    void *buffer,
    unsigned int length,
    int *handled) {
    TlsFixerRegistryHandle handle;
    TlsFixerConnection *connection;
    size_t requested = length;
    int result;
    unsigned int ticket_budget = 16;

    if (handled == NULL) {
        return TLS_FIXER_SCE_HTTP_ERROR_SSL;
    }
    *handled = 0;
    result = acquire_connection(sony_connection, &handle, &connection, handled);
    if (result != 0 || !*handled) {
        return result;
    }
    *handled = 1;
    if (connection->state != TLS_FIXER_CONNECTION_ACTIVE) {
        release_connection(&handle, connection);
        return TLS_FIXER_SCE_HTTP_ERROR_SSL;
    }
    if (length == 0) {
        release_connection(&handle, connection);
        return 0;
    }
    if (connection->pending_write_length != 0) {
        release_connection(&handle, connection);
        return TLS_FIXER_SCE_HTTP_ERROR_EAGAIN;
    }
    if (buffer == NULL) {
        tls_fixer_store_ssl_error(
            connection->sony_connection,
            TLS_FIXER_SCE_HTTPS_ERROR_INTERNAL,
            TLS_FIXER_SCE_HTTPS_DETAIL_INTERNAL);
        release_connection(&handle, connection);
        return TLS_FIXER_SCE_HTTP_ERROR_INVALID_VALUE;
    }
    if (requested > TLS_FIXER_MAX_IO_CHUNK) {
        requested = TLS_FIXER_MAX_IO_CHUNK;
    }

    connection->last_net_error = 0;
    do {
        result = mbedtls_ssl_read(&connection->ssl, buffer, requested);
        TLS_FIXER_LOG("event=tls.read.return connection=%08X tls_rc=%08X net_rc=%08X budget=%u",
            (unsigned int)(uintptr_t)sony_connection, result, connection->last_net_error,
            ticket_budget);
        /* Mbed TLS may consume a post-handshake record and yield WANT_READ without
         * a socket error. Sony's blocking read treats EAGAIN as a timeout, so keep
         * processing these records here. Actual socket waits retain their error. */
    } while ((result == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET ||
              (result == MBEDTLS_ERR_SSL_WANT_READ && connection->last_net_error == 0)) &&
             --ticket_budget != 0);
    if (result == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) {
        result = MBEDTLS_ERR_SSL_WANT_READ;
    }
    connection->last_tls_error = result < 0 ? result : 0;
    result = map_io_result(connection, result, 1);
    if (result < 0 && result != TLS_FIXER_SCE_HTTP_ERROR_EAGAIN &&
        result != TLS_FIXER_SCE_HTTP_ERROR_TIMEOUT) {
        TLS_FIXER_LOG(
            "read failed: connection=0x%08X tls=0x%08X net=0x%08X sony=0x%08X",
            (unsigned int)(uintptr_t)sony_connection,
            connection->last_tls_error,
            connection->last_net_error,
            result);
    }
    release_connection(&handle, connection);
    return result;
}

int tls_fixer_transport_write(
    void *sony_connection,
    const void *buffer,
    unsigned int length,
    int *handled) {
    TlsFixerRegistryHandle handle;
    TlsFixerConnection *connection;
    size_t requested = length;
    int result;

    if (handled == NULL) {
        return TLS_FIXER_SCE_HTTP_ERROR_SSL;
    }
    *handled = 0;
    result = acquire_connection(sony_connection, &handle, &connection, handled);
    if (result != 0 || !*handled) {
        return result;
    }
    *handled = 1;
    if (connection->state != TLS_FIXER_CONNECTION_ACTIVE) {
        release_connection(&handle, connection);
        return TLS_FIXER_SCE_HTTP_ERROR_SSL;
    }
    if (length == 0) {
        release_connection(&handle, connection);
        return 0;
    }
    if (buffer == NULL) {
        tls_fixer_store_ssl_error(
            connection->sony_connection,
            TLS_FIXER_SCE_HTTPS_ERROR_INTERNAL,
            TLS_FIXER_SCE_HTTPS_DETAIL_INTERNAL);
        release_connection(&handle, connection);
        return TLS_FIXER_SCE_HTTP_ERROR_INVALID_VALUE;
    }
    if (requested > TLS_FIXER_MAX_IO_CHUNK) {
        requested = TLS_FIXER_MAX_IO_CHUNK;
    }

    /* Mbed TLS requires stable write arguments while a record is awaiting a retry. */
    if (connection->pending_write_length != 0 &&
        (connection->pending_write_length != requested ||
         memcmp(connection->pending_write, buffer, requested) != 0)) {
        connection->state = TLS_FIXER_CONNECTION_FAILED;
        connection->pending_write_length = 0;
        mbedtls_platform_zeroize(connection->pending_write, sizeof(connection->pending_write));
        result = store_outcome(connection, TLS_FIXER_OUTCOME_IO,
                               (uint32_t)MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
        release_connection(&handle, connection);
        return result;
    }
    if (connection->pending_write_length == 0) {
        memcpy(connection->pending_write, buffer, requested);
        connection->pending_write_length = requested;
    }

    connection->last_net_error = 0;
    result = mbedtls_ssl_write(&connection->ssl, connection->pending_write,
                               connection->pending_write_length);
    if (result != MBEDTLS_ERR_SSL_WANT_READ && result != MBEDTLS_ERR_SSL_WANT_WRITE &&
        result != MBEDTLS_ERR_SSL_TIMEOUT) {
        connection->pending_write_length = 0;
        mbedtls_platform_zeroize(connection->pending_write, sizeof(connection->pending_write));
    }
    connection->last_tls_error = result < 0 ? result : 0;
    result = map_io_result(connection, result, 0);
    if (result < 0 && result != TLS_FIXER_SCE_HTTP_ERROR_EAGAIN &&
        result != TLS_FIXER_SCE_HTTP_ERROR_TIMEOUT) {
        TLS_FIXER_LOG(
            "write failed: connection=0x%08X tls=0x%08X net=0x%08X sony=0x%08X",
            (unsigned int)(uintptr_t)sony_connection,
            connection->last_tls_error,
            connection->last_net_error,
            result);
    }
    release_connection(&handle, connection);
    return result;
}

int tls_fixer_transport_shutdown(void *sony_connection, int *handled) {
    TlsFixerRegistryHandle handle;
    TlsFixerConnection *connection;
    int result;
    int send_close_notify;

    if (handled == NULL) {
        return TLS_FIXER_SCE_HTTP_ERROR_SSL;
    }
    *handled = 0;
    result = acquire_connection(sony_connection, &handle, &connection, handled);
    if (result != 0 || !*handled) {
        return result;
    }
    *handled = 1;

    if (connection->state == TLS_FIXER_CONNECTION_CLOSING) {
        release_connection(&handle, connection);
        return 0;
    }
    send_close_notify = connection->state == TLS_FIXER_CONNECTION_ACTIVE &&
                        connection->pending_write_length == 0;
    connection->state = TLS_FIXER_CONNECTION_CLOSING;

    result = tls_fixer_registry_remove(
        &g_tls_fixer_http.registry,
        (uintptr_t)sony_connection);
    if (result != TLS_FIXER_REGISTRY_OK) {
        release_connection(&handle, connection);
        return TLS_FIXER_SCE_HTTP_ERROR_SSL;
    }

    if (send_close_notify) {
        (void)mbedtls_ssl_close_notify(&connection->ssl);
    }
    TLS_FIXER_LOG(
        "connection shutdown: connection=0x%08X",
        (unsigned int)(uintptr_t)sony_connection);
    release_connection(&handle, connection);
    return 0;
}
