#include "backend.h"
#include "runtime_udp.h"
#include "tls_fixer/browser_start_diagnostics.h"
#include "ca_file.h"
#include "crypto_platform.h"
#include "diagnostics.h"
#include "tls_fixer/registry.h"
#include "tls_fixer/sony_abi.h"

#include <psp2/kernel/threadmgr/mutex.h>
#include <psp2/net/net.h>
#include <psp2common/net.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/ssl.h>
#include <psa/crypto.h>
#include <psa/crypto_extra.h>

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#if MBEDTLS_VERSION_NUMBER != 0x04020000
#error "The browser provider requires the pinned Mbed TLS 4.2.0 source configuration"
#endif

#define BROWSER_IO_CHUNK 1500
#define BROWSER_POLL_SLICE_MS 50

enum BrowserState { BROWSER_INITIALIZING, BROWSER_HANDSHAKING, BROWSER_ACTIVE,
    BROWSER_EOF, BROWSER_FAILED };

enum DefaultCaState { DEFAULT_CA_UNINITIALIZED, DEFAULT_CA_READY, DEFAULT_CA_FAILED };

typedef struct BrowserConnection {
    void *native;
    int index;
    int socket;
    SceUID mutex;
    uint32_t closing;
    enum BrowserState state;
    int error;
    int net_error;
    int want;
    unsigned int pending_length;
    uint32_t old_recv;
    uint32_t old_send;
    uint8_t verify_peer;
    uint8_t verify_host;
    uint8_t custom_ca_requested;
    uint8_t custom_ca_initialized;
    uint8_t notifying_close;
    uint8_t lookahead_valid;
    unsigned char lookahead;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config config;
    mbedtls_x509_crt_profile certificate_profile;
    mbedtls_x509_crt custom_ca;
    int ciphers[8];
    char hostname[1024];
    char ca_file[1024];
    unsigned char pending_write[BROWSER_IO_CHUNK];
} BrowserConnection;

static struct {
    TlsFixerBrowserOps ops;
    TlsFixerRegistry registry;
    SceUID registry_mutex;
    SceUID attach_mutex;
    mbedtls_x509_crt ca;
    int default_ca_error;
    uint32_t enabled;
    enum DefaultCaState default_ca_state;
    uint8_t initialized;
    uint8_t crypto_initialized;
} browser;

static uintptr_t connection_key(const void *native, int index) {
    return (uintptr_t)native + (uintptr_t)(unsigned int)index;
}

static size_t ssl_offset(int index) {
    return TLS_FIXER_CURL_SSL_OFFSET + TLS_FIXER_CURL_SSL_STRIDE * (size_t)(unsigned int)index;
}

static void registry_lock(void *unused) {
    (void)unused;
    (void)sceKernelLockMutex(browser.registry_mutex, 1, NULL);
}

static void registry_unlock(void *unused) {
    (void)unused;
    (void)sceKernelUnlockMutex(browser.registry_mutex, 1);
}

static void free_connection(void *unused, void *payload) {
    BrowserConnection *connection = payload;
    (void)unused;
    if (connection == NULL) return;
    mbedtls_ssl_free(&connection->ssl);
    mbedtls_ssl_config_free(&connection->config);
    if (connection->custom_ca_initialized) mbedtls_x509_crt_free(&connection->custom_ca);
    if (connection->mutex >= 0) (void)sceKernelDeleteMutex(connection->mutex);
    mbedtls_platform_zeroize(connection, sizeof(*connection));
    free(connection);
}

static int ensure_default_ca(void) {
    int result;
    if (browser.default_ca_state == DEFAULT_CA_READY) return 0;
    if (browser.default_ca_state == DEFAULT_CA_FAILED) return browser.default_ca_error;
    result = tls_fixer_load_ca_file(&browser.ca,
        browser.ops.default_ca_path != NULL ? browser.ops.default_ca_path : TLS_FIXER_DEFAULT_CA_PATH);
    if (result == 0) {
        browser.default_ca_state = DEFAULT_CA_READY;
        return 0;
    }
    mbedtls_x509_crt_free(&browser.ca);
    mbedtls_x509_crt_init(&browser.ca);
    browser.default_ca_error = result;
    browser.default_ca_state = DEFAULT_CA_FAILED;
    return result;
}

int tls_fixer_browser_init(const TlsFixerBrowserOps *ops) {
    const TlsFixerRegistryOps registry_ops = {registry_lock, registry_unlock, free_connection, NULL};
    int result;
    TlsFixerBrowserStartStage stage = TLS_FIXER_START_CRYPTO_PLATFORM;
    uint32_t diagnostic_detail;

    if (browser.initialized || ops == NULL || ops->timeleft == NULL || ops->socket_wait == NULL)
        return tls_fixer_browser_start_failure(TLS_FIXER_START_INIT_ARGUMENT, UINT32_MAX, -1);
    memset(&browser, 0, sizeof(browser));
    browser.registry_mutex = -1;
    browser.attach_mutex = -1;
    browser.ops = *ops;
    result = tls_fixer_crypto_platform_init();
    if (result != 0) return tls_fixer_browser_start_failure(stage, (uint32_t)result, result);
    browser.crypto_initialized = 1;
    stage = TLS_FIXER_START_PSA;
    result = (int)psa_crypto_init();
    if (result != PSA_SUCCESS) goto failed;
    mbedtls_x509_crt_init(&browser.ca);
    browser.registry_mutex = sceKernelCreateMutex("tls_fixer browser registry", 0, 0, NULL);
    browser.attach_mutex = sceKernelCreateMutex("tls_fixer browser attach", 0, 0, NULL);
    if (browser.registry_mutex < 0 || browser.attach_mutex < 0) {
        stage = browser.registry_mutex < 0 ? TLS_FIXER_START_REGISTRY_MUTEX : TLS_FIXER_START_ATTACH_MUTEX;
        result = TLS_FIXER_CURLE_OUT_OF_MEMORY;
        goto failed;
    }
    stage = TLS_FIXER_START_REGISTRY;
    result = tls_fixer_registry_init(&browser.registry, &registry_ops);
    if (result != 0) goto failed;
    browser.initialized = 1;
    return 0;

failed:
    diagnostic_detail = (uint32_t)(stage == TLS_FIXER_START_REGISTRY_MUTEX ? browser.registry_mutex :
        stage == TLS_FIXER_START_ATTACH_MUTEX ? browser.attach_mutex : result);
    if (browser.attach_mutex >= 0) (void)sceKernelDeleteMutex(browser.attach_mutex);
    if (browser.registry_mutex >= 0) (void)sceKernelDeleteMutex(browser.registry_mutex);
    mbedtls_x509_crt_free(&browser.ca);
    mbedtls_psa_crypto_free();
    tls_fixer_crypto_platform_free();
    memset(&browser, 0, sizeof(browser));
    return tls_fixer_browser_start_failure(stage, diagnostic_detail, result);
}

void tls_fixer_browser_enable(int enabled) {
    __atomic_store_n(&browser.enabled, enabled != 0, __ATOMIC_RELEASE);
}

int tls_fixer_browser_destroy(void) {
    int result;
    if (!browser.initialized) return 0;
    result = tls_fixer_registry_begin_stop_if_empty(&browser.registry);
    if (result != TLS_FIXER_REGISTRY_OK) return result;
    tls_fixer_browser_enable(0);
    result = tls_fixer_registry_destroy(&browser.registry);
    if (result != TLS_FIXER_REGISTRY_OK) return result;
    mbedtls_x509_crt_free(&browser.ca);
    mbedtls_psa_crypto_free();
    tls_fixer_crypto_platform_free();
    (void)sceKernelDeleteMutex(browser.attach_mutex);
    (void)sceKernelDeleteMutex(browser.registry_mutex);
    memset(&browser, 0, sizeof(browser));
    return 0;
}

size_t tls_fixer_browser_connection_count(void) {
    return browser.initialized ? tls_fixer_registry_count(&browser.registry) : 0;
}

static int bio_result(BrowserConnection *connection, int result, int sending) {
    if (result >= 0) return result;
    connection->net_error = result;
    switch ((uint32_t)result) {
        case (uint32_t)SCE_NET_ERROR_EAGAIN:
        case (uint32_t)SCE_NET_ERROR_EINTR:
            return sending ? MBEDTLS_ERR_SSL_WANT_WRITE : MBEDTLS_ERR_SSL_WANT_READ;
        case (uint32_t)SCE_NET_ERROR_ETIMEDOUT:
            return MBEDTLS_ERR_SSL_TIMEOUT;
        case (uint32_t)SCE_NET_ERROR_ECONNRESET:
            return MBEDTLS_ERR_NET_CONN_RESET;
        default:
            return sending ? MBEDTLS_ERR_NET_SEND_FAILED : MBEDTLS_ERR_NET_RECV_FAILED;
    }
}

static int browser_send(void *context, const unsigned char *data, size_t size) {
    BrowserConnection *connection = context;
    int result;
    if (__atomic_load_n(&connection->closing, __ATOMIC_ACQUIRE) && !connection->notifying_close) {
        return MBEDTLS_ERR_NET_SEND_FAILED;
    }
    if (size > INT_MAX) return MBEDTLS_ERR_NET_SEND_FAILED;
    tls_fixer_runtime_mark(TLS_FIXER_RT_BIO_SEND_ENTER, (int32_t)size);
    result = sceNetSend(connection->socket, data, (unsigned int)size, SCE_NET_MSG_DONTWAIT);
    tls_fixer_runtime_mark(TLS_FIXER_RT_BIO_SEND_RETURN, result);
    if (result == 0 && size != 0) return MBEDTLS_ERR_NET_SEND_FAILED;
    return bio_result(connection, result, 1);
}

static int browser_recv(void *context, unsigned char *data, size_t size) {
    BrowserConnection *connection = context;
    int result;
    if (__atomic_load_n(&connection->closing, __ATOMIC_ACQUIRE)) return MBEDTLS_ERR_NET_RECV_FAILED;
    if (size > INT_MAX) return MBEDTLS_ERR_NET_RECV_FAILED;
    tls_fixer_runtime_mark(TLS_FIXER_RT_BIO_RECV_ENTER, (int32_t)size);
    result = sceNetRecv(connection->socket, data, (unsigned int)size, SCE_NET_MSG_DONTWAIT);
    tls_fixer_runtime_mark(TLS_FIXER_RT_BIO_RECV_RETURN, result);
    return bio_result(connection, result, 0);
}

static int initialize_connection(BrowserConnection *connection, uint32_t cipher_mask) {
    static const char *const alpn[] = {"http/1.1", NULL};
    static const int tls12[] = {
        MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    };
    mbedtls_x509_crt *ca = &browser.ca;
    size_t count = 0;
    int result;

    connection->ciphers[count++] = MBEDTLS_TLS1_3_AES_128_GCM_SHA256;
    connection->ciphers[count++] = MBEDTLS_TLS1_3_AES_256_GCM_SHA384;
    connection->ciphers[count++] = MBEDTLS_TLS1_3_CHACHA20_POLY1305_SHA256;
    for (size_t i = 0; i < sizeof(tls12)/sizeof(tls12[0]); ++i) {
        if (cipher_mask & (UINT32_C(1) << i)) connection->ciphers[count++] = tls12[i];
    }
    connection->ciphers[count] = 0;
    if (connection->custom_ca_requested) {
        mbedtls_x509_crt_init(&connection->custom_ca);
        connection->custom_ca_initialized = 1;
        result = tls_fixer_load_ca_file(&connection->custom_ca, connection->ca_file);
        if (result != 0) return TLS_FIXER_CURLE_SSL_CACERT_BADFILE;
        ca = &connection->custom_ca;
    }
    result = mbedtls_ssl_config_defaults(&connection->config, MBEDTLS_SSL_IS_CLIENT,
        MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (result != 0) return TLS_FIXER_CURLE_OUT_OF_MEMORY;
    connection->certificate_profile = mbedtls_x509_crt_profile_default;
    /* System endpoints such as native-vita.np.ac.playstation.net require
     * SHA-1 certificate signatures. */
    connection->certificate_profile.allowed_mds |= MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA1);
    mbedtls_ssl_conf_cert_profile(&connection->config, &connection->certificate_profile);
    mbedtls_ssl_conf_min_tls_version(&connection->config, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_max_tls_version(&connection->config, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_ciphersuites(&connection->config, connection->ciphers);
    mbedtls_ssl_conf_authmode(&connection->config, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ca_chain(&connection->config, ca, NULL);
    result = mbedtls_ssl_conf_alpn_protocols(&connection->config, alpn);
    if (result != 0) return TLS_FIXER_CURLE_SSL_CONNECT_ERROR;
    result = mbedtls_ssl_setup(&connection->ssl, &connection->config);
    if (result != 0) return TLS_FIXER_CURLE_OUT_OF_MEMORY;
    result = mbedtls_ssl_set_hostname(&connection->ssl, connection->hostname);
    if (result != 0) return TLS_FIXER_CURLE_OUT_OF_MEMORY;
    mbedtls_ssl_set_bio(&connection->ssl, connection, browser_send, browser_recv, NULL);
    connection->state = BROWSER_HANDSHAKING;
    return 0;
}

static void release_connection(TlsFixerRegistryHandle *handle, BrowserConnection *connection) {
    (void)sceKernelUnlockMutex(connection->mutex, 1);
    (void)tls_fixer_registry_release(&browser.registry, handle);
}

static int acquire_connection(void *native, int index, TlsFixerRegistryHandle *handle,
    BrowserConnection **connection, int *handled) {
    int result;
    *handled = 0;
    if (!browser.initialized) return 0;
    if (native == NULL || index < 0 || index > 1) { *handled = 1; return TLS_FIXER_CURLE_BAD_FUNCTION_ARGUMENT; }
    if (sceKernelLockMutex(browser.attach_mutex, 1, NULL) < 0) { *handled = 1; return TLS_FIXER_CURLE_SSL_CONNECT_ERROR; }
    result = tls_fixer_registry_acquire(&browser.registry, connection_key(native, index), handle);
    (void)sceKernelUnlockMutex(browser.attach_mutex, 1);
    if (result == TLS_FIXER_REGISTRY_NOT_FOUND) return 0;
    *handled = 1;
    if (result != TLS_FIXER_REGISTRY_OK) return TLS_FIXER_CURLE_AGAIN;
    *connection = handle->payload;
    if (sceKernelTryLockMutex((*connection)->mutex, 1) < 0) {
        (void)tls_fixer_registry_release(&browser.registry, handle);
        return TLS_FIXER_CURLE_AGAIN;
    }
    if (__atomic_load_n(&(*connection)->closing, __ATOMIC_ACQUIRE)) {
        release_connection(handle, *connection);
        return TLS_FIXER_CURLE_ABORTED_BY_CALLBACK;
    }
    return 0;
}

static int create_or_acquire(void *native, int index, TlsFixerRegistryHandle *handle,
    BrowserConnection **output, int *handled) {
    TlsFixerBrowserOptions options;
    BrowserConnection *connection;
    size_t native_ssl = ssl_offset(index);
    int result;

    *handled = 0;
    if (!browser.initialized) return 0;
    if (sceKernelLockMutex(browser.attach_mutex, 1, NULL) < 0) { *handled = 1; return TLS_FIXER_CURLE_SSL_CONNECT_ERROR; }
    result = tls_fixer_registry_acquire(&browser.registry, connection_key(native, index), handle);
    if (result == TLS_FIXER_REGISTRY_OK) {
        (void)sceKernelUnlockMutex(browser.attach_mutex, 1);
        *handled = 1;
        connection = handle->payload;
        if (sceKernelTryLockMutex(connection->mutex, 1) < 0) {
            (void)tls_fixer_registry_release(&browser.registry, handle);
            return TLS_FIXER_CURLE_AGAIN;
        }
        *output = connection;
        return 0;
    }
    if (result != TLS_FIXER_REGISTRY_NOT_FOUND) {
        *handled = 1;
        result = TLS_FIXER_CURLE_AGAIN;
        goto unlock;
    }
    if (!__atomic_load_n(&browser.enabled, __ATOMIC_ACQUIRE) ||
        tls_fixer_read_u32(native, native_ssl + TLS_FIXER_CURL_SSL_HANDLE_OFFSET) != 0 ||
        tls_fixer_read_u32(native, native_ssl + TLS_FIXER_CURL_SSL_CONTEXT_OFFSET) != 0) {
        result = 0;
        goto unlock;
    }
    tls_fixer_runtime_mark(TLS_FIXER_RT_OPTIONS_ENTER, index);
    result = tls_fixer_browser_read_options(native, (unsigned int)index, browser.ops.default_ciphers,
        browser.ops.is_default_ctx_callback, &options);
    tls_fixer_runtime_mark(TLS_FIXER_RT_OPTIONS_RETURN, result);
    if (result == TLS_FIXER_BROWSER_CONFIG_LEGACY) {
        TLS_FIXER_LOG("browser connection uses legacy TLS: unsupported custom configuration");
        result = 0;
        goto unlock;
    }
    if (result != 0) { result = TLS_FIXER_CURLE_BAD_FUNCTION_ARGUMENT; goto unlock; }
    if (options.ca_file == NULL) {
        result = ensure_default_ca();
        if (result != 0) {
            TLS_FIXER_LOG("browser default trust initialization failed: 0x%08X; using legacy TLS", result);
            result = 0;
            goto unlock;
        }
    }
    *handled = 1;
    tls_fixer_runtime_mark(TLS_FIXER_RT_ALLOC_ENTER, (int32_t)sizeof(*connection));
    connection = calloc(1, sizeof(*connection));
    tls_fixer_runtime_mark(TLS_FIXER_RT_ALLOC_RETURN, connection == NULL ? TLS_FIXER_CURLE_OUT_OF_MEMORY : 0);
    if (connection == NULL) { result = TLS_FIXER_CURLE_OUT_OF_MEMORY; goto unlock; }
    connection->mutex = sceKernelCreateMutex("tls_fixer browser connection", 0, 0, NULL);
    if (connection->mutex < 0) { free(connection); result = TLS_FIXER_CURLE_OUT_OF_MEMORY; goto unlock; }
    mbedtls_ssl_init(&connection->ssl);
    mbedtls_ssl_config_init(&connection->config);
    connection->native = native;
    connection->index = index;
    connection->socket = options.socket;
    connection->verify_peer = options.verify_peer;
    connection->verify_host = options.verify_host;
    connection->custom_ca_requested = options.ca_file != NULL;
    memcpy(connection->hostname, options.hostname, strlen(options.hostname) + 1);
    if (options.ca_file != NULL) memcpy(connection->ca_file, options.ca_file, strlen(options.ca_file) + 1);
    connection->old_recv = tls_fixer_read_u32(native, TLS_FIXER_CURL_RECV_OFFSET + 4 * (size_t)(unsigned int)index);
    connection->old_send = tls_fixer_read_u32(native, TLS_FIXER_CURL_SEND_OFFSET + 4 * (size_t)(unsigned int)index);
    if (sceKernelLockMutex(connection->mutex, 1, NULL) < 0) {
        free_connection(NULL, connection);
        result = TLS_FIXER_CURLE_OUT_OF_MEMORY;
        goto unlock;
    }
    result = tls_fixer_registry_insert(&browser.registry, connection_key(native, index), connection);
    if (result != TLS_FIXER_REGISTRY_OK) {
        (void)sceKernelUnlockMutex(connection->mutex, 1);
        free_connection(NULL, connection);
        result = TLS_FIXER_CURLE_OUT_OF_MEMORY;
        goto unlock;
    }
    result = tls_fixer_registry_acquire(&browser.registry, connection_key(native, index), handle);
    if (result != TLS_FIXER_REGISTRY_OK) {
        (void)sceKernelUnlockMutex(connection->mutex, 1);
        (void)tls_fixer_registry_remove(&browser.registry, connection_key(native, index));
        result = TLS_FIXER_CURLE_SSL_CONNECT_ERROR;
        goto unlock;
    }
    tls_fixer_write_u32(native, native_ssl + TLS_FIXER_CURL_SSL_STATE_OFFSET, 1);
    tls_fixer_write_u32(native, native_ssl + TLS_FIXER_CURL_SSL_CONNECTING_OFFSET, 1);
    (void)sceKernelUnlockMutex(browser.attach_mutex, 1);
    tls_fixer_runtime_mark(TLS_FIXER_RT_SETUP_ENTER, index);
    result = initialize_connection(connection, options.tls12_suites);
    tls_fixer_runtime_mark(TLS_FIXER_RT_SETUP_RETURN, result);
    if (result != 0) {
        TLS_FIXER_LOG("browser connection setup failed: socket=%d code=%d", connection->socket, result);
        connection->state = BROWSER_FAILED;
        connection->error = result;
    }
    *output = connection;
    return 0;
unlock:
    (void)sceKernelUnlockMutex(browser.attach_mutex, 1);
    return result;
}

static uint32_t verification_code(uint32_t flags) {
    if (flags == 0) return 0;
    if (flags == UINT32_MAX) return 1;
    if (flags & MBEDTLS_X509_BADCERT_CN_MISMATCH) return 62;
    if (flags & MBEDTLS_X509_BADCERT_EXPIRED) return 10;
    if (flags & MBEDTLS_X509_BADCERT_FUTURE) return 9;
    if (flags & MBEDTLS_X509_BADCERT_REVOKED) return 23;
    if (flags & MBEDTLS_X509_BADCERT_NOT_TRUSTED) return 20;
    return 1;
}

static int verify_connection(BrowserConnection *connection, void *easy) {
    uint32_t flags = mbedtls_ssl_get_verify_result(&connection->ssl);
    uint32_t chain_flags = flags & ~MBEDTLS_X509_BADCERT_CN_MISMATCH;
    tls_fixer_write_u32(easy, TLS_FIXER_CURL_VERIFY_RESULT_OFFSET, verification_code(flags));
    if (flags == UINT32_MAX || mbedtls_ssl_get_peer_cert(&connection->ssl) == NULL) {
        return TLS_FIXER_CURLE_SSL_CONNECT_ERROR;
    }
    if (connection->verify_peer && chain_flags != 0) return TLS_FIXER_CURLE_SSL_CACERT;
    if (connection->verify_host && (flags & MBEDTLS_X509_BADCERT_CN_MISMATCH)) {
        return TLS_FIXER_CURLE_PEER_FAILED_VERIFICATION;
    }
    return 0;
}

int tls_fixer_browser_connect(void *native, int index, unsigned char nonblocking,
    unsigned char *done, int *handled) {
    TlsFixerRegistryHandle handle;
    BrowserConnection *connection = NULL;
    void *easy;
    int result;

    if (handled == NULL) return TLS_FIXER_CURLE_BAD_FUNCTION_ARGUMENT;
    *handled = 0;
    if (done == NULL || native == NULL || index < 0 || index > 1) {
        *handled = 1;
        return TLS_FIXER_CURLE_BAD_FUNCTION_ARGUMENT;
    }
    *done = 0;
    result = create_or_acquire(native, index, &handle, &connection, handled);
    if (!*handled) return result;
    if (result != 0) return result == TLS_FIXER_CURLE_AGAIN ? 0 : result;
    easy = (void *)(uintptr_t)tls_fixer_read_u32(native, TLS_FIXER_CURL_EASY_OFFSET);
    if (__atomic_load_n(&connection->closing, __ATOMIC_ACQUIRE) || easy == NULL) {
        result = TLS_FIXER_CURLE_ABORTED_BY_CALLBACK;
        goto failed;
    }
    if (connection->state == BROWSER_ACTIVE) { *done = 1; result = 0; goto finished; }
    if (connection->state == BROWSER_FAILED) { result = connection->error; goto finished; }
    if (connection->state != BROWSER_HANDSHAKING) { result = TLS_FIXER_CURLE_SSL_CONNECT_ERROR; goto failed; }

    for (;;) {
        tls_fixer_runtime_mark(TLS_FIXER_RT_TIMER_ENTER, index);
        int remaining = browser.ops.timeleft(easy, NULL, 1);
        tls_fixer_runtime_mark(TLS_FIXER_RT_TIMER_RETURN, remaining);
        if (__atomic_load_n(&connection->closing, __ATOMIC_ACQUIRE)) {
            result = TLS_FIXER_CURLE_ABORTED_BY_CALLBACK;
            goto failed;
        }
        if (remaining < 0) { result = TLS_FIXER_CURLE_OPERATION_TIMEDOUT; goto failed; }
        if (connection->want != 0) {
            int timeout = nonblocking ? 0 :
                (remaining == 0 || remaining > BROWSER_POLL_SLICE_MS ? BROWSER_POLL_SLICE_MS : remaining);
            tls_fixer_runtime_mark(TLS_FIXER_RT_WAIT_ENTER, timeout);
            result = browser.ops.socket_wait(connection->want == 2 ? connection->socket : -1,
                -1, connection->want == 3 ? connection->socket : -1, timeout);
            tls_fixer_runtime_mark(TLS_FIXER_RT_WAIT_RETURN, result);
            if (result < 0) { result = TLS_FIXER_CURLE_SSL_CONNECT_ERROR; goto failed; }
            if (result == 0) {
                if (nonblocking) { result = 0; goto finished; }
                continue;
            }
        }
        connection->net_error = 0;
        tls_fixer_runtime_mark(TLS_FIXER_RT_HANDSHAKE_ENTER, index);
        result = mbedtls_ssl_handshake(&connection->ssl);
        tls_fixer_runtime_mark(TLS_FIXER_RT_HANDSHAKE_RETURN, result);
        if (result == MBEDTLS_ERR_SSL_WANT_READ || result == MBEDTLS_ERR_SSL_WANT_WRITE) {
            connection->want = result == MBEDTLS_ERR_SSL_WANT_READ ? 2 : 3;
            tls_fixer_write_u32(native, ssl_offset(index) + TLS_FIXER_CURL_SSL_CONNECTING_OFFSET,
                (uint32_t)connection->want);
            if (nonblocking) { result = 0; goto finished; }
            continue;
        }
        if (result != 0) {
            uint32_t flags = mbedtls_ssl_get_verify_result(&connection->ssl);
            TLS_FIXER_LOG("browser handshake failed: tls=0x%08X net=0x%08X verify=0x%08X",
                result, connection->net_error, flags);
            if (result == MBEDTLS_ERR_SSL_TIMEOUT) result = TLS_FIXER_CURLE_OPERATION_TIMEDOUT;
            else if (flags != 0 && flags != UINT32_MAX) {
                tls_fixer_write_u32(easy, TLS_FIXER_CURL_VERIFY_RESULT_OFFSET, verification_code(flags));
                result = TLS_FIXER_CURLE_SSL_CACERT;
            } else result = TLS_FIXER_CURLE_SSL_CONNECT_ERROR;
            goto failed;
        }
        result = verify_connection(connection, easy);
        tls_fixer_runtime_mark(TLS_FIXER_RT_VERIFY_RETURN, result);
        if (result != 0) goto failed;
        connection->state = BROWSER_ACTIVE;
        connection->want = 0;
        tls_fixer_write_u32(native, ssl_offset(index) + TLS_FIXER_CURL_SSL_STATE_OFFSET, 2);
        tls_fixer_write_u32(native, ssl_offset(index) + TLS_FIXER_CURL_SSL_CONNECTING_OFFSET, 0);
        tls_fixer_write_u32(native, TLS_FIXER_CURL_RECV_OFFSET + 4 * (size_t)(unsigned int)index,
            (uint32_t)(uintptr_t)tls_fixer_browser_recv);
        tls_fixer_write_u32(native, TLS_FIXER_CURL_SEND_OFFSET + 4 * (size_t)(unsigned int)index,
            (uint32_t)(uintptr_t)tls_fixer_browser_send);
#if TLS_FIXER_ENABLE_RUNTIME_UDP
        const char *version = mbedtls_ssl_get_version(&connection->ssl);
        tls_fixer_runtime_mark(TLS_FIXER_RT_ACTIVE, strcmp(version, "TLSv1.3") == 0 ? 0x0304 :
            strcmp(version, "TLSv1.2") == 0 ? 0x0303 : 0);
#endif
        TLS_FIXER_LOG("browser handshake complete: socket=%d version=%s cipher=%s", connection->socket,
            mbedtls_ssl_get_version(&connection->ssl), mbedtls_ssl_get_ciphersuite(&connection->ssl));
        *done = 1;
        goto finished;
    }
failed:
    TLS_FIXER_LOG("browser connect rejected: socket=%d code=%d", connection->socket, result);
    connection->state = BROWSER_FAILED;
    connection->error = result;
finished:
    release_connection(&handle, connection);
    return result;
}

static int map_io(BrowserConnection *connection, int result, int sending, int *error) {
    if (result > 0) { *error = 0; return result; }
    if (result == MBEDTLS_ERR_SSL_WANT_READ || result == MBEDTLS_ERR_SSL_WANT_WRITE) {
        *error = TLS_FIXER_CURLE_AGAIN;
        return -1;
    }
    if (!sending && result == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
        connection->state = BROWSER_EOF;
        *error = 0;
        return 0;
    }
    connection->state = BROWSER_FAILED;
    connection->error = sending ? TLS_FIXER_CURLE_SEND_ERROR : TLS_FIXER_CURLE_RECV_ERROR;
    *error = connection->error;
    return -1;
}

int tls_fixer_browser_recv(void *native, int index, void *data, unsigned int length, int *error) {
    TlsFixerRegistryHandle handle;
    BrowserConnection *connection = NULL;
    int handled, result;
    unsigned int budget = 16;
    if (error == NULL) return -1;
    *error = TLS_FIXER_CURLE_RECV_ERROR;
    result = acquire_connection(native, index, &handle, &connection, &handled);
    if (result != 0 || !handled) { if (result == TLS_FIXER_CURLE_AGAIN) *error = result; return -1; }
    if (connection->state == BROWSER_EOF || length == 0) { *error = 0; result = 0; goto finished; }
    if (connection->state != BROWSER_ACTIVE || data == NULL) { result = -1; goto finished; }
    if (connection->pending_length != 0) { *error = TLS_FIXER_CURLE_AGAIN; result = -1; goto finished; }
    if (connection->lookahead_valid) {
        *(unsigned char *)data = connection->lookahead;
        connection->lookahead_valid = 0;
        *error = 0;
        result = 1;
        goto finished;
    }
    if (length > BROWSER_IO_CHUNK) length = BROWSER_IO_CHUNK;
    do {
        connection->net_error = 0;
        tls_fixer_runtime_mark(TLS_FIXER_RT_RECV_ENTER, (int32_t)length);
        result = mbedtls_ssl_read(&connection->ssl, data, length);
        tls_fixer_runtime_mark(TLS_FIXER_RT_RECV_RETURN, result);
    } while (result == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET && --budget != 0);
    if (result == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) result = MBEDTLS_ERR_SSL_WANT_READ;
    result = map_io(connection, result, 0, error);
finished:
    release_connection(&handle, connection);
    return result;
}

int tls_fixer_browser_send(void *native, int index, const void *data, unsigned int length, int *error) {
    TlsFixerRegistryHandle handle;
    BrowserConnection *connection = NULL;
    int handled, result;
    if (error == NULL) return -1;
    *error = TLS_FIXER_CURLE_SEND_ERROR;
    result = acquire_connection(native, index, &handle, &connection, &handled);
    if (result != 0 || !handled) { if (result == TLS_FIXER_CURLE_AGAIN) *error = result; return -1; }
    if (connection->state != BROWSER_ACTIVE || (length != 0 && data == NULL)) { result = -1; goto finished; }
    if (length > BROWSER_IO_CHUNK) length = BROWSER_IO_CHUNK;
    if (connection->pending_length != 0 && (length != connection->pending_length ||
        memcmp(data, connection->pending_write, length) != 0)) {
        connection->state = BROWSER_FAILED;
        connection->error = TLS_FIXER_CURLE_SEND_ERROR;
        result = -1;
        goto clear;
    }
    if (length == 0) { *error = 0; result = 0; goto finished; }
    if (connection->pending_length == 0) {
        memcpy(connection->pending_write, data, length);
        connection->pending_length = length;
    }
    connection->net_error = 0;
    tls_fixer_runtime_mark(TLS_FIXER_RT_SEND_ENTER, (int32_t)connection->pending_length);
    result = mbedtls_ssl_write(&connection->ssl, connection->pending_write, connection->pending_length);
    tls_fixer_runtime_mark(TLS_FIXER_RT_SEND_RETURN, result);
    result = map_io(connection, result, 1, error);
    if (*error == TLS_FIXER_CURLE_AGAIN) goto finished;
clear:
    mbedtls_platform_zeroize(connection->pending_write, sizeof(connection->pending_write));
    connection->pending_length = 0;
finished:
    release_connection(&handle, connection);
    return result;
}

int tls_fixer_browser_pending(void *native, int index, int *handled) {
    TlsFixerRegistryHandle handle;
    BrowserConnection *connection = NULL;
    int result;
    if (handled == NULL) return 0;
    result = acquire_connection(native, index, &handle, &connection, handled);
    if (result != 0 || !*handled) return 0;
    result = connection->state == BROWSER_ACTIVE && connection->pending_length == 0 &&
        (connection->lookahead_valid || mbedtls_ssl_check_pending(&connection->ssl));
    release_connection(&handle, connection);
    return result;
}

int tls_fixer_browser_check(void *native, int *handled) {
    TlsFixerRegistryHandle handle;
    BrowserConnection *connection = NULL;
    unsigned int budget = 16;
    int result;

    if (handled == NULL) return -1;
    result = acquire_connection(native, 0, &handle, &connection, handled);
    if (result != 0 || !*handled) return -1;
    if (connection->state == BROWSER_EOF || connection->state == BROWSER_FAILED) {
        result = 0;
        goto finished;
    }
    if (connection->state != BROWSER_ACTIVE || connection->pending_length != 0) {
        result = -1;
        goto finished;
    }
    if (connection->lookahead_valid || mbedtls_ssl_get_bytes_avail(&connection->ssl) != 0) {
        result = 1;
        goto finished;
    }
    do {
        connection->net_error = 0;
        result = mbedtls_ssl_read(&connection->ssl, &connection->lookahead, 1);
    } while (result == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET && --budget != 0);
    if (result > 0) {
        connection->lookahead_valid = 1;
        result = 1;
    } else if (result == MBEDTLS_ERR_SSL_WANT_READ || result == MBEDTLS_ERR_SSL_WANT_WRITE ||
        result == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) {
        result = -1;
    } else if (result == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
        connection->state = BROWSER_EOF;
        result = 0;
    } else {
        connection->state = BROWSER_FAILED;
        connection->error = TLS_FIXER_CURLE_RECV_ERROR;
        result = 0;
    }
finished:
    release_connection(&handle, connection);
    return result;
}

int tls_fixer_browser_close(void *native, int index, int *handled) {
    TlsFixerRegistryHandle handle;
    BrowserConnection *connection;
    int result;
    if (handled == NULL) return TLS_FIXER_CURLE_BAD_FUNCTION_ARGUMENT;
    *handled = 0;
    if (!browser.initialized) return 0;
    if (native == NULL || index < 0 || index > 1) { *handled = 1; return TLS_FIXER_CURLE_BAD_FUNCTION_ARGUMENT; }
    if (sceKernelLockMutex(browser.attach_mutex, 1, NULL) < 0) { *handled = 1; return TLS_FIXER_CURLE_SSL_CONNECT_ERROR; }
    result = tls_fixer_registry_acquire(&browser.registry, connection_key(native, index), &handle);
    if (result != TLS_FIXER_REGISTRY_OK) {
        (void)sceKernelUnlockMutex(browser.attach_mutex, 1);
        *handled = result != TLS_FIXER_REGISTRY_NOT_FOUND;
        return 0;
    }
    *handled = 1;
    connection = handle.payload;
    __atomic_store_n(&connection->closing, 1, __ATOMIC_RELEASE);
    (void)sceKernelUnlockMutex(browser.attach_mutex, 1);
    if (sceKernelLockMutex(connection->mutex, 1, NULL) < 0) {
        (void)tls_fixer_registry_release(&browser.registry, &handle);
        return TLS_FIXER_CURLE_SSL_CONNECT_ERROR;
    }
    if (connection->native != NULL) {
        /* BIO cancellation stays set: teardown must not flush pending application data. */
        if ((connection->state == BROWSER_ACTIVE || connection->state == BROWSER_EOF) &&
            connection->pending_length == 0) {
            connection->notifying_close = 1;
            (void)mbedtls_ssl_close_notify(&connection->ssl);
            connection->notifying_close = 0;
        }
        tls_fixer_write_u32(native, TLS_FIXER_CURL_RECV_OFFSET + 4 * (size_t)(unsigned int)index, connection->old_recv);
        tls_fixer_write_u32(native, TLS_FIXER_CURL_SEND_OFFSET + 4 * (size_t)(unsigned int)index, connection->old_send);
        tls_fixer_write_u32(native, ssl_offset(index) + TLS_FIXER_CURL_SSL_STATE_OFFSET, 0);
        tls_fixer_write_u32(native, ssl_offset(index) + TLS_FIXER_CURL_SSL_CONNECTING_OFFSET, 0);
        connection->native = NULL;
        (void)tls_fixer_registry_remove(&browser.registry, connection_key(native, index));
    }
    release_connection(&handle, connection);
    return 0;
}
