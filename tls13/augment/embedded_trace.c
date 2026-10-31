/* Experimental UDP sink. System modules cannot assume permission to write
 * ux0 files, and formatting buffers must not consume a 4 KiB caller stack. */
#include "trace.h"
#include <psp2/kernel/processmgr.h>
#include <psp2/kernel/threadmgr/thread.h>
#include <psp2/net/net.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#if TLS_FIXER_EMBEDDED_COMPARE_HTTP
#include "tls_fixer/sony_abi.h"
#include "embedded.h"
#include "optional_syscall.h"
#include "client_hello_trace.h"
#include <psa/crypto.h>
#endif

#if !TLS_FIXER_ENABLE_DEBUG_LOG
#error "This recorder is diagnostic-only"
#endif
_Static_assert(sizeof(TLS_FIXER_EMBEDDED_TRACE_NONCE) == 33, "128-bit capture nonce");

static unsigned int busy, records, dropped;
static char line[TLS_FIXER_TRACE_LINE_LIMIT];
static SceNetSockaddrIn destination;
typedef void (*StackObserver)(const char *, unsigned int, uintptr_t);
static StackObserver stack_observer;

void tls_fixer_embedded_set_stack_observer(StackObserver observer) {
    __atomic_store_n(&stack_observer, observer, __ATOMIC_RELEASE);
}

static void observe_stack(const char *phase, unsigned int after) {
    StackObserver observer = __atomic_load_n(&stack_observer, __ATOMIC_ACQUIRE);
    if (observer) {
        uintptr_t sp;
        __asm__ volatile("mov %0, sp" : "=r"(sp));
        observer(phase, after, sp);
    }
}

void tls_fixer_trace(const char *format, ...) {
    unsigned int expected = 0;
    if (!format || __atomic_load_n(&records, __ATOMIC_RELAXED) >= TLS_FIXER_TRACE_RECORD_LIMIT) return;
    if (!__atomic_compare_exchange_n(&busy, &expected, 1, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
        __atomic_add_fetch(&dropped, 1, __ATOMIC_RELAXED);
        return;
    }
    observe_stack(format, 0);
    int *net_errno = sceNetErrnoLoc();
    int saved_errno = net_errno ? *net_errno : 0;
    int descriptor = -1;
    unsigned int sequence = __atomic_fetch_add(&records, 1, __ATOMIC_RELAXED);
    int prefix = snprintf(line, sizeof(line), "ETF1 %s seq=%u pid=%08X tid=%08X t=%llu dropped=%u ",
        TLS_FIXER_EMBEDDED_TRACE_NONCE, sequence, (unsigned int)sceKernelGetProcessId(),
        (unsigned int)sceKernelGetThreadId(), (unsigned long long)sceKernelGetSystemTimeWide(),
        __atomic_load_n(&dropped, __ATOMIC_RELAXED));
    if (prefix < 0 || (unsigned int)prefix >= sizeof(line) - 2) goto done;
    va_list args;
    va_start(args, format);
    int result = vsnprintf(line + prefix, sizeof(line) - (unsigned int)prefix - 1, format, args);
    va_end(args);
    if (result < 0) goto done;
    size_t length = strlen(line);
    line[length++] = '\n';
    if (destination.sin_len == 0) {
        destination.sin_family = SCE_NET_AF_INET;
        destination.sin_port = sceNetHtons(TLS_FIXER_EMBEDDED_TRACE_PORT);
        if (sceNetInetPton(SCE_NET_AF_INET, TLS_FIXER_EMBEDDED_TRACE_HOST, &destination.sin_addr) != 1) goto done;
        destination.sin_len = sizeof(destination);
    }
    /* No persistent descriptor can survive NetTerm or accidentally be reused
     * by another connection. A missing receiver never blocks an HTTP call. */
    descriptor = sceNetSocket("tls_fixer trace", SCE_NET_AF_INET, SCE_NET_SOCK_DGRAM, 0);
    if (descriptor < 0) goto done;
    (void)sceNetSendto(descriptor, line, length, SCE_NET_MSG_DONTWAIT,
        (const SceNetSockaddr *)&destination, sizeof(destination));
done:
    if (descriptor >= 0) (void)sceNetSocketClose(descriptor);
    if (net_errno) *net_errno = saved_errno;
    observe_stack(format, 1);
    __atomic_store_n(&busy, 0, __ATOMIC_RELEASE);
}

#if TLS_FIXER_EMBEDDED_COMPARE_HTTP
extern int tls_fixer_native_ssl_version(const void *);
extern const void *tls_fixer_native_ssl_cipher(const void *);
static unsigned int hello_seen;
static void *observed_bio, *observed_connection;

void tls_fixer_embedded_capture_hello(void *connection, const unsigned char *data,
    size_t length, int modern) {
    if (connection == NULL || data == NULL || length == 0) return;
    const char *host = tls_fixer_connection_hostname(connection);
    if (host == NULL || strcmp(host, "IV0001-NPXS01001-00.auth.np.ac.playstation.net") != 0) return;
    unsigned int expected = 0;
    if (!__atomic_compare_exchange_n(&hello_seen, &expected, 1, 0, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) return;
    TlsFixerHelloView view;
    if (!tls_fixer_hello_view(data, length, &view)) {
        tls_fixer_trace("event=clienthello.skipped modern=%d bytes=%u", modern, (unsigned int)length);
        return;
    }
    tls_fixer_trace("event=clienthello.begin modern=%d format=%u version=%04X bytes=%u",
        modern, view.format, view.version, (unsigned int)view.bytes);
    static const char digits[] = "0123456789abcdef";
    for (size_t offset = 0; offset < view.bytes; offset += 64) {
        char hex[129];
        size_t count = view.bytes - offset;
        if (count > 64) count = 64;
        for (size_t i = 0; i < count; ++i) {
            hex[2 * i] = digits[data[offset + i] >> 4];
            hex[2 * i + 1] = digits[data[offset + i] & 15];
        }
        hex[2 * count] = 0;
        tls_fixer_trace("event=clienthello.part modern=%d offset=%u data=%s", modern, (unsigned int)offset, hex);
    }
}

static int native_bio_observer(void *bio, int event, const char *data, int length,
                               int argument, int result) {
    (void)argument;
    if (bio == observed_bio && event == 3 && data && length > 0)
        tls_fixer_embedded_capture_hello(observed_connection, (const unsigned char *)data, (size_t)length, 0);
    if (bio == observed_bio && event == 1) {
        observed_bio = NULL;
        observed_connection = NULL;
    }
    /* Native BIO_write passes 1 before I/O and the original result afterwards. */
    return result;
}

void tls_fixer_embedded_observe_native_bio(void *request, int socket) {
    if (__atomic_load_n(&hello_seen, __ATOMIC_RELAXED) || observed_bio) return;
    void *connection = tls_fixer_resolve_connection(request);
    if (connection == NULL) return;
    const char *host = tls_fixer_connection_hostname(connection);
    if (host == NULL || strcmp(host, "IV0001-NPXS01001-00.auth.np.ac.playstation.net") != 0) return;
    uintptr_t version_stub = (uintptr_t)tls_fixer_native_ssl_version;
    if ((version_stub & 3u) || !tls_fixer_user_stub_bound((const uint32_t *)version_stub)) return;
    const void *ssl = (const void *)(uintptr_t)tls_fixer_read_u32(connection, 0x40);
    if (ssl == NULL || tls_fixer_native_ssl_version(ssl) != 0x303) return;
    /* Audited bundled SSL3.74 layout: SSL_set_bio stores WBIO at+16. Its
     * socket method is type0x505; ctrl104/105 store/read the descriptor at+60.
     * Only attach to this connection's initialized socket BIO with no callback.
     * No module text, shared method table, BIO argument or I/O result is changed. */
    void *bio = (void *)(uintptr_t)tls_fixer_read_u32(ssl, 16);
    if (bio == NULL) return;
    const void *method = (const void *)(uintptr_t)tls_fixer_read_u32(bio, 0);
    if (method == NULL || tls_fixer_read_u32(method, 0) != 0x505 ||
        tls_fixer_read_u32(bio, 12) != 1 || tls_fixer_read_i32(bio, 60) != socket ||
        tls_fixer_read_u32(bio, 4) != 0) {
        tls_fixer_trace("event=clienthello.native_bio skipped=1");
        return;
    }
    observed_bio = bio;
    observed_connection = connection;
    tls_fixer_write_u32(bio, 4, (uint32_t)(uintptr_t)native_bio_observer);
    tls_fixer_trace("event=clienthello.native_bio attached=1");
}

void tls_fixer_embedded_compare_identity(void *request) {
    void *connection = tls_fixer_resolve_connection(request);
    if (connection == NULL) return;
    const char *host = tls_fixer_connection_hostname(connection);
    if (host == NULL || strcmp(host, "IV0001-NPXS01001-00.auth.np.ac.playstation.net") != 0) return;
    /* Audited native getters lock the identity mutex and report lengths when
     * out=NULL. This checks for internally loaded identity material without
     * copying certificate/key bytes or reading an unprotected heap pointer. */
    typedef int (*GetIdentity)(void *, unsigned int, unsigned int *);
    uintptr_t text = (uintptr_t)g_tls_fixer_embedded_bindings.text;
    unsigned int certificate_bytes = 0, key_bytes = 0;
    int certificate_rc = ((GetIdentity)(text + 0x13abf))(NULL, 0, &certificate_bytes);
    int key_rc = ((GetIdentity)(text + 0x13b29))(NULL, 0, &key_bytes);
    tls_fixer_trace("event=auth.identity connection=%08X certificate_rc=%08X certificate_bytes=%u key_rc=%08X key_bytes=%u",
        (unsigned int)(uintptr_t)connection, certificate_rc, certificate_bytes, key_rc, key_bytes);
}

void tls_fixer_embedded_compare_connected(void *request) {
    void *connection = tls_fixer_resolve_connection(request);
    if (connection == NULL) return;
    const char *host = tls_fixer_connection_hostname(connection);
    if (host == NULL || strcmp(host, "IV0001-NPXS01001-00.auth.np.ac.playstation.net") != 0) return;
    uintptr_t version_stub = (uintptr_t)tls_fixer_native_ssl_version;
    uintptr_t cipher_stub = (uintptr_t)tls_fixer_native_ssl_cipher;
    if ((version_stub & 3u) != 0 || (cipher_stub & 3u) != 0 ||
        !tls_fixer_user_stub_bound((const uint32_t *)version_stub) ||
        !tls_fixer_user_stub_bound((const uint32_t *)cipher_stub)) {
        tls_fixer_trace("event=native.tls.getters bound=0");
        return;
    }
    /* The original HTTP create routine owns its native SSL object at +0x40.
     * The bundled SSL getters return its version and immutable cipher entry;
     * the native cipher description uses name +4 and numeric ID +8. */
    const void *ssl = (const void *)(uintptr_t)tls_fixer_read_u32(connection, 0x40);
    if (ssl == NULL) return;
    const void *cipher = tls_fixer_native_ssl_cipher(ssl);
    const char *name = cipher ? (const char *)(uintptr_t)tls_fixer_read_u32(cipher, 4) : NULL;
    unsigned int id = cipher ? tls_fixer_read_u32(cipher, 8) : 0;
    tls_fixer_trace("event=native.tls.connected connection=%08X version=%04X cipher_id=%08X cipher=%.*s",
        (unsigned int)(uintptr_t)connection, tls_fixer_native_ssl_version(ssl), id,
        80, name ? name : "(none)");
}

static int hash_hex(const void *buffer, size_t length, char hex[65]) {
    unsigned char digest[32];
    size_t actual = 0;
    int rc = psa_hash_compute(PSA_ALG_SHA_256, buffer, length, digest, sizeof(digest), &actual);
    hex[0] = 0;
    if (rc == 0 && actual == sizeof(digest)) {
        static const char digits[] = "0123456789abcdef";
        for (size_t i = 0; i < sizeof(digest); ++i) {
            hex[2 * i] = digits[digest[i] >> 4];
            hex[2 * i + 1] = digits[digest[i] & 15];
        }
        hex[64] = 0;
    }
    return rc;
}

static void compare_headers(void *connection, const unsigned char *data, unsigned int length, int modern) {
    static const char request[] = "POST /nav/auth HTTP/1.0\r\n";
    if (length < sizeof(request) - 1 || memcmp(data, request, sizeof(request) - 1) != 0) return;
    unsigned int offset = sizeof(request) - 1, line = 0;
    char hex[65];
    while (offset + 1 < length && line < 32) {
        unsigned int end = offset, colon = length;
        while (end + 1 < length && !(data[end] == '\r' && data[end + 1] == '\n')) {
            if (data[end] == ':' && colon == length) colon = end;
            ++end;
        }
        if (end == offset || end + 1 >= length || colon == length || colon - offset > 64) return;
        int rc = hash_hex(data + offset, end - offset, hex);
        tls_fixer_trace("event=auth.header connection=%08X modern=%d index=%u name=%.*s bytes=%u hash_rc=%d sha256=%s",
            (unsigned int)(uintptr_t)connection, modern, line,
            (int)(colon - offset), data + offset, end - offset, rc, hex);
        offset = end + 2;
        ++line;
    }
}

void tls_fixer_embedded_compare_write(void *connection, const void *buffer,
    unsigned int length, int result, int modern) {
    /* Compare only the observed Shell auth destination. No plaintext, account
     * fields, cookies, passwords or tickets are copied into the trace. The hash
     * covers only bytes accepted by this call, excluding retries/unsent suffixes.
     * Both transport implementations have returned before hashing starts. */
    const char *host = tls_fixer_connection_hostname(connection);
    if (host == NULL || strcmp(host, "IV0001-NPXS01001-00.auth.np.ac.playstation.net") != 0) return;
    int *net_errno = sceNetErrnoLoc();
    int saved_errno = net_errno ? *net_errno : 0;
    char hex[65] = {0};
    int hash_result = -1;
    if (buffer != NULL && result > 0 && (unsigned int)result <= length) {
        hash_result = hash_hex(buffer, (size_t)result, hex);
    }
    tls_fixer_trace("event=auth.write connection=%08X modern=%d requested=%u rc=%08X hash_rc=%d sha256=%s",
        (unsigned int)(uintptr_t)connection, modern, length, result, hash_result, hex);
    if (buffer != NULL && result > 0 && (unsigned int)result <= length)
        compare_headers(connection, buffer, (unsigned int)result, modern);
    if (net_errno) *net_errno = saved_errno;
}
#endif
