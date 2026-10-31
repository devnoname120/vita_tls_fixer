#include "embedded.h"
#include "provider.h"
#include "transport.h"
#include "user_runtime.h"
#include "entry_gate.h"
#include "diagnostics.h"
#include <psp2/kernel/threadmgr/mutex.h>
#include <psp2/kernel/modulemgr.h>
#include <string.h>

#ifndef TLS_FIXER_EMBEDDED_NATIVE_CONTROL
#define TLS_FIXER_EMBEDDED_NATIVE_CONTROL 0
#endif

TlsFixerEmbeddedBindings g_tls_fixer_embedded_bindings = {.magic = 0x41584654, .version = 4};
TlsFixerProviderGlobal g_tls_fixer_http;
static SceUID g_lifecycle_mutex = -1;
static uint32_t g_gate = TLS_FIXER_GATE_CLOSED;
static _Atomic uint32_t g_http_live;
static uint32_t g_runtime_live;
static _Atomic int g_last_error;
static uint32_t g_creates, g_fallbacks;

int tls_fixer_embedded_enter(void) { return tls_fixer_gate_enter(&g_gate); }
void tls_fixer_embedded_leave(void) { tls_fixer_gate_leave(&g_gate); }

static int cleanup(void) {
    if (tls_fixer_gate_close(&g_gate) != 0) return -1;
    if (g_runtime_live) {
        /* Certificate/name callbacks have returned before their transport entry
         * leaves the entry gate. Retained names own Sony allocations and code only. */
        tls_fixer_embedded_cert_destroy();
        tls_fixer_embedded_redirect_destroy();
        tls_fixer_embedded_profile_destroy();
        int rc = tls_fixer_transport_global_destroy();
        if (rc < 0) return rc;
        rc = tls_fixer_user_runtime_destroy();
        if (rc < 0) return rc;
        g_runtime_live = 0;
    }
    g_tls_fixer_http.state = TLS_FIXER_PROVIDER_STOPPED;
    return 0;
}

static int initialize(void) {
    int rc;
    if (g_runtime_live) return g_tls_fixer_http.state == TLS_FIXER_PROVIDER_ACTIVE ? 0 : -1;
    g_tls_fixer_http.state = TLS_FIXER_PROVIDER_STARTING;
    memset((unsigned char *)&g_tls_fixer_http + sizeof(g_tls_fixer_http.state), 0,
           sizeof(g_tls_fixer_http) - sizeof(g_tls_fixer_http.state));
    g_tls_fixer_http.text_address = (uintptr_t)g_tls_fixer_embedded_bindings.text;
    g_tls_fixer_http.text_size = TLS_FIXER_LIBHTTP_TEXT_SIZE;
    g_tls_fixer_http.data_address = (uintptr_t)g_tls_fixer_embedded_bindings.data;
    g_tls_fixer_http.data_size = TLS_FIXER_LIBHTTP_DATA_MEMORY_SIZE;
    g_tls_fixer_http.global_https_options_address =
        g_tls_fixer_http.data_address + TLS_FIXER_LIBHTTP_GLOBAL_HTTPS_OPTIONS_OFFSET;
    rc = tls_fixer_cert_policy_bind(&g_tls_fixer_http.cert_policy,
        g_tls_fixer_embedded_bindings.text, TLS_FIXER_LIBHTTP_TEXT_SIZE);
    if (rc != 0) goto failed;
    rc = tls_fixer_user_runtime_init();
    if (rc != 0) goto failed;
    g_runtime_live = 1;
    rc = tls_fixer_transport_global_init();
    if (rc != 0) goto failed;
    tls_fixer_embedded_profile_init();
    rc = tls_fixer_embedded_cert_init();
    if (rc != 0) goto failed;
    tls_fixer_embedded_redirect_init();
    g_tls_fixer_http.state = TLS_FIXER_PROVIDER_ACTIVE;
    g_last_error = 0;
    return 0;
failed:
    g_last_error = rc;
    (void)cleanup();
    return rc;
}

int module_start(SceSize argc, const void *args) {
    if (g_tls_fixer_embedded_bindings.magic != 0x41584654 || g_tls_fixer_embedded_bindings.version != 4 ||
        !g_tls_fixer_embedded_bindings.text || !g_tls_fixer_embedded_bindings.data ||
        !g_tls_fixer_embedded_bindings.start || !g_tls_fixer_embedded_bindings.stop) return SCE_KERNEL_START_FAILED;
    int rc = g_tls_fixer_embedded_bindings.start(argc, args);
    TLS_FIXER_LOG("event=module.start native=%08X text=%08X data=%08X", rc,
        (unsigned int)(uintptr_t)g_tls_fixer_embedded_bindings.text,
        (unsigned int)(uintptr_t)g_tls_fixer_embedded_bindings.data);
    if (rc != SCE_KERNEL_START_SUCCESS) return rc;
    g_lifecycle_mutex = sceKernelCreateMutex("tls_fixer lifecycle", 0, 0, NULL);
    if (g_lifecycle_mutex < 0) g_last_error = g_lifecycle_mutex;
    return rc;
}

int module_stop(SceSize argc, const void *args) {
    /* The SDK requires sceHttpTerm before unloading HTTP. Reject an unload
     * while HTTP or TLS operations are still live, without partially stopping
     * Sony's module or leaving its global mutex destroyed. */
    if (g_http_live || tls_fixer_gate_count(&g_gate)) return SCE_KERNEL_STOP_FAIL;
    if (cleanup() < 0) return SCE_KERNEL_STOP_FAIL;
    int rc = g_tls_fixer_embedded_bindings.stop(argc, args);
    if (rc == SCE_KERNEL_STOP_SUCCESS && g_lifecycle_mutex >= 0) {
        sceKernelDeleteMutex(g_lifecycle_mutex);
        g_lifecycle_mutex = -1;
    }
    return rc;
}

int tls_fixer_embedded_http_init(unsigned int size) {
    if (g_lifecycle_mutex >= 0) {
        int lock = sceKernelLockMutex(g_lifecycle_mutex, 1, NULL);
        if (lock < 0) return lock;
        if (!g_http_live && g_runtime_live && cleanup() < 0) {
            sceKernelUnlockMutex(g_lifecycle_mutex, 1);
            return TLS_FIXER_SCE_HTTP_ERROR_SSL;
        }
    }
    int rc = g_tls_fixer_embedded_bindings.http_init(size);
    if (rc == 0) {
        g_http_live = 1;
        if (g_lifecycle_mutex >= 0) (void)initialize();
        tls_fixer_gate_open(&g_gate);
    }
    if (g_lifecycle_mutex >= 0) sceKernelUnlockMutex(g_lifecycle_mutex, 1);
    TLS_FIXER_LOG("event=http.init pool=%u rc=%08X state=%u error=%08X", size, rc,
        g_tls_fixer_http.state, g_last_error);
    return rc;
}

int tls_fixer_embedded_http_term(void) {
    if (g_lifecycle_mutex >= 0) {
        int lock = sceKernelLockMutex(g_lifecycle_mutex, 1, NULL);
        if (lock < 0) return lock;
    }
    int previous = g_tls_fixer_http.state;
    g_tls_fixer_http.state = TLS_FIXER_PROVIDER_STOPPING;
    int rc = g_tls_fixer_embedded_bindings.http_term();
    if (rc < 0) {
        g_tls_fixer_http.state = previous;
        if (g_lifecycle_mutex >= 0) sceKernelUnlockMutex(g_lifecycle_mutex, 1);
        return rc;
    }
    g_http_live = 0;
    if (g_lifecycle_mutex >= 0) {
        int destroyed = cleanup();
        if (destroyed < 0) g_last_error = destroyed;
        sceKernelUnlockMutex(g_lifecycle_mutex, 1);
    }
    return rc;
}

#if TLS_FIXER_ENABLE_DEBUG_LOG
/* Exact native 3.74 parser, verified by the merger's RX hash. This diagnostic
 * forwarding export is absent from the quiet payload. It remains usable before
 * HTTP initialization, as the original stateless parser is. */
int tls_fixer_embedded_parse_header(const char *headers, unsigned int length,
    const char *name, const char **value, unsigned int *value_length) {
    typedef int (*Parse)(const char *, unsigned int, const char *, const char **, unsigned int *);
    Parse native = (Parse)((uintptr_t)g_tls_fixer_embedded_bindings.text + 0xde51u);
    int rc = native(headers, length, name, value, value_length);
    TLS_FIXER_LOG("event=header.parse name=%s rc=%08X bytes=%u", name ? name : "(null)", rc, length);
    if (rc >= 0 && name && value && *value && value_length &&
        (strcmp(name, "Content-Type") == 0 || strcmp(name, "X-I-5-Status") == 0))
        TLS_FIXER_LOG("event=header.selected name=%s bytes=%u value=%.*s", name, *value_length,
            (int)(*value_length < 96u ? *value_length : 96u), *value);
    if (rc < 0 && headers && length)
        TLS_FIXER_LOG("event=header.input bytes=%u prefix=%.*s", length,
            (int)(length < 320u ? length : 320u), headers);
    return rc;
}
#endif

int tls_fixer_embedded_create(void *request, int socket) {
    if (!tls_fixer_embedded_enter()) return (int)UINT32_C(0x80431001);
    int handled = 0;
    int rc = g_tls_fixer_http.state == TLS_FIXER_PROVIDER_STOPPING ? TLS_FIXER_SCE_HTTP_ERROR_SSL :
        TLS_FIXER_EMBEDDED_NATIVE_CONTROL ? 0 : tls_fixer_transport_create(request, socket, &handled);
    if (g_tls_fixer_http.state == TLS_FIXER_PROVIDER_STOPPING) handled = 1;
    if (TLS_FIXER_EMBEDDED_NATIVE_CONTROL) TLS_FIXER_LOG("event=transport.control native=1 socket=%d", socket);
    if (!handled) { __atomic_add_fetch(&g_fallbacks, 1, __ATOMIC_RELAXED); rc = g_tls_fixer_embedded_bindings.create(request, socket); }
    else if (rc == 0) __atomic_add_fetch(&g_creates, 1, __ATOMIC_RELAXED);
#if TLS_FIXER_EMBEDDED_COMPARE_HTTP
    if (rc == 0) tls_fixer_embedded_compare_identity(request);
    if (rc == 0 && !handled) tls_fixer_embedded_observe_native_bio(request, socket);
#endif
    tls_fixer_embedded_leave();
    return rc;
}

int tls_fixer_embedded_connect(void *request) {
    if (!tls_fixer_embedded_enter()) return (int)UINT32_C(0x80431001);
    int handled = 0;
    int rc = tls_fixer_transport_connect(request, &handled);
    if (!handled) rc = g_tls_fixer_embedded_bindings.connect(request);
#if TLS_FIXER_EMBEDDED_COMPARE_HTTP
    if (!handled && rc == 0) tls_fixer_embedded_compare_connected(request);
#endif
    tls_fixer_embedded_leave(); return rc;
}
int tls_fixer_embedded_map_io(void *connection, int result) {
    if (!tls_fixer_embedded_enter()) return (int)UINT32_C(0x80431001);
    int handled = 0;
    int rc = tls_fixer_transport_map_io(connection, result, &handled);
    if (!handled) rc = g_tls_fixer_embedded_bindings.map_io(connection, result);
    tls_fixer_embedded_leave(); return rc;
}
int tls_fixer_embedded_read(void *connection, void *buffer, unsigned int length) {
    if (!tls_fixer_embedded_enter()) return (int)UINT32_C(0x80431001);
    int handled = 0;
    int rc = tls_fixer_transport_read(connection, buffer, length, &handled);
    if (!handled) rc = g_tls_fixer_embedded_bindings.read(connection, buffer, length);
    tls_fixer_embedded_leave(); return rc;
}
int tls_fixer_embedded_write(void *connection, const void *buffer, unsigned int length) {
    if (!tls_fixer_embedded_enter()) return (int)UINT32_C(0x80431001);
    int handled = 0;
    int rc = tls_fixer_transport_write(connection, buffer, length, &handled);
    if (!handled) rc = g_tls_fixer_embedded_bindings.write(connection, buffer, length);
#if TLS_FIXER_EMBEDDED_COMPARE_HTTP
    tls_fixer_embedded_compare_write(connection, buffer, length, rc, handled);
#endif
    tls_fixer_embedded_leave(); return rc;
}
int tls_fixer_embedded_shutdown(void *connection) {
    if (!tls_fixer_embedded_enter()) return (int)UINT32_C(0x80431001);
    int handled = 0;
    int rc = tls_fixer_transport_shutdown(connection, &handled);
    if (!handled) rc = g_tls_fixer_embedded_bindings.shutdown(connection);
    tls_fixer_embedded_leave(); return rc;
}

int tls_fixer_embedded_create_connection(int t, const char *h, const char *s, unsigned short p, int k) {
    if (!tls_fixer_embedded_enter()) return (int)UINT32_C(0x80431001);
    int rc = tls_fixer_embedded_redirect_connection(t, h, s, p, k);
    tls_fixer_embedded_leave(); return rc;
}
int tls_fixer_embedded_create_connection_url(int t, const char *u, int k) {
    if (!tls_fixer_embedded_enter()) return (int)UINT32_C(0x80431001);
    int rc = tls_fixer_embedded_redirect_connection_url(t, u, k);
    tls_fixer_embedded_leave(); return rc;
}
int tls_fixer_embedded_create_request_url(int c, int m, const char *u, SceULong64 l) {
    if (!tls_fixer_embedded_enter()) return (int)UINT32_C(0x80431001);
    int rc = tls_fixer_embedded_redirect_request_url(c, m, u, l);
    tls_fixer_embedded_leave(); return rc;
}

const uint32_t *tls_fixer_embedded_stats(void) {
    static uint32_t values[10];
    TlsFixerRuntimeStats heap = {0};
    (void)tls_fixer_user_runtime_stats(&heap);
    values[0] = 0x41584654; values[1] = 2; values[2] = g_tls_fixer_http.state;
    values[3] = (uint32_t)g_last_error; values[4] = heap.capacity; values[5] = heap.used;
    values[6] = heap.peak; values[7] = __atomic_load_n(&g_creates, __ATOMIC_RELAXED);
    values[8] = __atomic_load_n(&g_fallbacks, __ATOMIC_RELAXED); values[9] = tls_fixer_gate_count(&g_gate);
    return values;
}

int tls_fixer_embedded_active(void) {
    return !TLS_FIXER_EMBEDDED_NATIVE_CONTROL &&
        g_tls_fixer_http.state == TLS_FIXER_PROVIDER_ACTIVE && g_last_error == 0;
}
