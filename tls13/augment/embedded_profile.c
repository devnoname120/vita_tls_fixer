#include "embedded.h"
#include "hello_policy.h"
#include "provider.h"
#include "diagnostics.h"
#include <psp2/kernel/threadmgr/mutex.h>
#include <stdlib.h>

static TlsFixerHelloPolicy g_policy;
static int g_policy_live;

static int lock_policy(void) {
    if (!g_policy_live) return -1;
    int rc = sceKernelLockMutex(g_tls_fixer_http.registry_mutex, 1, NULL);
    if (rc < 0) atomic_store(&g_policy.uncertain, 1);
    return rc;
}
static void unlock_policy(void) { (void)sceKernelUnlockMutex(g_tls_fixer_http.registry_mutex, 1); }

void tls_fixer_embedded_profile_init(void) {
    tls_fixer_hello_policy_init(&g_policy, malloc, free);
    g_policy_live = 1;
}
void tls_fixer_embedded_profile_destroy(void) {
    /* The entry gate is closed and drained before runtime cleanup. */
    if (g_policy_live) tls_fixer_hello_policy_clear(&g_policy);
    g_policy_live = 0;
}

int tls_fixer_embedded_profile_for_request(const void *request) {
    if (lock_policy() < 0) return -1;
    /* Sony snapshots the connection settings into each request. An explicit
     * request override, or changing the parent afterwards, must follow that
     * request's settings rather than the transport connection's older copy. */
    int result = tls_fixer_hello_policy_get(&g_policy, (uintptr_t)request + 76u);
    unlock_policy();
    TLS_FIXER_LOG("event=profile.lookup request=%08X id=%08X key=%08X profile=%d",
        (unsigned int)(uintptr_t)request, tls_fixer_read_u32(request, 0),
        (unsigned int)((uintptr_t)request + 76u), result);
    return result;
}

static int private_option(int handle, unsigned int flags, int enable) {
    if (!tls_fixer_embedded_enter()) return (int)UINT32_C(0x80431001);
    TlsFixerEmbeddedBindings *b = &g_tls_fixer_embedded_bindings;
    unsigned int kind = ((unsigned int)handle >> 28) - 1u;
    void *object = NULL;
    uintptr_t key = 0;
    /* Hold a native reference across the original call and metadata update.
     * Never hold our registry mutex while executing any native function. */
    if ((flags & 0x40u) != 0 && kind < 3u &&
        b->acquire_object(&object, handle, kind, 0) >= 0 && object != NULL) {
        static const unsigned int offsets[] = {0, 100, 76};
        key = (uintptr_t)object + offsets[kind];
    }
    int rc = (enable ? b->enable_private : b->disable_private)(handle, flags);
    if (lock_policy() >= 0) {
        tls_fixer_hello_policy_private_result(&g_policy, key, flags, enable, rc);
        unlock_policy();
    }
    if (object != NULL) (void)b->release_object[kind](object);
    TLS_FIXER_LOG("event=tls.private_profile handle=%08X flags=%08X enable=%d rc=%08X key=%08X",
        handle, flags, enable, rc, (unsigned int)key);
    tls_fixer_embedded_leave();
    return rc;
}
int tls_fixer_embedded_enable_private(int h, unsigned int f) { return private_option(h, f, 1); }
int tls_fixer_embedded_disable_private(int h, unsigned int f) { return private_option(h, f, 0); }

int tls_fixer_embedded_copy_settings(const void *source, void *destination) {
    int entered = tls_fixer_embedded_enter();
    int profile = -1;
    if (entered && lock_policy() >= 0) {
        profile = tls_fixer_hello_policy_get(&g_policy, (uintptr_t)source);
        unlock_policy();
    }
    int rc = g_tls_fixer_embedded_bindings.copy_settings(source, destination);
    if (entered && rc >= 0 && lock_policy() >= 0) {
        tls_fixer_hello_policy_set(&g_policy, (uintptr_t)destination, profile);
        unlock_policy();
    }
    TLS_FIXER_LOG("event=profile.copy source=%08X destination=%08X entered=%d profile=%d rc=%08X",
        (unsigned int)(uintptr_t)source, (unsigned int)(uintptr_t)destination, entered, profile, rc);
    if (entered) tls_fixer_embedded_leave();
    return rc;
}

void tls_fixer_embedded_destroy_settings(void *settings) {
    int entered = tls_fixer_embedded_enter();
    /* Forget before native cleanup can release/reuse the allocation. */
    if (entered && lock_policy() >= 0) {
        tls_fixer_hello_policy_forget(&g_policy, (uintptr_t)settings);
        unlock_policy();
    }
    g_tls_fixer_embedded_bindings.destroy_settings(settings);
    if (entered) tls_fixer_embedded_leave();
}

static int free_failed(void *allocator, void *object, size_t settings_offset) {
    int entered = tls_fixer_embedded_enter();
    /* A constructor can copy settings, then fail before registering its
     * handle. Sony frees the object directly on these two exits, without the
     * ordinary settings destructor. Remove our marker before that free so a
     * later allocation cannot inherit an abandoned private profile. */
    if (entered && object != NULL && lock_policy() >= 0) {
        tls_fixer_hello_policy_forget(&g_policy, (uintptr_t)object + settings_offset);
        unlock_policy();
    }
    int rc = g_tls_fixer_embedded_bindings.free_allocation(allocator, object);
    if (entered) tls_fixer_embedded_leave();
    return rc;
}

int tls_fixer_embedded_free_failed_connection(void *allocator, void *object) {
    return free_failed(allocator, object, 100);
}
int tls_fixer_embedded_free_failed_request(void *allocator, void *object) {
    return free_failed(allocator, object, 76);
}
