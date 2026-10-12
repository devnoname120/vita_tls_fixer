#include "post_start.h"
#include "boot_trace.h"
#include "tls13_loader.h"

#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/kernel/threadmgr/misc.h>
#include <psp2kern/kernel/threadmgr/mutex.h>
#include <stdint.h>

typedef struct PendingBrowser {
    SceUID pid;
    SceUID module;
    char path[TLS_FIXER_PENDING_BROWSER_PATH_SIZE];
} PendingBrowser;

static PendingBrowser pending[TLS_FIXER_PENDING_BROWSER_LIMIT];
static SceUID pending_mutex = -1;
static uint32_t pending_count;

int tls_fixer_post_start_init(void) {
    if (pending_mutex >= 0) return -1;
    SceUID created = ksceKernelCreateMutex("tls_fixer browser start", 0, 0, NULL);
    if (created < 0) return created;
    memset(pending, 0, sizeof(pending));
    __atomic_store_n(&pending_count, 0, __ATOMIC_RELEASE);
    pending_mutex = created;
    return 0;
}

int tls_fixer_post_start_destroy(void) {
    if (pending_mutex < 0) return 0;
    int result = ksceKernelDeleteMutex(pending_mutex);
    if (result < 0) return result;
    pending_mutex = -1;
    memset(pending, 0, sizeof(pending));
    __atomic_store_n(&pending_count, 0, __ATOMIC_RELEASE);
    return 0;
}

int tls_fixer_post_start_defer(SceUID pid, SceUID module, const char *path) {
    if (pending_mutex < 0 || pid <= 0 || module <= 0 || path == NULL) return -1;
    size_t length = strnlen(path, TLS_FIXER_PENDING_BROWSER_PATH_SIZE);
    if (length == 0 || length == TLS_FIXER_PENDING_BROWSER_PATH_SIZE) return -1;
    int result = ksceKernelLockMutex(pending_mutex, 1, NULL);
    if (result < 0) return result;
    size_t available = TLS_FIXER_PENDING_BROWSER_LIMIT;
    result = -1;
    for (size_t i = 0; i < TLS_FIXER_PENDING_BROWSER_LIMIT; ++i) {
        if (pending[i].pid == pid && pending[i].module == module) {
            result = strcmp(pending[i].path, path) == 0 ? 1 : -1;
            goto done;
        }
        if (pending[i].pid == 0 && available == TLS_FIXER_PENDING_BROWSER_LIMIT) available = i;
    }
    if (available != TLS_FIXER_PENDING_BROWSER_LIMIT) {
        PendingBrowser *item = &pending[available];
        item->pid = pid;
        item->module = module;
        memcpy(item->path, path, length + 1);
        (void)__atomic_add_fetch(&pending_count, 1, __ATOMIC_RELEASE);
        result = 0;
    }
done:
    if (ksceKernelUnlockMutex(pending_mutex, 1) < 0) return -1;
    return result;
}

int tls_fixer_post_start_complete(SceUID pid, SceUID module, int native_result) {
    char path[TLS_FIXER_PENDING_BROWSER_PATH_SIZE];
    int found = 0;
    if (__atomic_load_n(&pending_count, __ATOMIC_ACQUIRE) == 0) return 0;
    if (pid == 0) pid = ksceKernelGetProcessId();
    if (pending_mutex < 0 || pid <= 0 || module <= 0) return -1;
    int result = ksceKernelLockMutex(pending_mutex, 1, NULL);
    if (result < 0) return result;
    for (size_t i = 0; i < TLS_FIXER_PENDING_BROWSER_LIMIT; ++i) {
        if (pending[i].pid != pid || pending[i].module != module) continue;
        memcpy(path, pending[i].path, sizeof(path));
        memset(&pending[i], 0, sizeof(pending[i]));
        (void)__atomic_sub_fetch(&pending_count, 1, __ATOMIC_RELEASE);
        found = 1;
        break;
    }
    if (ksceKernelUnlockMutex(pending_mutex, 1) < 0) return -1;
    if (!found) return 0;

    /* Native start links imported variables; installing a detour earlier corrupts it. */
    if (tls_fixer_boot_trace_event("native.start.return", pid, module, native_result) < 0) return -1;
    if (native_result != 0) return native_result < 0 ? native_result : -1;
    if (tls_fixer_boot_trace_event("prepare.enter", pid, module, 1) < 0) return -1;
    result = tls_fixer_kernel_inject_browser_for_pid(pid, module, path);
    if (tls_fixer_boot_trace_event("prepare.return", pid, module, result) < 0) return -1;
    return result;
}
