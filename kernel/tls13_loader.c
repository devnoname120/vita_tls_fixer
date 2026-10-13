#include "tls13_loader.h"
#include "native_module_api.h"
#include "memory_probe.h"

#include <psp2/io/fcntl.h>
#include <psp2kern/io/fcntl.h>
#include <psp2kern/io/stat.h>
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/sysroot.h>
#include <psp2kern/kernel/threadmgr/misc.h>
#include <psp2kern/kernel/threadmgr/mutex.h>
#include <psp2kern/kernel/utils.h>

#include <stddef.h>
#include <stdint.h>

#include "tls_fixer/sony_abi.h"
#include "tls_fixer/browser_abi.h"
#include "tls_fixer/path.h"
#include "tls_fixer/browser_start_diagnostics.h"
#include "boot_trace.h"
#ifndef TLS_FIXER_INSPECT_CONNECT_PATCH
#define TLS_FIXER_INSPECT_CONNECT_PATCH 0
#endif
#if TLS_FIXER_INSPECT_CONNECT_PATCH
#include "code_snapshot.h"
#if !TLS_FIXER_BROWSER_START_DIAGNOSTICS || !TLS_FIXER_BROWSER_ACTIVATION || !TLS_FIXER_TRACE_MODULE_PATHS
#error "Connect snapshots require the queued browser startup diagnostic"
#endif
#endif

/* VitaSDK supplies this native stub but omits its declaration from the kernel I/O header. */
SceUID ksceIoOpenForPid(SceUID pid, const char *filename, int flags, unsigned int mode);

#ifndef TLS_FIXER_PREPARE_ONLY
#define TLS_FIXER_PREPARE_ONLY 0
#endif

#ifndef TLS_FIXER_REDIRECTION_ONLY
#define TLS_FIXER_REDIRECTION_ONLY 0
#endif
#ifndef TLS_FIXER_PREPARE_EXTENDED_STACK
#define TLS_FIXER_PREPARE_EXTENDED_STACK 0
#endif
#ifndef TLS_FIXER_PREPARE_NO_MODULE_QUERIES
#define TLS_FIXER_PREPARE_NO_MODULE_QUERIES 0
#endif
#ifndef TLS_FIXER_PREPARE_TARGET_QUERY_ONLY
#define TLS_FIXER_PREPARE_TARGET_QUERY_ONLY 0
#endif
#ifndef TLS_FIXER_PREPARE_LIST_TARGET_ONLY
#define TLS_FIXER_PREPARE_LIST_TARGET_ONLY 0
#endif
#ifndef TLS_FIXER_PREPARE_NAME_QUERY
#define TLS_FIXER_PREPARE_NAME_QUERY 0
#endif
#ifndef TLS_FIXER_BROWSER_ACTIVATION
#define TLS_FIXER_BROWSER_ACTIVATION 0
#endif
#if TLS_FIXER_PREPARE_NAME_QUERY
#include <taihen.h>
#if defined(__arm__)
_Static_assert(sizeof(tai_module_info_t) == 0x38, "taiHEN ARM32 module-info extent");
#endif
#endif
#if TLS_FIXER_PREPARE_NO_MODULE_QUERIES && (!TLS_FIXER_PREPARE_ONLY || !TLS_FIXER_PREPARE_EXTENDED_STACK || !TLS_FIXER_ENABLE_BOOT_TRACE)
#error "Omitting module queries is restricted to traced native-stack preparation diagnostics"
#endif
#if TLS_FIXER_PREPARE_TARGET_QUERY_ONLY && (!TLS_FIXER_PREPARE_ONLY || !TLS_FIXER_PREPARE_EXTENDED_STACK || !TLS_FIXER_ENABLE_BOOT_TRACE || TLS_FIXER_PREPARE_NO_MODULE_QUERIES)
#error "Target-only queries require an exclusive traced native-stack preparation diagnostic"
#endif
#if TLS_FIXER_PREPARE_LIST_TARGET_ONLY && (!TLS_FIXER_PREPARE_ONLY || !TLS_FIXER_PREPARE_EXTENDED_STACK || !TLS_FIXER_ENABLE_BOOT_TRACE || TLS_FIXER_PREPARE_NO_MODULE_QUERIES || TLS_FIXER_PREPARE_TARGET_QUERY_ONLY)
#error "List-and-target queries require an exclusive traced native-stack preparation diagnostic"
#endif
#if TLS_FIXER_PREPARE_NAME_QUERY && (!TLS_FIXER_PREPARE_EXTENDED_STACK || \
    ((TLS_FIXER_PREPARE_ONLY || TLS_FIXER_BROWSER_ACTIVATION) && !TLS_FIXER_ENABLE_BOOT_TRACE) || \
    TLS_FIXER_PREPARE_NO_MODULE_QUERIES || TLS_FIXER_PREPARE_TARGET_QUERY_ONLY || TLS_FIXER_PREPARE_LIST_TARGET_ONLY)
#error "Name queries require the native stack and an unambiguous target-query strategy"
#endif
#if TLS_FIXER_BROWSER_ACTIVATION && (TLS_FIXER_PREPARE_ONLY || TLS_FIXER_REDIRECTION_ONLY || !TLS_FIXER_PREPARE_NAME_QUERY || !TLS_FIXER_PREPARE_EXTENDED_STACK || !TLS_FIXER_ENABLE_BOOT_TRACE)
#error "Browser activation requires exclusive traced native-stack name lookup with preparation-only disabled"
#endif

#define TLS_FIXER_LIBHTTP_PATH "vs0:/data/external/tls_fixer/libhttp.suprx"
#ifndef TLS_FIXER_HTTP_PROVIDER_PATH
#define TLS_FIXER_HTTP_PROVIDER_PATH "vs0:/data/external/tls_fixer/tls_fixer_http.suprx"
#endif
#define TLS_FIXER_PROVIDER_PATH TLS_FIXER_HTTP_PROVIDER_PATH
#ifndef TLS_FIXER_HTTP_TEST_TITLE_ID
#define TLS_FIXER_HTTP_TEST_TITLE_ID ""
#endif
#define TLS_FIXER_HASH_BUFFER_SIZE UINT32_C(1024)
#define TLS_FIXER_HASH_WORKSPACE_SIZE UINT32_C(4096)
#define TLS_FIXER_MAX_PROCESS_MODULES UINT32_C(256)
#define TLS_FIXER_QUERY_WORKSPACE_SIZE UINT32_C(4096)
#define TLS_FIXER_ARGUMENT_WORKSPACE_SIZE UINT32_C(4096)

_Static_assert(sizeof(SceKernelAllocMemBlockKernelOpt) == 0x58, "Native allocation option extent");
_Static_assert(offsetof(SceKernelAllocMemBlockKernelOpt, pid) == 0x24, "Native allocation PID offset");

static const uint8_t g_expected_libhttp_sha256[SCE_SHA256_DIGEST_SIZE] = {
    0x42, 0xBC, 0x7E, 0x34, 0x07, 0x79, 0x64, 0xAC,
    0x7E, 0xDC, 0x43, 0x65, 0xAB, 0xAD, 0x8A, 0xF9,
    0xBF, 0x41, 0x79, 0x3A, 0x34, 0xD2, 0xC7, 0xEF,
    0xD6, 0x31, 0x97, 0x6F, 0x7D, 0x27, 0x39, 0xC1,
};

static const uint8_t g_expected_browser_sha256[SCE_SHA256_DIGEST_SIZE] = {
    0x73, 0x88, 0x62, 0x13, 0x38, 0x19, 0xfc, 0x37,
    0xbc, 0x21, 0xf7, 0x14, 0xda, 0x7c, 0xa7, 0x6c,
    0x72, 0xd7, 0x3a, 0x62, 0x0a, 0xfa, 0xfb, 0xe6,
    0xa9, 0x40, 0xd8, 0x7d, 0xd4, 0xe6, 0xdc, 0x58,
};

typedef struct LoaderTarget {
    const char *module_path;
    const char *provider_path;
    const char *provider_name;
    const uint8_t *hash;
    uint32_t start_magic;
    uint32_t start_version;
} LoaderTarget;

static const LoaderTarget targets[] = {
    {TLS_FIXER_LIBHTTP_PATH, TLS_FIXER_PROVIDER_PATH, "tls_fixer_http", g_expected_libhttp_sha256,
        TLS_FIXER_START_MAGIC, TLS_FIXER_START_VERSION},
    {"vs0:/data/external/tls_fixer/ScePsp2Compat.suprx", TLS_FIXER_BROWSER_PROVIDER_BOOT_PATH,
        "tls_fixer", g_expected_browser_sha256, TLS_FIXER_BROWSER_START_MAGIC, TLS_FIXER_BROWSER_START_VERSION}
};

static uint8_t ready[2];
static struct { SceUID pid; unsigned int target; } in_flight[64];
static SceUID g_injection_mutex = -1;

typedef struct HashWorkspace {
    SceSha256Context context;
    uint8_t buffer[TLS_FIXER_HASH_BUFFER_SIZE];
} HashWorkspace;

_Static_assert(sizeof(HashWorkspace) <= TLS_FIXER_HASH_WORKSPACE_SIZE,
    "hash workspace exceeds its bounded allocation");

static int trace_hash(const char *stage, SceUID pid, SceUID module_id, int result) {
    if (pid <= 0) return 0;
    return tls_fixer_boot_trace_event(stage, pid, module_id, result);
}

static int hash_file_sha256(const char *path, uint8_t digest[SCE_SHA256_DIGEST_SIZE],
    SceUID pid, SceUID module_id, SceUID namespace_pid) {
    HashWorkspace *workspace = NULL;
    void *allocation = NULL;
    SceUID descriptor = -1, memory;
    int result = -1, first = 1;

    /* The nested loader stack must not also hold the file buffer and SHA state. */
    if (trace_hash("hash.alloc.enter", pid, module_id, TLS_FIXER_HASH_WORKSPACE_SIZE) < 0) return -1;
    memory = ksceKernelAllocMemBlock("tls_fixer hash workspace", SCE_KERNEL_MEMBLOCK_TYPE_KERNEL_RW,
        TLS_FIXER_HASH_WORKSPACE_SIZE, NULL);
    if (trace_hash("hash.alloc.return", pid, module_id, memory) < 0) goto cleanup;
    if (memory < 0) return memory;
    if (trace_hash("hash.base.enter", pid, module_id, 0) < 0) goto cleanup;
    int base_result = ksceKernelGetMemBlockBase(memory, &allocation);
    if (base_result >= 0 && allocation != NULL) workspace = allocation;
    if (trace_hash("hash.base.return", pid, module_id, base_result) < 0 || workspace == NULL) goto cleanup;

    if (trace_hash("hash.open.enter", pid, module_id, 0) < 0) goto cleanup;
    descriptor = namespace_pid > 0 ? ksceIoOpenForPid(namespace_pid, path, SCE_O_RDONLY, 0)
        : ksceIoOpen(path, SCE_O_RDONLY, 0);
    if (trace_hash("hash.open.return", pid, module_id, descriptor) < 0) goto cleanup;
    if (descriptor < 0) {
        result = descriptor;
        goto cleanup;
    }

    if (trace_hash("hash.init.enter", pid, module_id, 0) < 0) goto cleanup;
    result = ksceSha256BlockInit(&workspace->context);
    if (trace_hash("hash.init.return", pid, module_id, result) < 0) result = -1;
    if (result < 0) goto cleanup;
    if (trace_hash("hash.stream.enter", pid, module_id, 0) < 0) { result = -1; goto cleanup; }
    while (result >= 0) {
        if (first && trace_hash("hash.read.enter", pid, module_id, 0) < 0) { result = -1; break; }
        int bytes_read = ksceIoRead(descriptor, workspace->buffer, sizeof(workspace->buffer));
        if (first && trace_hash("hash.read.return", pid, module_id, bytes_read) < 0) { result = -1; break; }
        if (bytes_read < 0) {
            result = bytes_read;
            break;
        }
        if (bytes_read == 0) {
            result = 0;
            break;
        }
        if (first && trace_hash("hash.update.enter", pid, module_id, bytes_read) < 0) { result = -1; break; }
        result = ksceSha256BlockUpdate(&workspace->context, workspace->buffer, (SceSize)bytes_read);
        if (first && trace_hash("hash.update.return", pid, module_id, result) < 0) result = -1;
        first = 0;
    }
    if (trace_hash("hash.stream.return", pid, module_id, result) < 0) result = -1;
    if (result >= 0) {
        if (trace_hash("hash.finish.enter", pid, module_id, 0) < 0) { result = -1; goto cleanup; }
        result = ksceSha256BlockResult(&workspace->context, digest);
        if (trace_hash("hash.finish.return", pid, module_id, result) < 0) result = -1;
    }

cleanup:
    if (descriptor >= 0) {
        if (trace_hash("hash.close.enter", pid, module_id, result) < 0 && result >= 0) result = -1;
        int closed = ksceIoClose(descriptor);
        int recorded = trace_hash("hash.close.return", pid, module_id, closed);
        if ((closed < 0 || recorded < 0) && result >= 0) result = -1;
    }
    if (workspace != NULL) memset(workspace, 0, sizeof(*workspace));
    if (memory >= 0) {
        if (trace_hash("hash.free.enter", pid, module_id, result) < 0 && result >= 0) result = -1;
        int freed = ksceKernelFreeMemBlock(memory);
        int recorded = trace_hash("hash.free.return", pid, module_id, freed);
        if ((freed < 0 || recorded < 0) && result >= 0) result = -1;
    }
    return result;
}

#if !TLS_FIXER_REDIRECTION_ONLY
typedef struct QueryWorkspace {
    SceUID module_ids[TLS_FIXER_MAX_PROCESS_MODULES];
    SceKernelModuleInfo info;
    char browser_module_path[256];
    SceKernelAllocMemBlockKernelOpt argument_options;
    TlsFixerStartArgs argument_echo;
#if TLS_FIXER_PREPARE_NAME_QUERY
    tai_module_info_t name_info;
    SceUID name_target_uid;
#endif
} QueryWorkspace;

_Static_assert(sizeof(QueryWorkspace) <= TLS_FIXER_QUERY_WORKSPACE_SIZE,
    "module query workspace exceeds its bounded allocation");

#if TLS_FIXER_PREPARE_NAME_QUERY
static int named_module_matches(const tai_module_info_t *info, const char *name) {
    return info->modid > 0 && memchr(info->name, '\0', sizeof(info->name)) != NULL &&
        strcmp(info->name, name) == 0;
}

static int lookup_name(SceUID pid, const char *name, tai_module_info_t *info,
    const char *enter_stage, const char *return_stage) {
    memset(info, 0, sizeof(*info));
    info->size = sizeof(*info);
    if (tls_fixer_boot_trace_event(enter_stage, pid, 0, 0) < 0) return -1;
    int result = taiGetModuleInfoForKernel(pid, name, info);
    if (tls_fixer_boot_trace_event(return_stage, pid, result == 0 ? info->modid : 0, result) < 0) return -1;
    return result;
}

static int provider_is_loaded_by_name(SceUID pid, const char *target_name,
    const char *provider_name, QueryWorkspace *workspace) {
    tai_module_info_t *info = &workspace->name_info;
    int result = lookup_name(pid, target_name, info, "name.target.enter", "name.target.return");
    if (result != 0 || !named_module_matches(info, target_name)) return -1;
    workspace->name_target_uid = info->modid;
    result = lookup_name(pid, provider_name, info, "name.provider.enter", "name.provider.return");
    /* Only taiHEN's explicit not-found result establishes absence. */
    if (result == (int32_t)UINT32_C(0x90010002)) return 0;
    return result == 0 && named_module_matches(info, provider_name) ? 1 : -1;
}
#elif !TLS_FIXER_PREPARE_NO_MODULE_QUERIES && !TLS_FIXER_PREPARE_TARGET_QUERY_ONLY
static int provider_is_loaded(SceUID pid, const char *module_name, QueryWorkspace *workspace) {
    SceSize module_count = TLS_FIXER_MAX_PROCESS_MODULES;
    SceSize index;
    int query_result;

    if (tls_fixer_boot_trace_event("module.list.enter", pid, 0, (int32_t)module_count) < 0) return -1;
    query_result = ksceKernelGetModuleList(
            pid,
            0xFF,
            1,
            workspace->module_ids,
            &module_count);
    if (tls_fixer_boot_trace_event("module.list.return", pid, (int32_t)module_count, query_result) < 0) return -1;
    if (query_result < 0) return -1;
    if (module_count >= TLS_FIXER_MAX_PROCESS_MODULES) {
        return -1;
    }
    if (TLS_FIXER_PREPARE_LIST_TARGET_ONLY) {
        /* This diagnostic cannot start a provider or claim a completed presence scan. */
        return tls_fixer_boot_trace_event("module.inspect.skipped", pid, (int32_t)module_count, 0);
    }

    for (index = 0; index < module_count; ++index) {
        SceKernelModuleInfo *info = &workspace->info;

        memset(info, 0, sizeof(*info));
        info->size = sizeof(*info);
        if (tls_fixer_boot_trace_event("module.info.enter", pid, workspace->module_ids[index], (int32_t)index) < 0) return -1;
        query_result = ksceKernelGetModuleInfo(pid, workspace->module_ids[index], info);
        if (tls_fixer_boot_trace_event("module.info.return", pid, workspace->module_ids[index], query_result) < 0) return -1;
        if (query_result < 0) return -1;
        if (strcmp(info->module_name, module_name) == 0) {
            return 1;
        }
    }
    return 0;
}
#endif
#endif

static int target_matches(const LoaderTarget *target, SceUID pid, SceUID module_id,
    SceUID module_namespace_pid, SceUID provider_namespace_pid) {
    uint8_t digest[SCE_SHA256_DIGEST_SIZE];
    SceIoStat status;
    int matches = 0;
    if (trace_hash("hash.stat.enter", pid, module_id, 0) < 0) return 0;
    int found;
    if (provider_namespace_pid > 0) {
        SceUID fd = ksceIoOpenForPid(provider_namespace_pid, target->provider_path, SCE_O_RDONLY, 0);
        found = fd;
        if (fd >= 0) {
            found = ksceIoGetstatByFd(fd, &status);
            int closed = ksceIoClose(fd);
            if (closed < 0) found = closed;
        }
    } else {
        found = ksceIoGetstat(target->provider_path, &status);
    }
    if (trace_hash("hash.stat.return", pid, module_id, found) < 0 || found < 0) return 0;
    if (hash_file_sha256(target->module_path, digest, pid, module_id, module_namespace_pid) >= 0 &&
        trace_hash("hash.compare.enter", pid, module_id, 0) >= 0) {
        int compared = timingsafe_memcmp(digest, target->hash, sizeof(digest));
        matches = trace_hash("hash.compare.return", pid, module_id, compared) >= 0 && compared == 0;
    }
    memset(digest, 0, sizeof(digest));
    return matches;
}

int tls_fixer_kernel_loader_init(void) {
    if (g_injection_mutex >= 0) return -1;
    memset(ready, 0, sizeof(ready));
    memset(in_flight, 0, sizeof(in_flight));
    for (size_t i = 0; i < sizeof(targets)/sizeof(targets[0]); ++i) {
        ready[i] = (uint8_t)(!(TLS_FIXER_BROWSER_ACTIVATION && i == 0) &&
            target_matches(&targets[i], 0, 0, 0, 0));
    }
    if (!ready[0] && !ready[1]) return -1;
    g_injection_mutex = ksceKernelCreateMutex("tls_fixer inject", 0, 0, NULL);
    if (g_injection_mutex < 0) {
        memset(ready, 0, sizeof(ready));
        return g_injection_mutex;
    }
    return 0;
}

void tls_fixer_kernel_loader_destroy(void) {
    memset(ready, 0, sizeof(ready));
    if (g_injection_mutex >= 0) {
        (void)ksceKernelDeleteMutex(g_injection_mutex);
        g_injection_mutex = -1;
    }
}

int tls_fixer_kernel_loader_ready(void) {
    return ready[0];
}

int tls_fixer_kernel_browser_loader_ready(void) {
    return ready[1];
}

#if !TLS_FIXER_REDIRECTION_ONLY
static int inject_target(SceUID pid, SceUID module_id, unsigned int target_index, const char *provider_path) {
    const LoaderTarget *target = &targets[target_index];
    const char *file_path = target_index == 1
        ? target->provider_path : provider_path;
    const SceUID module_namespace_pid = target_index == 1 ? pid : 0;
    /* Load the installed provider globally, into pid. Only the compat file uses its overlay. */
    const SceUID provider_namespace_pid = 0;
    QueryWorkspace *workspace = NULL;
    void *allocation = NULL;
    SceUID query_memory = -1;
    SceUID argument_memory = -1;
#if !TLS_FIXER_PREPARE_NO_MODULE_QUERIES
    void *user_arguments = NULL;
    TlsFixerStartArgs arguments;
    SceKernelModuleInfo *target_info;
    int start_status = SCE_KERNEL_START_FAILED;
#if !TLS_FIXER_PREPARE_TARGET_QUERY_ONLY
    int loaded;
#endif
    SceUID provider_modid;
#endif
    int result;
    size_t slot = sizeof(in_flight)/sizeof(in_flight[0]);

    if (!ready[target_index] || g_injection_mutex < 0 || pid <= 0 || module_id < 0 || provider_path == NULL) {
        return -1;
    }
    if (tls_fixer_boot_trace_event("reserve.enter", pid, module_id, (int32_t)target_index) < 0) return -1;
    result = ksceKernelLockMutex(g_injection_mutex, 1, NULL);
    if (result < 0) {
        (void)tls_fixer_boot_trace_event("reserve.failed", pid, module_id, result);
        return result;
    }

    for (size_t i = 0; i < sizeof(in_flight)/sizeof(in_flight[0]); ++i) {
        if (in_flight[i].pid == pid && in_flight[i].target == target_index) {
            (void)ksceKernelUnlockMutex(g_injection_mutex, 1);
            return 1;
        }
        if (in_flight[i].pid == 0 && slot == sizeof(in_flight)/sizeof(in_flight[0])) slot = i;
    }
    if (slot == sizeof(in_flight)/sizeof(in_flight[0])) {
        (void)ksceKernelUnlockMutex(g_injection_mutex, 1);
        return -1;
    }
    in_flight[slot].pid = pid;
    in_flight[slot].target = target_index;
    (void)ksceKernelUnlockMutex(g_injection_mutex, 1);

    result = -1;
    if (tls_fixer_boot_trace_event("reserve.return", pid, module_id, (int32_t)slot) < 0) goto cleanup;
    /* Query buffers must not consume the nested native loader's kernel stack. */
    if (tls_fixer_boot_trace_event("query.alloc.enter", pid, module_id, TLS_FIXER_QUERY_WORKSPACE_SIZE) < 0) goto cleanup;
    query_memory = ksceKernelAllocMemBlock("tls_fixer query workspace", SCE_KERNEL_MEMBLOCK_TYPE_KERNEL_RW,
        TLS_FIXER_QUERY_WORKSPACE_SIZE, NULL);
    if (tls_fixer_boot_trace_event("query.alloc.return", pid, module_id, query_memory) < 0 || query_memory < 0) goto cleanup;
    if (tls_fixer_boot_trace_event("query.base.enter", pid, module_id, 0) < 0) goto cleanup;
    int base_result = ksceKernelGetMemBlockBase(query_memory, &allocation);
    if (base_result >= 0 && allocation != NULL) workspace = allocation;
    if (tls_fixer_boot_trace_event("query.base.return", pid, module_id, base_result) < 0 || workspace == NULL) goto cleanup;
#if TLS_FIXER_PREPARE_NO_MODULE_QUERIES || TLS_FIXER_PREPARE_TARGET_QUERY_ONLY
    if (tls_fixer_boot_trace_event("scan.skipped", pid, module_id, 0) < 0) goto cleanup;
#else
    if (tls_fixer_boot_trace_event("scan.enter", pid, module_id, 0) < 0) goto cleanup;
#if TLS_FIXER_PREPARE_NAME_QUERY
    loaded = provider_is_loaded_by_name(pid, target_index == 1 ? "ScePsp2Compat" : "SceLibHttp",
        target->provider_name, workspace);
#else
    loaded = provider_is_loaded(pid, target->provider_name, workspace);
#endif
    if (tls_fixer_boot_trace_event("scan.return", pid, module_id, loaded) < 0) goto cleanup;
    if (loaded < 0) {
        result = loaded;
        goto cleanup;
    }
    if (loaded != 0) {
        result = 0;
        goto cleanup;
    }
    /* The HTTP provider now owns its sceClib mspace; host SceLibc is not a prerequisite. */
#endif

    result = -1;
    LoaderTarget verification_target = *target;
    if (target_index == 1) {
        if (!tls_fixer_browser_module_path(provider_path, workspace->browser_module_path,
                sizeof(workspace->browser_module_path))) goto cleanup;
        verification_target.provider_path = file_path;
        verification_target.module_path = workspace->browser_module_path;
    }
    if (tls_fixer_boot_trace_event("hash.enter", pid, module_id, (int32_t)target_index) < 0) goto cleanup;
    int matched = target_matches(&verification_target, pid, module_id,
        module_namespace_pid, provider_namespace_pid);
    if (tls_fixer_boot_trace_event("hash.return", pid, module_id, matched) < 0) goto cleanup;
    if (!matched) {
        result = -1;
        goto cleanup;
    }
#if TLS_FIXER_PREPARE_NO_MODULE_QUERIES
    if (tls_fixer_boot_trace_event("target.skipped", pid, module_id, 0) < 0) goto cleanup;
#else
    target_info = &workspace->info;
    memset(target_info, 0, sizeof(*target_info));
    target_info->size = sizeof(*target_info);
    if (tls_fixer_boot_trace_event("target.info.enter", pid, module_id, 0) < 0) goto cleanup;
    result = ksceKernelGetModuleInfo(pid, module_id, target_info);
    if (tls_fixer_boot_trace_event("target.info.return", pid, target_info->modid, result) < 0) {
        result = -1;
        goto cleanup;
    }
    if (result < 0 || target_info->modid <= 0 ||
        strcmp(target_info->module_name, target_index == 1 ? "ScePsp2Compat" : "SceLibHttp") != 0) {
        result = -1;
        goto cleanup;
    }
#if TLS_FIXER_PREPARE_NAME_QUERY
    if (target_info->modid != workspace->name_target_uid) {
        result = -1;
        goto cleanup;
    }
#endif
    if (TLS_FIXER_PREPARE_ONLY) {
        result = 0;
        goto cleanup;
    }
    if (TLS_FIXER_BROWSER_ACTIVATION) {
        void *text = target_info->segments[0].vaddr;
        /* A process-local provider must not redirect a shared mapping for other processes. */
        if (text == NULL || tls_fixer_boot_trace_event("target.shared.enter", pid,
                (int32_t)(uintptr_t)text, 0) < 0) {
            result = -1;
            goto cleanup;
        }
        result = ksceKernelGetModuleIsSharedByAddr(pid, text);
        if (tls_fixer_boot_trace_event("target.shared.return", pid,
                (int32_t)(uintptr_t)text, result) < 0 || result != 0) {
            result = -1;
            goto cleanup;
        }
    }
#if TLS_FIXER_INSPECT_CONNECT_PATCH
    if (tls_fixer_code_snapshot(pid, target_info, TLS_FIXER_BROWSER_CONNECT_OFFSET, "code.before") < 0) {
        result = -1;
        goto cleanup;
    }
#endif
    arguments.magic = target->start_magic;
    arguments.version = target->start_version;
    arguments.libhttp_modid = target_info->modid;
    arguments.reserved = 0;

    /* The native entry-thread path copies from the current process's user address space. */
    if (ksceKernelGetProcessId() != pid) {
        result = -1;
        goto cleanup;
    }
    memset(&workspace->argument_options, 0, sizeof(workspace->argument_options));
    workspace->argument_options.size = sizeof(workspace->argument_options);
    workspace->argument_options.attr = SCE_KERNEL_ALLOC_MEMBLOCK_ATTR_HAS_PID;
    workspace->argument_options.pid = pid;
    if (tls_fixer_boot_trace_event("args.alloc.enter", pid, module_id, TLS_FIXER_ARGUMENT_WORKSPACE_SIZE) < 0) {
        result = -1;
        goto cleanup;
    }
    argument_memory = ksceKernelAllocMemBlock("tls_fixer start arguments", SCE_KERNEL_MEMBLOCK_TYPE_USER_RW,
        TLS_FIXER_ARGUMENT_WORKSPACE_SIZE, &workspace->argument_options);
    if (tls_fixer_boot_trace_event("args.alloc.return", pid, module_id, argument_memory) < 0 || argument_memory < 0) {
        result = -1;
        goto cleanup;
    }
    if (tls_fixer_boot_trace_event("args.base.enter", pid, module_id, 0) < 0) { result = -1; goto cleanup; }
    result = ksceKernelGetMemBlockBase(argument_memory, &user_arguments);
    if (tls_fixer_boot_trace_event("args.base.return", pid, module_id, result) < 0 ||
        result < 0 || user_arguments == NULL) { result = -1; goto cleanup; }
    if (tls_fixer_boot_trace_event("args.copy.enter", pid, module_id, sizeof(arguments)) < 0) { result = -1; goto cleanup; }
    result = ksceKernelCopyToUserProc(pid, user_arguments, &arguments, sizeof(arguments));
    if (tls_fixer_boot_trace_event("args.copy.return", pid, module_id, result) < 0 || result != 0) {
        result = -1;
        goto cleanup;
    }
    if (tls_fixer_boot_trace_event("args.verify.enter", pid, module_id, 0) < 0) { result = -1; goto cleanup; }
    result = ksceKernelCopyFromUserProc(pid, &workspace->argument_echo, user_arguments, sizeof(arguments));
    if (result == 0 && memcmp(&workspace->argument_echo, &arguments, sizeof(arguments)) != 0) result = -1;
    if (tls_fixer_boot_trace_event("args.verify.return", pid, module_id, result) < 0 || result != 0) {
        result = -1;
        goto cleanup;
    }

    if (tls_fixer_boot_trace_event("provider.start.enter", pid, module_id, target_info->modid) < 0) {
        memset(&arguments, 0, sizeof(arguments));
        result = -1;
        goto cleanup;
    }
    provider_modid = ksceKernelLoadStartModuleForPid(
        pid,
        file_path,
        sizeof(arguments),
        user_arguments,
        provider_namespace_pid > 0 ? 0x1000 : 0,
        NULL,
        &start_status);
    memset(&arguments, 0, sizeof(arguments));

    if (tls_fixer_boot_trace_event("provider.start.return", pid, module_id, provider_modid) < 0 ||
        tls_fixer_boot_trace_event("provider.status", pid, provider_modid, start_status) < 0) {
        /* A completed user entry may already have published hooks, even if logging fails. */
        result = -1;
        goto cleanup;
    }
    if (provider_modid <= 0) {
        result = provider_modid < 0 ? provider_modid : -1;
        goto cleanup;
    }
    if (start_status != SCE_KERNEL_START_SUCCESS) {
        if (!TLS_FIXER_BROWSER_ACTIVATION) {
            (void)ksceKernelUnloadModuleForPid(pid, provider_modid, 0, NULL);
        }
        result = -1;
        goto cleanup;
    }
#if TLS_FIXER_INSPECT_CONNECT_PATCH
    if (tls_fixer_code_snapshot(pid, target_info, TLS_FIXER_BROWSER_CONNECT_OFFSET, "code.after") < 0 ||
        tls_fixer_code_snapshot(pid, target_info, 0xa6234, "code.wrapper") < 0) {
        result = -1;
        goto cleanup;
    }
    memset(target_info, 0, sizeof(*target_info));
    target_info->size = sizeof(*target_info);
    if (tls_fixer_boot_trace_event("code.provider.info.enter", pid, provider_modid, 0) < 0) {
        result = -1;
        goto cleanup;
    }
    result = ksceKernelGetModuleInfo(pid, provider_modid, target_info);
    if (tls_fixer_boot_trace_event("code.provider.info.return", pid, provider_modid, result) < 0 ||
        result != 0 || memcmp(target_info->module_name, "tls_fixer", sizeof("tls_fixer")) != 0 ||
        tls_fixer_code_snapshot(pid, target_info, 0, "code.provider") < 0) {
        result = -1;
        goto cleanup;
    }
#endif
#endif
    result = 0;

cleanup:
    if (argument_memory >= 0) {
        if (tls_fixer_boot_trace_event("args.free.enter", pid, module_id, result) < 0 && result >= 0) result = -1;
        int freed = ksceKernelFreeMemBlock(argument_memory);
        int recorded = tls_fixer_boot_trace_event("args.free.return", pid, module_id, freed);
        if ((freed < 0 || recorded < 0) && result >= 0) result = -1;
    }
    if (workspace != NULL) memset(workspace, 0, sizeof(*workspace));
    if (query_memory >= 0) {
        if (tls_fixer_boot_trace_event("query.free.enter", pid, module_id, result) < 0 && result >= 0) result = -1;
        int freed = ksceKernelFreeMemBlock(query_memory);
        int recorded = tls_fixer_boot_trace_event("query.free.return", pid, module_id, freed);
        if ((freed < 0 || recorded < 0) && result >= 0) result = -1;
    }
    (void)tls_fixer_boot_trace_event("cleanup.enter", pid, module_id, result);
    if (ksceKernelLockMutex(g_injection_mutex, 1, NULL) >= 0) {
        in_flight[slot].pid = 0;
        in_flight[slot].target = 0;
        (void)ksceKernelUnlockMutex(g_injection_mutex, 1);
    }
    (void)tls_fixer_boot_trace_event("cleanup.return", pid, module_id, result);
    return result;
}

#if TLS_FIXER_PREPARE_EXTENDED_STACK
typedef struct PreparationCall {
    SceUID pid;
    SceUID module_id;
    unsigned int target_index;
    const char *provider_path;
    int result;
    int called;
} PreparationCall;

static int prepare_on_native_stack(void *opaque) {
    PreparationCall *call = opaque;
    call->called = 1;
    if (tls_fixer_boot_trace_event("stack.callback.enter", call->pid, call->module_id, 0) < 0) return 0;
    call->result = inject_target(call->pid, call->module_id, call->target_index, call->provider_path);
    if (tls_fixer_boot_trace_event("stack.callback.return", call->pid, call->module_id, call->result) < 0) {
        call->result = -1;
    }
    return 0;
}

static int dispatch_preparation(SceUID pid, SceUID module_id, unsigned int target_index, const char *provider_path) {
    PreparationCall call = {pid, module_id, target_index, provider_path, -1, 0};
    tls_fixer_memory_probe_record("mem.stack.before", pid);
    if (tls_fixer_boot_trace_event("stack.extend.enter", pid, module_id, 16384) < 0) return -1;
    int result = ksceKernelRunWithStack(16384, prepare_on_native_stack, &call);
    tls_fixer_memory_probe_record("mem.stack.after", pid);
    if (tls_fixer_boot_trace_event("stack.extend.return", pid, module_id, result) < 0) return -1;
    if (result < 0) return result;
    return call.called ? call.result : -1;
}
#else
#define dispatch_preparation inject_target
#endif

int tls_fixer_kernel_inject_for_pid(SceUID pid, SceUID libhttp_modid) {
    if (TLS_FIXER_BROWSER_ACTIVATION) return -1;
    if (!ready[0] || g_injection_mutex < 0 || pid <= 0 || libhttp_modid < 0) return -1;
    if (!TLS_FIXER_PREPARE_ONLY) {
        char title_id[16] = {0};
        if (tls_fixer_boot_trace_event("http.title.enter", pid, libhttp_modid, 0) < 0) return -1;
        int result = ksceKernelSysrootGetProcessTitleId(pid, title_id, sizeof(title_id));
        if (tls_fixer_boot_trace_event("http.title.return", pid, libhttp_modid, result) < 0) return -1;
        if (result < 0) return result;
        /* Exclude the controller and WebKit helper before allocating an HTTP preparation stack. */
        if (memcmp(title_id, "NPXS10003", sizeof("NPXS10003")) == 0 ||
            memcmp(title_id, "NPXS10083", sizeof("NPXS10083")) == 0) {
            (void)tls_fixer_boot_trace_event("http.browser.skipped", pid, libhttp_modid, 0);
            return 0;
        }
        /* A staged diagnostic must not first execute in early system processes. */
        if (TLS_FIXER_HTTP_TEST_TITLE_ID[0] != '\0' &&
            strcmp(title_id, TLS_FIXER_HTTP_TEST_TITLE_ID) != 0) {
            (void)tls_fixer_boot_trace_event("http.test.skipped", pid, libhttp_modid, 0);
            return 0;
        }
    }
    return dispatch_preparation(pid, libhttp_modid, 0, targets[0].provider_path);
}

int tls_fixer_kernel_inject_browser_for_pid(SceUID pid, SceUID compat_modid, const char *provider_path) {
    return dispatch_preparation(pid, compat_modid, 1, provider_path);
}
#endif
