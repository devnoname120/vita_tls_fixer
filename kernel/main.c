/*
    Original module-redirection code by SKGleba
    All Rights Reserved
*/

#include <psp2kern/kernel/debug.h>
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/processmgr.h>
#include <psp2kern/kernel/sysroot.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/types.h>
#include <taihen.h>
#include <vitasdkkern.h>

#include <stddef.h>
#include <stdint.h>

#include "tls_fixer/path.h"
#include "tls13_loader.h"
#include "psn_redirect.h"
#include "memory_probe.h"
#include "allocation_probe.h"
#include "self_disarm.h"
#include "disarm_result.h"
#include "hook_guard.h"
#include "native_module_api.h"
#include "browser_inventory.h"

#ifndef TLS_FIXER_ENABLE_SELF_DISARM
#define TLS_FIXER_ENABLE_SELF_DISARM 1
#endif

#ifndef TLS_FIXER_DISARM_RESULT_ONLY
#define TLS_FIXER_DISARM_RESULT_ONLY 0
#endif
#include "boot_trace.h"

#ifndef TLS_FIXER_SELF_DISARM_ONLY
#define TLS_FIXER_SELF_DISARM_ONLY 0
#endif

#ifndef TLS_FIXER_INITIALIZE_ONLY
#define TLS_FIXER_INITIALIZE_ONLY 0
#endif

#ifndef TLS_FIXER_REDIRECTION_ONLY
#define TLS_FIXER_REDIRECTION_ONLY 0
#endif

#ifndef TLS_FIXER_PREPARE_ONLY
#define TLS_FIXER_PREPARE_ONLY 0
#endif

#ifndef TLS_FIXER_BROWSER_ACTIVATION
#define TLS_FIXER_BROWSER_ACTIVATION 0
#endif

#ifndef TLS_FIXER_BROWSER_POST_START
#define TLS_FIXER_BROWSER_POST_START 0
#endif
#ifndef TLS_FIXER_SKIP_DNS_START
#define TLS_FIXER_SKIP_DNS_START 0
#endif
#ifndef TLS_FIXER_SKIP_HTTP_START
#define TLS_FIXER_SKIP_HTTP_START 0
#endif
#if TLS_FIXER_BROWSER_POST_START
#include "post_start.h"
#endif

#if TLS_FIXER_TRACE_MODULE_PATHS && (!TLS_FIXER_ENABLE_BOOT_TRACE || \
    (TLS_FIXER_REDIRECTION_ONLY && TLS_FIXER_BROWSER_ACTIVATION) || \
    (!TLS_FIXER_REDIRECTION_ONLY && !TLS_FIXER_BROWSER_ACTIVATION && !TLS_FIXER_BROWSER_POST_START))
#error Queued path diagnostics require exclusive redirection-only or browser-only activation
#endif

#define TLS_FIXER_MAX_MODULE_PATH ((size_t)0x400)
#define TLS_FIXER_PATH_OBSERVER_NAMESPACE_FLAG UINT32_C(0x1000)

static const char *const g_replacement_modules[] = {
    "vs0:/data/external/tls_fixer/ScePsp2Compat.suprx",
    "vs0:/data/external/tls_fixer/libhttp.suprx",
    "vs0:/data/external/tls_fixer/libssl.suprx",
    "vs0:/data/external/tls_fixer/old_dns_fix.suprx",
    "vs0:/data/external/tls_fixer/np_commerce2.suprx",
};

static uint8_t g_replace[sizeof(g_replacement_modules) / sizeof(g_replacement_modules[0])];
static uint8_t g_replace_iap;
static uint8_t g_dns_fix_state;
static int g_psn_redirect_ready;
static int g_loader_hook_id = -1;
static tai_hook_ref_t g_loader_hook_ref;
#if TLS_FIXER_BROWSER_POST_START
static int g_start_hook_id = -1;
static tai_hook_ref_t g_start_hook_ref;
#if defined(__arm__) && TLS_FIXER_ENABLE_BOOT_TRACE
typedef struct BrowserStartTrace { SceUID pid, module; } BrowserStartTrace;
static int trace_browser_module_on_stack(void *argument) {
    const BrowserStartTrace *call = argument;
    SceKernelModuleInfo info;
    uint32_t name[7];
    memset(&info, 0, sizeof(info));
    info.size = sizeof(info);
    int result = ksceKernelGetModuleInfo(call->pid, call->module, &info);
    if (result != 0) {
        (void)tls_fixer_boot_trace_event("browser.module.info", call->pid, call->module, result);
        return 0;
    }
    memcpy(name, info.module_name, sizeof(name));
    (void)tls_fixer_boot_trace_event("browser.module.name", call->pid, name[0], name[1]);
    (void)tls_fixer_boot_trace_event("browser.module.name2", call->pid, name[2], name[3]);
    (void)tls_fixer_boot_trace_event("browser.module.text", call->pid,
        (int32_t)(uintptr_t)info.segments[0].vaddr, (int32_t)info.state);
    return 0;
}
static void trace_browser_module(SceUID pid, SceUID module) {
    char title[16] = {0};
    if (ksceKernelSysrootGetProcessTitleId(pid, title, sizeof(title)) < 0 ||
        (memcmp(title, "NPXS10003", sizeof("NPXS10003")) != 0 &&
         memcmp(title, "NPXS10083", sizeof("NPXS10083")) != 0)) return;
    BrowserStartTrace call = {pid, module};
    tls_fixer_browser_inventory_request(pid);
    (void)ksceKernelRunWithStack(16384, trace_browser_module_on_stack, &call);
}
#endif

static int start_for_pid_patched(SceUID pid, SceUID module, SceSize size,
    const void *data, uint32_t flags, const void *options, int *status) {
    const SceUID target_pid = pid == 0 ? ksceKernelGetProcessId() : pid;
    int result = TAI_CONTINUE(int, g_start_hook_ref, pid, module, size, data, flags, options, status);
    (void)tls_fixer_post_start_complete(target_pid, module, result);
#if defined(__arm__) && TLS_FIXER_ENABLE_BOOT_TRACE
    trace_browser_module(target_pid, module);
#endif
    return result;
}
#endif

static int add_replace_flags(void) {
    SceIoStat status;
    size_t index;

    for (index = 0; index < sizeof(g_replace); ++index) {
        g_replace[index] = ksceIoGetstat(g_replacement_modules[index], &status) >= 0;
    }
    g_replace_iap = (uint8_t)(g_replace[1] && g_replace[2]);
    g_dns_fix_state = (uint8_t)((g_replace[3] && g_replace[4]) ? 2 : 0);
    g_psn_redirect_ready = tls_fixer_psn_redirect_init();
    if (g_psn_redirect_ready) g_dns_fix_state = 0;
    return g_replace[0] || g_replace_iap || g_dns_fix_state || g_psn_redirect_ready;
}

static SceUID load_for_pid_patched(
    SceUID pid,
    const char *path,
    uint32_t flags,
    int *ptr_to_four) {
    const char *load_path = path;
    uint32_t load_flags = flags;
    char browser_path[256];
    char browser_provider[256];
    int loads_replacement_libhttp = 0;
    int loads_replacement_libssl = 0;
    int loads_replacement_browser = 0;
    int route_kind = 0;
    int trace_ok = 1;
    SceUID result;
    tls_fixer_trace_status_note_load();
    const SceUID target_pid = pid == 0 ? ksceKernelGetProcessId() : pid;
    const int psn_redirect = tls_fixer_psn_redirect_wanted(target_pid, path,
        tls_fixer_path_equals(path, "vs0:sys/external/libhttp.suprx", TLS_FIXER_MAX_MODULE_PATH) ||
        tls_fixer_path_equals(path, "vs0:/sys/external/libhttp.suprx", TLS_FIXER_MAX_MODULE_PATH));

#if defined(__arm__) && TLS_FIXER_ENABLE_BOOT_TRACE
    if (tls_fixer_path_has_suffix(path, "ScePsp2Compat.suprx", TLS_FIXER_MAX_MODULE_PATH)) {
        static const char *const stages[] = {"compat.path0", "compat.path1", "compat.path2", "compat.path3",
            "compat.path4", "compat.path5", "compat.path6", "compat.path7"};
        uint32_t words[16] = {0};
        size_t size = strnlen(path, sizeof(words));
        memcpy(words, path, size);
        (void)tls_fixer_boot_trace_event("compat.seen", target_pid, g_replace[0],
            tls_fixer_kernel_browser_loader_ready());
        for (size_t i = 0; i < sizeof(stages)/sizeof(stages[0]); ++i)
            (void)tls_fixer_boot_trace_event(stages[i], target_pid, words[2*i], words[2*i+1]);
    }
#endif

    if (g_replace_iap &&
        (tls_fixer_path_equals(path, "vs0:sys/external/libhttp.suprx", TLS_FIXER_MAX_MODULE_PATH) ||
         tls_fixer_path_equals(path, "vs0:/sys/external/libhttp.suprx", TLS_FIXER_MAX_MODULE_PATH))) {
        load_path = g_replacement_modules[1];
        loads_replacement_libhttp = 1;
        route_kind = 1;
    } else if (g_replace_iap &&
               (tls_fixer_path_equals(path, "vs0:sys/external/libssl.suprx", TLS_FIXER_MAX_MODULE_PATH) ||
                tls_fixer_path_equals(path, "vs0:/sys/external/libssl.suprx", TLS_FIXER_MAX_MODULE_PATH))) {
        load_path = g_replacement_modules[2];
        loads_replacement_libssl = 1;
        route_kind = 2;
    } else if (g_replace[0] &&
               tls_fixer_browser_replacement_path(path, browser_path, sizeof(browser_path))) {
        load_path = browser_path;
        loads_replacement_browser = 1;
        route_kind = 3;
    } else if (__atomic_load_n(&g_dns_fix_state, __ATOMIC_RELAXED) != 0 &&
               tls_fixer_path_equals(
                   path,
                   "vs0:sys/external/np_commerce2.suprx",
                   TLS_FIXER_MAX_MODULE_PATH)) {
        load_path = g_replacement_modules[4];
        route_kind = 4;
    }

#if TLS_FIXER_TRACE_MODULE_PATHS
    const int trace_this_load = (flags & TLS_FIXER_PATH_OBSERVER_NAMESPACE_FLAG) != 0;
    if (trace_this_load &&
        tls_fixer_boot_trace_path("load.enter", target_pid, route_kind, (int32_t)flags, path) < 0) {
        trace_ok = 0;
    }
    if (trace_this_load && trace_ok && load_path != path &&
        tls_fixer_boot_trace_path("load.selected", target_pid, route_kind, (int32_t)flags, load_path) < 0) {
        trace_ok = 0;
    }
#else
    const int trace_this_load = route_kind != 0;
    if (trace_this_load && tls_fixer_boot_trace_event("load.enter", target_pid, route_kind, (int32_t)flags) < 0) {
        trace_ok = 0;
    }
#endif
    /* Shared mappings outlive a process, while taiHEN's process-exit cleanup only
     * frees its hook records. Stateful user hooks require private HTTP/SSL code. */
    if ((loads_replacement_libhttp || loads_replacement_libssl) &&
        !TLS_FIXER_SKIP_HTTP_START && !TLS_FIXER_REDIRECTION_ONLY && !TLS_FIXER_PREPARE_ONLY &&
        !TLS_FIXER_BROWSER_ACTIVATION) {
        int allowed = tls_fixer_kernel_http_process_allowed(target_pid);
        if ((flags & UINT32_C(0x08000000)) != 0)
            (void)tls_fixer_boot_trace_event("http.private.policy", target_pid, route_kind, allowed);
        if (allowed > 0) {
            /* Removing only the explicit shared request still reuses shared Sony
             * libraries. Use the direct loader mode too, then verify ownership. */
            load_flags &= ~UINT32_C(0x08000001);
        }
        if ((flags & UINT32_C(0x08000000)) != 0)
            (void)tls_fixer_boot_trace_event("http.private.flags", target_pid,
                (int32_t)flags, (int32_t)load_flags);
    }
    result = TAI_CONTINUE(
        SceUID,
        g_loader_hook_ref,
        pid,
        load_path,
        load_flags,
        ptr_to_four);

    if (trace_this_load && trace_ok &&
        tls_fixer_boot_trace_event("load.return", target_pid, result, route_kind) < 0) {
        trace_ok = 0;
    }
    if (TLS_FIXER_REDIRECTION_ONLY || !trace_ok) goto hook_return;

#if TLS_FIXER_BROWSER_POST_START
    if (result >= 0 && psn_redirect) (void)tls_fixer_post_start_defer_psn(target_pid, result);
#else
    (void)psn_redirect;
#endif
    if (!TLS_FIXER_SKIP_HTTP_START && !TLS_FIXER_BROWSER_ACTIVATION && result >= 0 && loads_replacement_libhttp && tls_fixer_kernel_loader_ready()) {
#if TLS_FIXER_BROWSER_POST_START
        if (tls_fixer_boot_trace_event("http.defer.enter", target_pid, result, 0) < 0) goto hook_return;
        int deferred_http = tls_fixer_post_start_defer_http(target_pid, result);
        (void)tls_fixer_boot_trace_event("http.defer.return", target_pid, result, deferred_http);
#else
        int print_result;
        if (tls_fixer_boot_trace_event("prepare.enter", target_pid, result, 0) < 0) goto hook_return;
        int inject_result = tls_fixer_kernel_inject_for_pid(target_pid, result);
        if (tls_fixer_boot_trace_event("prepare.return", target_pid, result, inject_result) < 0) goto hook_return;
        if (tls_fixer_boot_trace_event("print.enter", target_pid, result, inject_result) < 0) goto hook_return;
        if (inject_result < 0) {
            print_result = ksceDebugPrintf(
                "tls_fixer: provider injection failed for pid 0x%X: 0x%08X\n",
                target_pid,
                inject_result);
        } else {
            print_result = ksceDebugPrintf(
                TLS_FIXER_PREPARE_ONLY
                    ? "tls_fixer: provider prerequisites checked for pid 0x%X, libhttp 0x%X\n"
                    : "tls_fixer: provider load processed for pid 0x%X, libhttp 0x%X\n",
                target_pid,
                result);
        }
        if (tls_fixer_boot_trace_event("print.return", target_pid, result, print_result) < 0) goto hook_return;
#endif
    }

    if (result >= 0 && loads_replacement_browser && tls_fixer_kernel_browser_loader_ready() &&
        tls_fixer_browser_provider_path(load_path, browser_provider, sizeof(browser_provider))) {
#if TLS_FIXER_BROWSER_POST_START
        if (tls_fixer_boot_trace_event("browser.defer.enter", target_pid, result, 0) < 0) goto hook_return;
        int deferred = tls_fixer_post_start_defer(target_pid, result, browser_provider);
        (void)tls_fixer_boot_trace_event("browser.defer.return", target_pid, result, deferred);
#else
        if (tls_fixer_boot_trace_event("prepare.enter", target_pid, result, 1) < 0) goto hook_return;
        int injected = tls_fixer_kernel_inject_browser_for_pid(target_pid, result, browser_provider);
        if (tls_fixer_boot_trace_event("prepare.return", target_pid, result, injected) < 0) goto hook_return;
        if (tls_fixer_boot_trace_event("print.enter", target_pid, result, injected) < 0) goto hook_return;
        int print_result = ksceDebugPrintf(TLS_FIXER_PREPARE_ONLY
            ? "tls_fixer: browser prerequisites pid=0x%X compat=0x%X result=0x%08X\n"
            : "tls_fixer: browser provider load pid=0x%X compat=0x%X result=0x%08X\n",
            target_pid, result, injected);
        if (tls_fixer_boot_trace_event("print.return", target_pid, result, print_result) < 0) goto hook_return;
#endif
    }

    if (!TLS_FIXER_SKIP_DNS_START && !TLS_FIXER_PREPARE_ONLY && !TLS_FIXER_BROWSER_ACTIVATION && result >= 0 && loads_replacement_libssl &&
        target_pid == ksceKernelSysrootGetShellPid()) {
        uint8_t expected = 2;
        /* Helper loading can reenter this hook before the outer load finishes. */
        if (__atomic_compare_exchange_n(&g_dns_fix_state, &expected, 3, 0,
                __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
            int start_status = SCE_KERNEL_START_FAILED;
            tls_fixer_memory_probe_record("mem.dns.before", target_pid);
            (void)tls_fixer_boot_trace_event("dns.start.enter", target_pid, result, 0);
            SceUID dns_module = ksceKernelLoadStartModuleForPid(
                target_pid,
                g_replacement_modules[3],
                0,
                NULL,
                0,
                NULL,
                &start_status);
            (void)tls_fixer_boot_trace_event("dns.start.return", target_pid, dns_module, start_status);
            tls_fixer_memory_probe_record("mem.dns.after", target_pid);
            __atomic_store_n(&g_dns_fix_state,
                dns_module > 0 && start_status == SCE_KERNEL_START_SUCCESS ? 1 : 2,
                __ATOMIC_RELEASE);
        }
    }

hook_return:
    if (trace_this_load && trace_ok) {
        (void)tls_fixer_boot_trace_event("hook.return", target_pid, result, route_kind);
    }
    return result;
}

int _start(SceSize argc, const void *args) __attribute__((weak, alias("module_start")));

int module_start(SceSize argc, const void *args) {
    SceUID module_id;
    int has_replacements;

    (void)argc;
    (void)args;

#if TLS_FIXER_ENABLE_SELF_DISARM
    int disarm_outcome = tls_fixer_self_disarm();
    int report_result = 0;
    if (TLS_FIXER_DISARM_RESULT_ONLY || TLS_FIXER_ENABLE_BOOT_TRACE) {
        report_result = tls_fixer_write_disarm_result(disarm_outcome, tls_fixer_self_disarm_report());
    }
    if (TLS_FIXER_DISARM_RESULT_ONLY) {
        return disarm_outcome == 0 && report_result >= 0
            ? SCE_KERNEL_START_SUCCESS : SCE_KERNEL_START_FAILED;
    }
    if (disarm_outcome != 0 || report_result < 0) {
        return SCE_KERNEL_START_FAILED;
    }
    if (TLS_FIXER_SELF_DISARM_ONLY) {
        return SCE_KERNEL_START_SUCCESS;
    }
#endif
    int trace_result = tls_fixer_boot_trace_open();
    if (TLS_FIXER_ENABLE_BOOT_TRACE) {
        int setup_report = tls_fixer_write_trace_setup_result(trace_result);
        if (trace_result < 0 || setup_report < 0) {
            if (trace_result >= 0) (void)tls_fixer_boot_trace_close();
            return SCE_KERNEL_START_FAILED;
        }
    }
    if (trace_result < 0) return SCE_KERNEL_START_FAILED;
    if (tls_fixer_memory_probe_init() < 0) {
        (void)tls_fixer_boot_trace_event("mem.bind.failed", 0, 0, -1);
        goto failed_before_hook;
    }
    tls_fixer_memory_probe_record("mem.start", 0);
#if defined(__arm__) && !TLS_FIXER_SELF_DISARM_ONLY && !TLS_FIXER_DISARM_RESULT_ONLY
    /* Resolve once here, never from a loader-hook callback. One-shot builds
     * have already completed durable disarming above. */
    if (tls_fixer_boot_trace_event("native.bind.enter", 0, 0, 0) < 0) goto failed_before_hook;
    int bind_result = tls_fixer_native_module_api_init();
    if (tls_fixer_boot_trace_event("native.bind.return", 0, 0, bind_result) < 0 || bind_result < 0)
        goto failed_before_hook;
#endif
    if (tls_fixer_allocation_probe_prepare() < 0) goto failed_before_hook;
    if (tls_fixer_boot_trace_event("startup.checks.enter", 0, 0, 0) < 0) goto failed_before_hook;

#if TLS_FIXER_ENABLE_BOOT_TRACE
    ksceDebugPrintf("tls_fixer module loaded\n");
#endif
    has_replacements = add_replace_flags();
    if (tls_fixer_boot_trace_event("startup.checks.return", 0, 0, has_replacements) < 0) goto failed_before_hook;
#if TLS_FIXER_TRACE_MODULE_PATHS
    if (tls_fixer_boot_trace_event("trace.path.mask", 0,
            (int32_t)TLS_FIXER_PATH_OBSERVER_NAMESPACE_FLAG, 0) < 0) goto failed_before_hook;
#endif
    uint32_t replacement_bits = 0;
    for (size_t i = 0; i < sizeof(g_replace); ++i) {
        if (g_replace[i]) replacement_bits |= UINT32_C(1) << i;
    }
    if (tls_fixer_boot_trace_event("startup.replacements", 0, (int32_t)replacement_bits, 0) < 0) goto failed_before_hook;
    if (g_replace_iap || g_replace[0]) {
        int init_result;
        if (tls_fixer_boot_trace_event("loader.init.enter", 0, 0, 0) < 0) goto failed_before_hook;
        init_result = tls_fixer_kernel_loader_init();
        tls_fixer_memory_probe_record("mem.loader.ready", 0);
        if (tls_fixer_boot_trace_event("loader.init.return", 0, 0, init_result) < 0) goto failed_before_hook;
#if TLS_FIXER_ENABLE_BOOT_TRACE
        ksceDebugPrintf("tls_fixer: exact-module gates app=%d browser=%d\n",
            tls_fixer_kernel_loader_ready(), tls_fixer_kernel_browser_loader_ready());
#endif
    }
    int provider_bits = (!!tls_fixer_kernel_loader_ready()) | ((!!tls_fixer_kernel_browser_loader_ready()) << 1);
    if (tls_fixer_boot_trace_event("startup.providers", 0, provider_bits, 0) < 0) goto failed_before_hook;

    if (TLS_FIXER_INITIALIZE_ONLY || !has_replacements) {
        return SCE_KERNEL_START_SUCCESS;
    }

    module_id = ksceKernelSearchModuleByName("SceKernelModulemgr");
    if (module_id <= 0 || tls_fixer_validate_loader_hook(module_id) < 0) goto failed_before_hook;
    if (tls_fixer_trace_status_start() < 0) goto failed_before_hook;
    if (tls_fixer_allocation_probe_install() < 0) goto failed_before_hook;
#if TLS_FIXER_BROWSER_POST_START
    if (tls_fixer_post_start_init() < 0) goto failed_before_hook;
    if (tls_fixer_boot_trace_event("start.hook.install.enter", 0, module_id, 0) < 0) goto failed_before_hook;
    g_start_hook_id = taiHookFunctionOffsetForKernel(KERNEL_PID, &g_start_hook_ref,
        module_id, 0, TLS_FIXER_MODULEMGR_START_OFFSET, 1, start_for_pid_patched);
    int start_recorded = tls_fixer_boot_trace_event("start.hook.install.return", 0, module_id, g_start_hook_id);
    if (g_start_hook_id < 0 || start_recorded < 0) goto failed_before_hook;
#endif
    if (tls_fixer_boot_trace_event("hook.install.enter", 0, module_id, 0) < 0) goto failed_before_hook;

    g_loader_hook_id = taiHookFunctionOffsetForKernel(
        KERNEL_PID,
        &g_loader_hook_ref,
        module_id,
        0,
        TLS_FIXER_MODULEMGR_LOAD_OFFSET,
        1,
        load_for_pid_patched);
    (void)tls_fixer_boot_trace_event("hook.install.return", 0, module_id, g_loader_hook_id);
    if (g_loader_hook_id < 0) goto failed_before_hook;
    return SCE_KERNEL_START_SUCCESS;
failed_before_hook:
    if (tls_fixer_allocation_probe_resident()) return SCE_KERNEL_START_SUCCESS;
#if TLS_FIXER_BROWSER_POST_START
    /* A published native continuation can still be executing on another thread. */
    if (g_start_hook_id >= 0 || g_loader_hook_id >= 0) return SCE_KERNEL_START_SUCCESS;
    if (tls_fixer_post_start_destroy() < 0) return SCE_KERNEL_START_SUCCESS;
#endif
    /* A worker that could not be joined must not outlive its module's code. */
    if (tls_fixer_trace_status_stop() < 0) return SCE_KERNEL_START_SUCCESS;
    tls_fixer_psn_redirect_destroy();
    tls_fixer_kernel_loader_destroy();
    (void)tls_fixer_boot_trace_close();
    return SCE_KERNEL_START_FAILED;
}

int module_stop(SceSize argc, const void *args) {
    (void)argc;
    (void)args;

    if (TLS_FIXER_SELF_DISARM_ONLY || TLS_FIXER_DISARM_RESULT_ONLY) return SCE_KERNEL_STOP_SUCCESS;
    if (g_loader_hook_id >= 0 || tls_fixer_allocation_probe_resident()) return SCE_KERNEL_STOP_FAIL;
#if TLS_FIXER_BROWSER_POST_START
    if (g_start_hook_id >= 0 || tls_fixer_post_start_destroy() < 0) return SCE_KERNEL_STOP_FAIL;
#endif
    if (tls_fixer_trace_status_stop() < 0) return SCE_KERNEL_STOP_FAIL;
    tls_fixer_psn_redirect_destroy();
    tls_fixer_kernel_loader_destroy();
    (void)tls_fixer_boot_trace_close();
    return SCE_KERNEL_STOP_SUCCESS;
}
