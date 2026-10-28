#include <kernel_mock.h>
#include <taihen.h>
#include <assert.h>
#include <stdio.h>
#include "boot_trace.h"
#include "disarm_result.h"

#define _start tls_fixer_test_kernel_entry
#include "../../../kernel/main.c"
#undef _start

static SceUID current_pid, seen_pid, injected_pid;
static SceUID load_result;
static int pid_queries, injections, dns_loads;
static uint32_t seen_flags;
static int *seen_options;
static char selected_path[256], provider_path[256];
static int disarm_result, disarm_calls, startup_operations, checking_startup;
static int loader_initializations, hook_installations;
static int loader_destructions;
static int hook_validation_result, hook_validations;
static int injection_result;
static int http_process_allowed = 1;
static int http_mapping_private, http_mapping_queries;
static int dns_reenter, dns_start_status;
static SceUID dns_load_result;
#if TLS_FIXER_BROWSER_POST_START
typedef int (*TestStartFunction)(SceUID, SceUID, SceSize, const void *, uint32_t, const void *, int *);
static TestStartFunction installed_start;
static int start_install_error, load_install_error;
static int native_link_finished;
static uint32_t simulated_detour_literal;
static int original_start(SceUID, SceUID, SceSize, const void *, uint32_t, const void *, int *);
#endif

#if (defined(TLS_FIXER_DISARM_RESULT_ONLY) && TLS_FIXER_DISARM_RESULT_ONLY) || TLS_FIXER_ENABLE_BOOT_TRACE
static TlsFixerDisarmReport diagnostic_report;
static int report_calls, report_result;
const TlsFixerDisarmReport *tls_fixer_self_disarm_report(void) {
    assert(disarm_calls == 1);
    return &diagnostic_report;
}
int tls_fixer_write_disarm_result(int outcome, const TlsFixerDisarmReport *report) {
    assert(disarm_calls == 1 && report == &diagnostic_report && outcome == disarm_result);
#if defined(TLS_FIXER_DISARM_RESULT_ONLY) && TLS_FIXER_DISARM_RESULT_ONLY
    assert(startup_operations == 0 && loader_initializations == 0 && hook_installations == 0);
#endif
    ++report_calls;
    return report_result;
}
#endif

#if TLS_FIXER_ENABLE_BOOT_TRACE
static int trace_opens, trace_open_fail, trace_closes;
static int trace_setup_calls, trace_setup_value;
static const char *trace_fail_stage;
#if TLS_FIXER_TRACE_MODULE_PATHS
static unsigned int path_calls, replacement_bits, provider_bits, path_flag_mask;
static unsigned int status_starts, status_stops, counted_loads;
static int status_start_error, status_stop_error;
static char input_path_seen[256], selected_path_seen[256];
#endif
static int record_route, native_calls, route_prints;
static size_t route_event_count;
static struct {
    const char *stage;
    int32_t pid, object, result;
} route_events[32];
static void record_event(const char *stage, int32_t pid, int32_t object, int32_t result) {
    if (!record_route) return;
    assert(route_event_count < sizeof(route_events) / sizeof(route_events[0]));
    route_events[route_event_count].stage = stage;
    route_events[route_event_count].pid = pid;
    route_events[route_event_count].object = object;
    route_events[route_event_count++].result = result;
}
int tls_fixer_write_trace_setup_result(int outcome) {
    assert(trace_opens > 0 && report_calls > 0);
    ++trace_setup_calls;
    trace_setup_value = outcome;
    return 0;
}
int tls_fixer_boot_trace_open(void) { assert(disarm_calls == 1 && disarm_result == 0); ++trace_opens; return trace_open_fail ? -1 : 0; }
int tls_fixer_boot_trace_close(void) { ++trace_closes; return 0; }
int tls_fixer_boot_trace_event(const char *stage, int32_t pid, int32_t object, int32_t result) {
    assert(trace_opens > 0 && !trace_open_fail);
#if TLS_FIXER_TRACE_MODULE_PATHS
    if (strcmp(stage, "startup.replacements") == 0) replacement_bits = (unsigned int)object;
    if (strcmp(stage, "startup.providers") == 0) provider_bits = (unsigned int)object;
    if (strcmp(stage, "trace.path.mask") == 0) path_flag_mask = (unsigned int)object;
#endif
    record_event(stage, pid, object, result);
    return trace_fail_stage != NULL && strcmp(stage, trace_fail_stage) == 0 ? -1 : 0;
}
#if TLS_FIXER_TRACE_MODULE_PATHS
void tls_fixer_trace_status_note_load(void) { ++counted_loads; }
int tls_fixer_trace_status_start(void) {
    assert(disarm_calls == 1 && disarm_result == 0 && trace_opens > 0);
    assert(hook_validations > 0 && hook_installations == 0);
    ++status_starts;
    return status_start_error;
}
int tls_fixer_trace_status_stop(void) { ++status_stops; return status_stop_error; }
int tls_fixer_boot_trace_path(const char *stage, int32_t pid, int32_t object, int32_t result,
    const char *path) {
    ++path_calls;
    assert(path != NULL && strlen(path) < sizeof(input_path_seen));
    strcpy(strcmp(stage, "load.enter") == 0 ? input_path_seen : selected_path_seen, path);
    return tls_fixer_boot_trace_event(stage, pid, object, result);
}
#endif
#endif

int tls_fixer_self_disarm(void) { ++disarm_calls; return disarm_result; }
static void assert_startup_disarm(void) {
#if TLS_FIXER_ENABLE_SELF_DISARM
    assert(disarm_calls == 1 && disarm_result == 0);
#else
    assert(disarm_calls == 0);
#endif
}
static void startup_operation(void) {
    ++startup_operations;
    if (checking_startup) assert_startup_disarm();
#if TLS_FIXER_ENABLE_BOOT_TRACE
    assert(trace_opens > 0 && !trace_open_fail);
#endif
}

SceUID ksceKernelGetProcessId(void) { ++pid_queries; return current_pid; }
SceUID ksceKernelSysrootGetShellPid(void) { return 99; }
int ksceDebugPrintf(const char *format, ...) {
    startup_operation();
    (void)format;
#if TLS_FIXER_ENABLE_BOOT_TRACE
    if (record_route) {
        ++route_prints;
        record_event("printf.call", 0, 0, -13);
        return -13;
    }
#endif
    return 0;
}
int ksceIoGetstat(const char *path, SceIoStat *status) { startup_operation(); (void)path; (void)status; return 0; }
SceUID ksceKernelSearchModuleByName(const char *name) { startup_operation(); (void)name; return 11; }
int tls_fixer_validate_loader_hook(SceUID module) {
    startup_operation();
    assert_startup_disarm();
    assert(module == 11 && hook_installations == 0);
    ++hook_validations;
    return hook_validation_result;
}
int tls_fixer_kernel_loader_init(void) { startup_operation(); ++loader_initializations; return 0; }
void tls_fixer_kernel_loader_destroy(void) { ++loader_destructions; }
int tls_fixer_kernel_loader_ready(void) { return 1; }
int tls_fixer_kernel_http_process_allowed(SceUID pid) { return pid > 0 && http_process_allowed; }
int tls_fixer_native_http_is_private(SceUID pid) {
    assert(pid > 0 && pid != KERNEL_PID && pid != 99);
    ++http_mapping_queries;
    return http_mapping_private;
}
int tls_fixer_kernel_browser_loader_ready(void) { return 1; }
int tls_fixer_kernel_inject_for_pid(SceUID pid, SceUID module) {
    assert(module == 88);
#if TLS_FIXER_BROWSER_POST_START
    assert(native_link_finished);
    simulated_detour_literal = UINT32_C(0x81280001);
#endif
    injected_pid = pid;
    ++injections;
    return pid > 0 ? injection_result : -1;
}
int tls_fixer_kernel_inject_browser_for_pid(SceUID pid, SceUID module, const char *path) {
    strcpy(provider_path, path);
    return tls_fixer_kernel_inject_for_pid(pid, module);
}
SceUID ksceKernelLoadStartModuleForPid(SceUID pid, const char *path, SceSize size,
    const void *data, int flags, const void *options, int *status) {
    assert(pid == 99 && strcmp(path, g_replacement_modules[3]) == 0);
    assert(size == 0 && data == NULL && flags == 0 && options == NULL);
    ++dns_loads;
    if (dns_reenter) {
        dns_reenter = 0;
        assert(load_for_pid_patched(pid, "vs0:sys/external/libssl.suprx", 0, NULL) == 88);
        assert(dns_loads == 1);
    }
    *status = dns_start_status;
    return dns_load_result;
}
static SceUID original_load(SceUID pid, const char *path, uint32_t flags, int *options) {
#if TLS_FIXER_ENABLE_BOOT_TRACE
    ++native_calls;
    record_event("native.call", pid, 0, (int32_t)flags);
#endif
    seen_pid = pid;
    seen_flags = flags;
    seen_options = options;
    strcpy(selected_path, path);
    current_pid = 777;
    return load_result;
}
int taiHookFunctionOffsetForKernel(SceUID pid, tai_hook_ref_t *reference, SceUID module,
    int segment, size_t offset, int thumb, const void *function) {
    (void)pid; (void)module; (void)segment; (void)offset; (void)thumb; (void)function;
    startup_operation();
    ++hook_installations;
#if TLS_FIXER_BROWSER_POST_START
    assert(pid == KERNEL_PID && module == 11 && segment == 0 && thumb == 1);
    if (offset == TLS_FIXER_MODULEMGR_START_OFFSET) {
        assert(hook_installations == 1);
        if (start_install_error) return -71;
        installed_start = (TestStartFunction)function;
        *reference = (tai_hook_ref_t)original_start;
        return 31;
    }
    assert(offset == TLS_FIXER_MODULEMGR_LOAD_OFFSET && installed_start != NULL);
    if (load_install_error) return -72;
#endif
    *reference = (tai_hook_ref_t)original_load;
    return 1;
}
static void reset(void) {
    http_mapping_private = 0;
    http_mapping_queries = 0;
#if TLS_FIXER_BROWSER_POST_START
    native_link_finished = 0;
    simulated_detour_literal = 0;
#endif
    memset(g_replace, 1, sizeof(g_replace));
    g_replace_iap = 1;
    g_dns_fix_state = 0;
    g_loader_hook_ref = (tai_hook_ref_t)original_load;
    current_pid = 99;
    seen_pid = injected_pid = -1;
    pid_queries = injections = dns_loads = 0;
    load_result = 88;
    injection_result = 0;
    dns_reenter = 0;
    dns_start_status = SCE_KERNEL_START_SUCCESS;
    dns_load_result = 88;
    provider_path[0] = '\0';
    selected_path[0] = '\0';
#if TLS_FIXER_ENABLE_BOOT_TRACE
    native_calls = route_prints = 0;
    route_event_count = 0;
#if TLS_FIXER_TRACE_MODULE_PATHS
    path_calls = 0;
    counted_loads = 0;
    input_path_seen[0] = selected_path_seen[0] = '\0';
#endif
#endif
}

int main(void) {
    int options = 4;
    const char *paths[] = {"vs0:sys/external/libhttp.suprx", "wb0:/webcore/ScePsp2Compat.suprx"};
    reset();
    disarm_result = -1;
    assert(module_start(0, NULL) == SCE_KERNEL_START_FAILED);
    assert(disarm_calls == 1 && startup_operations == 0);
    assert(hook_validations == 0);
#if TLS_FIXER_ENABLE_BOOT_TRACE
    assert(report_calls == 1 && trace_setup_calls == 0);
#endif
#if defined(TLS_FIXER_DISARM_RESULT_ONLY) && TLS_FIXER_DISARM_RESULT_ONLY
    assert(report_calls == 1);
    disarm_calls = 0;
    disarm_result = 0;
    assert(module_start(0, NULL) == SCE_KERNEL_START_SUCCESS);
    assert(report_calls == 2 && disarm_calls == 1);
    disarm_calls = 0;
    report_result = -99;
    assert(module_start(0, NULL) == SCE_KERNEL_START_FAILED);
    assert(report_calls == 3 && disarm_calls == 1);
    assert(startup_operations == 0 && loader_initializations == 0 && hook_installations == 0);
    assert(injections == 0 && dns_loads == 0);
    assert(module_stop(0, NULL) == SCE_KERNEL_STOP_SUCCESS);
    puts("disarm result-only entry: failure and success recorded without hooks or provider operations PASS");
    return 0;
#endif
    disarm_calls = 0;
    disarm_result = 0;
#if TLS_FIXER_ENABLE_BOOT_TRACE
    assert(trace_opens == 0);
    trace_open_fail = 1;
    assert(module_start(0, NULL) == SCE_KERNEL_START_FAILED);
    assert(disarm_calls == 1 && trace_opens == 1 && startup_operations == 0);
    assert(trace_setup_calls == 1 && trace_setup_value == -1);
    disarm_calls = 0;
    trace_open_fail = 0;
    static const char *const startup_failures[] = {"startup.checks.enter", "startup.checks.return",
        "loader.init.enter", "loader.init.return", "hook.install.enter"
#if TLS_FIXER_TRACE_MODULE_PATHS
        , "trace.path.mask"
#endif
    };
    for (size_t i = 0; i < sizeof(startup_failures) / sizeof(startup_failures[0]); ++i) {
        trace_fail_stage = startup_failures[i];
        assert(module_start(0, NULL) == SCE_KERNEL_START_FAILED);
        assert(disarm_calls == 1 && hook_installations == 0 && injections == 0 && dns_loads == 0);
        assert(trace_closes == (int)i + 1);
        disarm_calls = 0;
    }
    trace_fail_stage = NULL;
    startup_operations = loader_initializations = 0;
#endif
    checking_startup = 1;
#if !TLS_FIXER_SELF_DISARM_ONLY && !TLS_FIXER_INITIALIZE_ONLY
    int destructions_before = loader_destructions;
    hook_validation_result = -1;
    assert(module_start(0, NULL) == SCE_KERNEL_START_FAILED);
    assert(disarm_calls == 1 && hook_validations > 0 && hook_installations == 0);
    assert(loader_destructions == destructions_before + 1);
    assert(injections == 0 && dns_loads == 0);
    disarm_calls = 0;
    hook_validation_result = 0;
    startup_operations = loader_initializations = 0;
#endif
#if TLS_FIXER_TRACE_MODULE_PATHS
    status_start_error = -71;
    assert(module_start(0, NULL) == SCE_KERNEL_START_FAILED);
    assert(status_starts > 0 && status_stops > 0 && hook_installations == 0);
    disarm_calls = 0;
    status_stop_error = -72;
    int before_destroys = loader_destructions, before_closes = trace_closes;
    assert(module_start(0, NULL) == SCE_KERNEL_START_SUCCESS);
    assert(hook_installations == 0 && loader_destructions == before_destroys && trace_closes == before_closes);
    assert(module_stop(0, NULL) == SCE_KERNEL_STOP_FAIL);
    assert(loader_destructions == before_destroys && trace_closes == before_closes);
    status_stop_error = 0;
    assert(module_stop(0, NULL) == SCE_KERNEL_STOP_SUCCESS);
    assert(loader_destructions == before_destroys + 1 && trace_closes == before_closes + 1);
    status_start_error = 0;
    disarm_calls = 0;
    startup_operations = loader_initializations = 0;
#endif
    assert(module_start(0, NULL) == SCE_KERNEL_START_SUCCESS);
#if defined(TLS_FIXER_SELF_DISARM_ONLY) && TLS_FIXER_SELF_DISARM_ONLY
    assert(disarm_calls == 1 && startup_operations == 0);
    assert(injections == 0 && dns_loads == 0);
    assert(module_stop(0, NULL) == SCE_KERNEL_STOP_SUCCESS);
    assert(startup_operations == 0);
    puts("kernel self-disarm-only entry: no logging, queries, hooks or injection PASS");
    return 0;
#endif
    assert(disarm_calls == 1 && startup_operations > 0);
#if defined(TLS_FIXER_INITIALIZE_ONLY) && TLS_FIXER_INITIALIZE_ONLY
    assert(loader_initializations == 1 && hook_installations == 0);
    assert(injections == 0 && dns_loads == 0);
    assert(module_stop(0, NULL) == SCE_KERNEL_STOP_SUCCESS);
    puts("kernel initialization-only entry: module checks and loader init without hooks PASS");
    return 0;
#endif
    checking_startup = 0;
#if TLS_FIXER_TRACE_MODULE_PATHS
    assert(replacement_bits == 31 && provider_bits == 3);
    assert(loader_initializations == 1 && hook_installations == 1);
    assert(module_stop(0, NULL) == SCE_KERNEL_STOP_FAIL);
    record_route = 1;
    const char *observed_paths[] = {"opaque:webcore/ScePsp2Compat.suprx",
        "wb0:/tls_fixer/ScePsp2Compat.suprx", "ux0:/unrelated.suprx",
        "wb0:/webcore/ScePsp2Compat.suprx", "vs0:sys/external/libhttp.suprx"};
    const uint32_t excluded_flags[] = {0, 0x800, 0x8001, 0x08000002,
        0x08008001, UINT32_C(0x80000000), UINT32_C(0xffffefff)};
    const uint32_t included_flags[] = {0x1000, 0x1010, 0x08009001, UINT32_MAX};
    for (size_t i = 0; i < sizeof(observed_paths) / sizeof(observed_paths[0]); ++i) {
        int kind = (i == 0 || i == 3) ? 3 : i == 4 ? 1 : 0;
        const char *expected_path = i == 0 ? "opaque:tls_fixer/ScePsp2Compat.suprx"
            : i == 3 ? "wb0:/tls_fixer/ScePsp2Compat.suprx"
            : i == 4 ? g_replacement_modules[1] : observed_paths[i];
        for (size_t n = 0; n < sizeof(excluded_flags) / sizeof(excluded_flags[0]); ++n) {
            for (unsigned int failure = 0; failure < 2; ++failure) {
                reset();
                load_result = failure ? -5 : 88;
                assert(load_for_pid_patched(123, observed_paths[i], excluded_flags[n], &options) == load_result);
                assert(path_calls == 0 && route_event_count == 1);
                assert(strcmp(route_events[0].stage, "native.call") == 0);
                assert(native_calls == 1 && injections == 0 && dns_loads == 0 && route_prints == 0);
                assert(counted_loads == 1);
                assert(seen_pid == 123 && seen_flags == excluded_flags[n] && seen_options == &options);
                assert(strcmp(selected_path, expected_path) == 0);
            }
        }
        for (size_t n = 0; n < sizeof(included_flags) / sizeof(included_flags[0]); ++n) {
            reset();
            assert(load_for_pid_patched(123, observed_paths[i], included_flags[n], &options) == 88);
            assert(path_calls == (kind ? 2u : 1u));
            assert(counted_loads == 1);
            assert(route_event_count == (kind ? 5u : 4u));
            assert((uint32_t)route_events[0].result == included_flags[n]);
            assert(native_calls == 1 && injections == 0 && dns_loads == 0 && route_prints == 0);
        }
        for (unsigned int failure = 0; failure < 2; ++failure) {
            reset();
            load_result = failure ? -5 : 88;
            assert(load_for_pid_patched(0, observed_paths[i], 0x1000, &options) == load_result);
            assert(native_calls == 1 && injections == 0 && dns_loads == 0 && route_prints == 0);
            assert(strcmp(input_path_seen, observed_paths[i]) == 0);
            assert(path_calls == (kind ? 2u : 1u));
            assert(strcmp(route_events[0].stage, "load.enter") == 0);
            assert(route_events[0].object == kind && route_events[0].pid == 99 && route_events[0].result == 0x1000);
            assert(seen_pid == 0 && seen_options == &options && seen_flags == 0x1000);
            assert(route_event_count == (kind ? 5u : 4u));
            if (kind) {
                assert(strcmp(selected_path_seen, expected_path) == 0);
                assert(strcmp(route_events[1].stage, "load.selected") == 0);
            } else assert(strcmp(selected_path, observed_paths[i]) == 0);
            assert(strcmp(route_events[route_event_count - 2].stage, "load.return") == 0);
            assert(route_events[route_event_count - 2].object == load_result);
        }
        const char *failed[] = {"load.enter", "load.selected", "load.return", "hook.return"};
        for (size_t n = 0; n < sizeof(failed) / sizeof(failed[0]); ++n) {
            reset();
            trace_fail_stage = failed[n];
            assert(load_for_pid_patched(123, observed_paths[i], 0x1000, &options) == 88);
            assert(native_calls == 1 && injections == 0 && dns_loads == 0);
            assert(seen_pid == 123 && seen_flags == 0x1000 && seen_options == &options);
        }
        trace_fail_stage = NULL;
    }
    assert(path_flag_mask == 0x1000);
    puts("module path observation: process-namespace loads only; unobserved native outcomes preserved PASS");
    return 0;
#endif
#if defined(TLS_FIXER_REDIRECTION_ONLY) && TLS_FIXER_REDIRECTION_ONLY
    assert(loader_initializations == 1 && hook_installations == 1);
    assert(module_stop(0, NULL) == SCE_KERNEL_STOP_FAIL);
#if TLS_FIXER_ENABLE_BOOT_TRACE
    record_route = 1;
#endif
    for (unsigned int i = 0; i < sizeof(paths)/sizeof(paths[0]); ++i) {
        reset();
        assert(load_for_pid_patched(0, paths[i], 0x1000, &options) == 88);
        assert(injections == 0 && dns_loads == 0);
        assert(seen_pid == 0 && seen_flags == 0x1000 && seen_options == &options);
        assert(strcmp(selected_path, i == 0 ? g_replacement_modules[1] : "wb0:/tls_fixer/ScePsp2Compat.suprx") == 0);
#if TLS_FIXER_ENABLE_BOOT_TRACE
        assert(native_calls == 1 && route_prints == 0 && route_event_count == 4);
        assert(strcmp(route_events[0].stage, "load.enter") == 0);
        assert(strcmp(route_events[1].stage, "native.call") == 0);
        assert(strcmp(route_events[2].stage, "load.return") == 0);
        assert(strcmp(route_events[3].stage, "hook.return") == 0);
        assert(route_events[0].object == (i == 0 ? 1 : 3) && route_events[0].pid == 99);
        assert(route_events[2].object == 88 && route_events[3].object == 88);
#endif
        reset();
        assert(load_for_pid_patched(123, paths[i], 0, NULL) == 88 && injections == 0);
        reset();
        load_result = -5;
        assert(load_for_pid_patched(0, paths[i], 0, NULL) == -5 && injections == 0);
#if TLS_FIXER_ENABLE_BOOT_TRACE
        assert(native_calls == 1 && route_prints == 0 && route_event_count == 4);
        assert(route_events[2].object == -5 && route_events[3].object == -5);
        static const char *const failed_markers[] = {"load.enter", "load.return", "hook.return"};
        for (size_t n = 0; n < sizeof(failed_markers) / sizeof(failed_markers[0]); ++n) {
            reset();
            trace_fail_stage = failed_markers[n];
            assert(load_for_pid_patched(0, paths[i], 0x1000, &options) == 88);
            assert(native_calls == 1 && injections == 0 && dns_loads == 0 && route_prints == 0);
            assert(seen_flags == 0x1000 && seen_options == &options);
        }
        trace_fail_stage = NULL;
#endif
    }
    reset();
    g_dns_fix_state = 2;
    assert(load_for_pid_patched(0, "vs0:sys/external/libssl.suprx", 0, NULL) == 88);
    assert(strcmp(selected_path, g_replacement_modules[2]) == 0 && dns_loads == 0);
    reset();
    assert(load_for_pid_patched(0, "ux0:/unrelated.suprx", 0, NULL) == 88 && injections == 0);
    assert(strcmp(selected_path, "ux0:/unrelated.suprx") == 0);
#if TLS_FIXER_ENABLE_BOOT_TRACE
    assert(native_calls == 1 && route_prints == 0 && route_event_count == 1);
    assert(strcmp(route_events[0].stage, "native.call") == 0);
    record_route = 0;
#endif
    puts("kernel redirection-only route: hooks and path replacement without provider/DNS injection PASS");
    return 0;
#endif
    for (unsigned int i = 0; i < sizeof(paths)/sizeof(paths[0]); ++i) {
        reset();
        assert(load_for_pid_patched(0, paths[i], 0x1000, &options) == 88);
        assert(injections == 1 && injected_pid == 99 && pid_queries == 1);
        assert(seen_pid == 0 && seen_flags == 0x1000 && seen_options == &options);
        if (i == 1) {
            assert(strcmp(selected_path, "wb0:/tls_fixer/ScePsp2Compat.suprx") == 0);
            assert(strcmp(provider_path, "wb0:/tls_fixer/tls_fixer.suprx") == 0);
        }
        reset();
        assert(load_for_pid_patched(123, paths[i], 0, NULL) == 88);
        assert(injections == 1 && injected_pid == 123 && pid_queries == 0 && seen_pid == 123);
        reset();
        load_result = -5;
        assert(load_for_pid_patched(0, paths[i], 0, NULL) == -5 && injections == 0);
    }
    reset();
    g_dns_fix_state = 2;
    assert(load_for_pid_patched(0, "vs0:sys/external/libssl.suprx", 0, NULL) == 88);
#if defined(TLS_FIXER_PREPARE_ONLY) && TLS_FIXER_PREPARE_ONLY
    assert(dns_loads == 0 && g_dns_fix_state == 2);
#else
    assert(dns_loads == 1 && g_dns_fix_state == 1);
    for (unsigned int failure = 0; failure < 3; ++failure) {
        reset();
        g_dns_fix_state = 2;
        dns_load_result = failure == 0 ? -456 : failure == 1 ? 0 : 88;
        dns_start_status = failure == 2 ? SCE_KERNEL_START_FAILED : SCE_KERNEL_START_SUCCESS;
        assert(load_for_pid_patched(99, "vs0:sys/external/libssl.suprx", 0, NULL) == 88);
        assert(dns_loads == 1 && g_dns_fix_state == 2);
        dns_load_result = 88;
        dns_start_status = SCE_KERNEL_START_SUCCESS;
        assert(load_for_pid_patched(99, "vs0:sys/external/libssl.suprx", 0, NULL) == 88);
        assert(dns_loads == 2 && g_dns_fix_state == 1);
    }
    reset();
    g_dns_fix_state = 2;
    dns_reenter = 1;
    assert(load_for_pid_patched(99, "vs0:sys/external/libssl.suprx", 0, NULL) == 88);
    assert(dns_loads == 1 && g_dns_fix_state == 1);
    assert(load_for_pid_patched(99, "vs0:sys/external/libssl.suprx", 0, NULL) == 88);
    assert(dns_loads == 1);
#endif
    reset();
    assert(load_for_pid_patched(0, "ux0:/unrelated.suprx", 0, NULL) == 88 && injections == 0);
    assert(strcmp(selected_path, "ux0:/unrelated.suprx") == 0);
#if TLS_FIXER_ENABLE_BOOT_TRACE
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i) {
        reset();
        trace_fail_stage = "prepare.enter";
        assert(load_for_pid_patched(0, paths[i], 0x1000, &options) == 88);
        assert(injections == 0 && dns_loads == 0);
        assert(seen_pid == 0 && seen_flags == 0x1000 && seen_options == &options);
        reset();
        trace_fail_stage = "prepare.return";
        assert(load_for_pid_patched(0, paths[i], 0x1000, &options) == 88);
        assert(injections == 1 && dns_loads == 0);
    }
    trace_fail_stage = NULL;
    record_route = 1;
    static const char *const completed_route[] = {"load.enter", "native.call", "load.return",
        "prepare.enter", "prepare.return", "print.enter", "printf.call", "print.return", "hook.return"};
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i) {
        for (int failure = 0; failure < 2; ++failure) {
            reset();
            injection_result = failure ? -42 : 0;
            assert(load_for_pid_patched(0, paths[i], 0x1000, &options) == 88);
            assert(native_calls == 1 && injections == 1 && route_prints == 1);
            assert(route_event_count == sizeof(completed_route) / sizeof(completed_route[0]));
            for (size_t n = 0; n < route_event_count; ++n) {
                assert(strcmp(route_events[n].stage, completed_route[n]) == 0);
            }
            assert(route_events[0].pid == 99 && route_events[0].object == (i == 0 ? 1 : 3));
            assert(route_events[0].result == 0x1000);
            assert(route_events[2].object == 88 && route_events[2].pid == 99);
            assert(route_events[4].result == injection_result && route_events[5].result == injection_result);
            assert(route_events[7].result == -13);
            assert(route_events[8].object == 88 && route_events[8].pid == 99);
        }
        static const char *const failures[] = {"load.enter", "load.return", "prepare.enter",
            "prepare.return", "print.enter", "print.return", "hook.return"};
        for (size_t n = 0; n < sizeof(failures) / sizeof(failures[0]); ++n) {
            reset();
            trace_fail_stage = failures[n];
            assert(load_for_pid_patched(0, paths[i], 0x1000, &options) == 88);
            assert(native_calls == 1 && injections == (n >= 3) && route_prints == (n >= 5));
            assert(seen_pid == 0 && seen_flags == 0x1000 && seen_options == &options);
        }
        trace_fail_stage = NULL;
        reset();
        load_result = -5;
        assert(load_for_pid_patched(0, paths[i], 0x1000, &options) == -5);
        assert(native_calls == 1 && injections == 0 && route_prints == 0 && route_event_count == 4);
        assert(strcmp(route_events[2].stage, "load.return") == 0 && route_events[2].object == -5);
        assert(strcmp(route_events[3].stage, "hook.return") == 0 && route_events[3].object == -5);
    }
    static const char *const other_paths[] = {"vs0:sys/external/libssl.suprx", "vs0:sys/external/np_commerce2.suprx"};
    for (size_t i = 0; i < sizeof(other_paths) / sizeof(other_paths[0]); ++i) {
        reset();
        g_dns_fix_state = 2;
        assert(load_for_pid_patched(123, other_paths[i], 0, NULL) == 88);
        assert(native_calls == 1 && injections == 0 && dns_loads == 0 && route_prints == 0);
        assert(route_event_count == 4 && route_events[0].pid == 123);
        assert(route_events[0].object == (i == 0 ? 2 : 4));
        assert(strcmp(route_events[3].stage, "hook.return") == 0);
    }
    reset();
    assert(load_for_pid_patched(0, "ux0:/unrelated.suprx", 0, NULL) == 88);
    assert(native_calls == 1 && injections == 0 && route_prints == 0 && route_event_count == 1);
    assert(strcmp(route_events[0].stage, "native.call") == 0);
    record_route = 0;
#endif
    puts("kernel module route: current-PID and explicit-PID handoff PASS");
    return 0;
}
