#define main tls_fixer_shared_route_suite
#include "test_route.c"
#include "tls_fixer/browser_start_diagnostics.h"
#undef main

int main(void) {
    int options = 4;
    reset();
    disarm_result = -1;
    assert(module_start(0, NULL) == SCE_KERNEL_START_FAILED);
    assert(disarm_calls == 1 && startup_operations == 0 && injections == 0);
    disarm_calls = 0;
    disarm_result = 0;
    checking_startup = 1;
#if TLS_FIXER_TRACE_MODULE_PATHS
    status_start_error = -71;
    assert(module_start(0, NULL) == SCE_KERNEL_START_FAILED);
    assert(status_starts == 1 && status_stops > 0 && hook_installations == 0);
    assert(injections == 0 && dns_loads == 0);
    status_start_error = 0;
    disarm_calls = 0;
#endif
    assert(module_start(0, NULL) == SCE_KERNEL_START_SUCCESS);
    assert(disarm_calls == 1 && hook_installations == 1);
#if TLS_FIXER_TRACE_MODULE_PATHS
    assert(status_starts == 2 && path_flag_mask == 0x1000);
#endif
    checking_startup = 0;
    record_route = 1;

    const char *const system_paths[] = {
        "vs0:sys/external/libhttp.suprx", "vs0:/sys/external/libhttp.suprx",
        "vs0:sys/external/libssl.suprx", "vs0:/sys/external/libssl.suprx",
        "vs0:sys/external/np_commerce2.suprx", "ux0:/unrelated.suprx"
    };
    for (size_t i = 0; i < sizeof(system_paths) / sizeof(system_paths[0]); ++i) {
        reset();
        g_dns_fix_state = 2;
        assert(load_for_pid_patched(0, system_paths[i], 0x1000, &options) == 88);
        assert(native_calls == 1 && injections == 0 && dns_loads == 0);
        assert(seen_pid == 0 && seen_flags == 0x1000 && seen_options == &options);
#if TLS_FIXER_TRACE_MODULE_PATHS
        reset();
        g_dns_fix_state = 2;
        assert(load_for_pid_patched(0, system_paths[i], 0x08008001, &options) == 88);
        assert(native_calls == 1 && injections == 0 && dns_loads == 0);
        assert(counted_loads == 1 && path_calls == 0 && route_event_count == 1);
        assert(seen_flags == 0x08008001 && seen_options == &options);
#endif
    }
    for (unsigned int i = 0; i < 80; ++i) {
        reset();
        SceUID pid = i % 2 ? 123 : 0;
        assert(load_for_pid_patched(pid, "wb0:/webcore/ScePsp2Compat.suprx", 0x1000, &options) == 88);
        assert(injections == 1 && dns_loads == 0 && native_calls == 1);
        assert(injected_pid == (pid ? pid : 99));
        assert(strcmp(provider_path, "wb0:/tls_fixer/" TLS_FIXER_BROWSER_PROVIDER_FILENAME) == 0);
        assert(strcmp(selected_path, "wb0:/tls_fixer/ScePsp2Compat.suprx") == 0);
        assert(seen_pid == pid && seen_flags == 0x1000 && seen_options == &options);
    }
    const char *const failed_markers[] = {"load.enter", "load.return", "prepare.enter"};
    for (size_t i = 0; i < sizeof(failed_markers) / sizeof(failed_markers[0]); ++i) {
        reset();
        trace_fail_stage = failed_markers[i];
        assert(load_for_pid_patched(0, "wb0:/webcore/ScePsp2Compat.suprx", 0x1000, &options) == 88);
        assert(injections == 0 && dns_loads == 0 && native_calls == 1);
    }
    trace_fail_stage = NULL;
#if TLS_FIXER_TRACE_MODULE_PATHS
    const char *const browser_paths[] = {
        "sd7d4949a9e23f:/webcore/ScePsp2Compat.suprx",
        "sd7d4949a9e23f:webcore/ScePsp2Compat.suprx"
    };
    const char *const provider_paths[] = {
        "sd7d4949a9e23f:/tls_fixer/" TLS_FIXER_BROWSER_PROVIDER_FILENAME,
        "sd7d4949a9e23f:tls_fixer/" TLS_FIXER_BROWSER_PROVIDER_FILENAME
    };
    for (size_t i = 0; i < sizeof(browser_paths) / sizeof(browser_paths[0]); ++i) {
        reset();
        assert(load_for_pid_patched(123, browser_paths[i], 0x1000, &options) == 88);
        assert(injections == 1 && injected_pid == 123 && dns_loads == 0 && native_calls == 1);
        assert(path_calls == 2 && counted_loads == 1);
        assert(strcmp(input_path_seen, browser_paths[i]) == 0);
        assert(strcmp(provider_path, provider_paths[i]) == 0);
        assert(strcmp(route_events[0].stage, "load.enter") == 0);
        assert(strcmp(route_events[1].stage, "load.selected") == 0);
        assert(strcmp(route_events[route_event_count - 1].stage, "hook.return") == 0);
        reset();
        trace_fail_stage = "load.selected";
        assert(load_for_pid_patched(123, browser_paths[i], 0x1000, &options) == 88);
        assert(injections == 0 && native_calls == 1 && dns_loads == 0);
        trace_fail_stage = NULL;
    }
#endif
    reset();
    load_result = -5;
    assert(load_for_pid_patched(0, "wb0:/webcore/ScePsp2Compat.suprx", 0x1000, &options) == -5);
    assert(injections == 0 && dns_loads == 0);
    reset();
    injection_result = -42;
    assert(load_for_pid_patched(0, "wb0:/webcore/ScePsp2Compat.suprx", 0x1000, &options) == 88);
    assert(injections == 1 && dns_loads == 0 && native_calls == 1);
    assert(module_stop(0, NULL) == SCE_KERNEL_STOP_FAIL);
    puts("browser-only route: no application or DNS startup, exact namespace and fail-closed diagnostics PASS");
    return 0;
}
