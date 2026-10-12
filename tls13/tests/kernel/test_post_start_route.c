#define main unused_route_suite
#include "test_route.c"
#undef main

static int mutex_live, mutex_locked, mutex_create_error;
static unsigned int mutex_deletes, starts;
static int start_result, start_entry_result;
static SceUID expect_start_pid, expect_start_module;
static SceSize expect_start_size;
static const void *expect_start_data, *expect_start_options;
static int *expect_start_status;
static uint32_t expect_start_flags;

static uint32_t imported_movw_fixup(uint32_t word, uint32_t value) {
    return (word & ~UINT32_C(0x70ff040f)) | ((value & 0xf000u) >> 12) |
        ((value & 0x0800u) >> 1) | ((value & 0x0700u) << 20) | ((value & 0xffu) << 16);
}

SceUID ksceKernelCreateMutex(const char *name, unsigned int attr, int count, const void *options) {
    assert(disarm_calls == 1 && disarm_result == 0 && hook_installations == 0);
    assert(name != NULL && attr == 0 && count == 0 && options == NULL && !mutex_live);
    if (mutex_create_error) return -73;
    mutex_live = 1;
    return 41;
}
int ksceKernelDeleteMutex(SceUID id) {
    assert(id == 41 && mutex_live && !mutex_locked && installed_start == NULL);
    mutex_live = 0;
    ++mutex_deletes;
    return 0;
}
int ksceKernelLockMutex(SceUID id, int count, unsigned int *timeout) {
    assert(id == 41 && mutex_live && !mutex_locked && count == 1 && timeout == NULL);
    mutex_locked = 1;
    return 0;
}
int ksceKernelUnlockMutex(SceUID id, int count) {
    assert(id == 41 && mutex_locked && count == 1);
    mutex_locked = 0;
    return 0;
}

static int original_start(SceUID pid, SceUID module, SceSize size, const void *data,
    uint32_t flags, const void *options, int *status) {
    assert(pid == expect_start_pid && module == expect_start_module && size == expect_start_size);
    assert(data == expect_start_data && flags == expect_start_flags && options == expect_start_options);
    assert(status == expect_start_status && !mutex_locked && injections == 0);
    ++starts;
    simulated_detour_literal = imported_movw_fixup(simulated_detour_literal, UINT32_C(0xe00111d4));
    native_link_finished = start_result == 0;
    if (status != NULL) *status = start_entry_result;
    record_event("native.start.call", pid, module, start_result);
    return start_result;
}

static void begin_start(SceUID pid, SceUID module, int outcome, int null_arguments) {
    static const unsigned char bytes[] = {1, 4, 9};
    static const uint32_t option[4] = {16, 1, 2, 3};
    static int status;
    expect_start_pid = pid;
    expect_start_module = module;
    expect_start_size = null_arguments ? 0 : sizeof(bytes);
    expect_start_data = null_arguments ? NULL : bytes;
    expect_start_options = null_arguments ? NULL : option;
    expect_start_status = null_arguments ? NULL : &status;
    expect_start_flags = null_arguments ? 0 : UINT32_C(0x08001002);
    status = -999;
    start_entry_result = 19;
    start_result = outcome;
    unsigned int before = starts;
    assert(installed_start(pid, module, expect_start_size, expect_start_data,
        expect_start_flags, expect_start_options, expect_start_status) == outcome);
    assert(starts == before + 1);
    if (!null_arguments) assert(status == start_entry_result);
}

int main(int argc, char **argv) {
    assert(argc == 2);
    assert(imported_movw_fixup(UINT32_C(0x81280001), UINT32_C(0xe00111d4)) == UINT32_C(0x91d40001));
    const char *scenario = argv[1];
    reset();
    checking_startup = 1;
    if (strcmp(scenario, "disarm-fail") == 0) disarm_result = -1;
    if (strcmp(scenario, "guard-fail") == 0) hook_validation_result = -1;
    if (strcmp(scenario, "init-fail") == 0) mutex_create_error = 1;
    if (strcmp(scenario, "start-install-fail") == 0) start_install_error = 1;
    if (strcmp(scenario, "load-install-fail") == 0) load_install_error = 1;
    if (strcmp(scenario, "after-start-publication") == 0) trace_fail_stage = "hook.install.enter";
    int outcome = module_start(0, NULL);
    if (strcmp(scenario, "valid") != 0) {
        assert(injections == 0 && dns_loads == 0);
        if (load_install_error || strcmp(scenario, "after-start-publication") == 0) {
            assert(outcome == SCE_KERNEL_START_SUCCESS && installed_start != NULL && mutex_live);
            assert(loader_destructions == 0 && trace_closes == 0 && mutex_deletes == 0);
            assert(module_stop(0, NULL) == SCE_KERNEL_STOP_FAIL);
        } else {
            assert(outcome == SCE_KERNEL_START_FAILED && installed_start == NULL && !mutex_live);
            assert(hook_installations == (start_install_error ? 1 : 0));
        }
        return 0;
    }
    assert(outcome == SCE_KERNEL_START_SUCCESS);
    checking_startup = 0;
    record_route = 1;
    int load_options = 4;
    const char *path = "sd0123456789ab:/webcore/ScePsp2Compat.suprx";
    assert(load_for_pid_patched(0, path, 0x1000, &load_options) == 88);
    assert(injections == 0 && dns_loads == 0 && native_calls == 1);
    assert(hook_installations == 2 && installed_start != NULL && mutex_live);
    assert(strcmp(selected_path, "sd0123456789ab:/tls_fixer/ScePsp2Compat.suprx") == 0);
    current_pid = 99;
    begin_start(0, 88, 0, 0);
    assert(injections == 1 && injected_pid == 99 && dns_loads == 0);
    assert(simulated_detour_literal == UINT32_C(0x81280001));
    assert(strcmp(provider_path, "sd0123456789ab:/tls_fixer/tls_fixer.suprx") == 0);
    size_t native = SIZE_MAX, prepared = SIZE_MAX;
    for (size_t i = 0; i < route_event_count; ++i) {
        if (strcmp(route_events[i].stage, "native.start.call") == 0) native = i;
        if (strcmp(route_events[i].stage, "prepare.enter") == 0) prepared = i;
    }
    assert(native < prepared);
    reset();
    begin_start(99, 88, 0, 1);
    assert(injections == 0);
    const int failures[] = {-11, 1, 2};
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        reset();
        assert(load_for_pid_patched(99, path, 0x1000, &load_options) == 88);
        assert(injections == 0);
        begin_start(99, 88, failures[i], 0);
        assert(injections == 0);
        begin_start(99, 88, 0, 1);
        assert(injections == 0);
    }
    reset();
    assert(load_for_pid_patched(99, path, 0x1000, &load_options) == 88);
    injection_result = -81;
    begin_start(99, 88, 0, 1);
    assert(injections == 1);
    reset();
    load_result = -27;
    assert(load_for_pid_patched(99, path, 0x1000, &load_options) == -27);
    begin_start(99, 88, 0, 1);
    assert(injections == 0);
    assert(module_stop(0, NULL) == SCE_KERNEL_STOP_FAIL);
    puts("post-start route: no early injection, native ABI/results and resident-hook safety PASS");
    return 0;
}
