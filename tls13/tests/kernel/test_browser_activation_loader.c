#define main tls_fixer_shared_loader_suite
#define ksceKernelLoadStartModuleForPid fixture_load_start
#define ksceKernelUnloadModuleForPid fixture_unload
#define ksceKernelGetModuleInfo fixture_module_info
#include "test_loader.c"
#undef main
#undef ksceKernelLoadStartModuleForPid
#undef ksceKernelUnloadModuleForPid
#undef ksceKernelGetModuleInfo

static int named_target_result, named_provider_result = (int32_t)UINT32_C(0x90010002);
static int named_target_id = 188, malformed_name, override_start_status = -1;
static unsigned int named_target_calls, named_provider_calls;
static int shared_result, missing_text;
static unsigned int shared_queries;
#if TLS_FIXER_INSPECT_CONNECT_PATCH
static unsigned int snapshot_calls, provider_info_queries;
static const char *snapshot_fail_stage;
static int provider_info_error;
int tls_fixer_code_snapshot(SceUID pid, const SceKernelModuleInfo *info, size_t offset, const char *stage) {
    assert(pid == 99 && !locked && query_live);
    require_query_workspace(info, sizeof(*info));
    assert(info->segments[0].vaddr == (void *)(uintptr_t)0x81000000);
    ++snapshot_calls;
    if (strcmp(stage, "code.provider") == 0) {
        assert(offset == 0 && strcmp(info->module_name, "tls_fixer") == 0);
    } else {
        assert(offset == (strcmp(stage, "code.wrapper") == 0 ? 0xa6234u : TLS_FIXER_BROWSER_CONNECT_OFFSET));
        assert(strcmp(info->module_name, "ScePsp2Compat") == 0);
    }
    return snapshot_fail_stage != NULL && strcmp(stage, snapshot_fail_stage) == 0 ? -71 : 0;
}
#endif

int ksceKernelGetModuleInfo(SceUID pid, SceUID id, SceKernelModuleInfo *info) {
#if TLS_FIXER_INSPECT_CONNECT_PATCH
    if (id == 777) {
        assert(pid == 99 && info->size == sizeof(*info));
        assert(strcmp(last_stage, "code.provider.info.enter") == 0 && !locked);
        require_query_workspace(info, sizeof(*info));
        ++provider_info_queries;
        strcpy(info->module_name, "tls_fixer");
        info->modid = 199;
        info->segments[0].vaddr = (void *)(uintptr_t)0x81000000;
        return provider_info_error;
    }
#endif
    int result = fixture_module_info(pid, id, info);
    if (result == 0) info->segments[0].vaddr = missing_text ? NULL : (void *)(uintptr_t)0x81000000;
    return result;
}

int ksceKernelGetModuleIsSharedByAddr(SceUID pid, void *address) {
    assert(pid == 99 && address == (void *)(uintptr_t)0x81000000 && !locked);
    assert(strcmp(last_stage, "target.shared.enter") == 0 && query_live);
    ++shared_queries;
    return shared_result;
}

int taiGetModuleInfoForKernel(SceUID pid, const char *name, tai_module_info_t *info) {
    assert(pid == 99 && !locked && info->size == sizeof(*info));
    require_query_workspace(info, sizeof(*info));
    int target = strcmp(name, "ScePsp2Compat") == 0;
    assert(target || strcmp(name, "tls_fixer") == 0);
    assert(strcmp(last_stage, target ? "name.target.enter" : "name.provider.enter") == 0);
    if (target) ++named_target_calls;
    else ++named_provider_calls;
    int result = target ? named_target_result : named_provider_result;
    if (result != 0) return result;
    info->modid = target ? named_target_id : 199;
    strcpy(info->name, malformed_name ? "unrelated" : name);
    return 0;
}

SceUID ksceKernelLoadStartModuleForPid(SceUID pid, const char *path, SceSize size,
    const void *data, int flags, const void *options, int *status) {
    assert(strcmp(last_stage, "provider.start.enter") == 0);
    assert(stack_calls > 0 && query_live && !workspace_live && !locked);
    SceUID result = fixture_load_start(pid, path, size, data, flags, options, status);
    if (override_start_status >= 0) *status = override_start_status;
    return result;
}

int ksceKernelUnloadModuleForPid(SceUID pid, SceUID module, int flags, const void *options) {
    (void)pid; (void)module; (void)flags; (void)options;
    assert(!"The diagnostic must not unload a possibly published user hook");
    return -1;
}

static void clean(void) {
    assert(!argument_live && argument_allocations == argument_frees);
    assert(!query_live && query_allocations == query_frees);
    assert(!workspace_live && allocations == frees && open_descriptors == 0);
    assert(!locked && unloads == 0 && list_queries == 0);
}

int main(void) {
    reset();
    assert(tls_fixer_kernel_loader_init() == 0);
    assert(!tls_fixer_kernel_loader_ready() && tls_fixer_kernel_browser_loader_ready());
    unsigned int before_stack = stack_calls, before_alloc = query_allocations;
    assert(tls_fixer_kernel_inject_for_pid(99, 88) < 0);
    assert(stack_calls == before_stack && query_allocations == before_alloc && loads == 0);
    checking_hash_trace = 1;
    runtime_namespace_required = 1;
    for (unsigned int i = 0; i < 80; ++i) {
        int before = loads;
        reenter = i % 2;
        assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) == 0);
        assert(loads == before + 1);
        clean();
    }
    reenter = 0;
    assert(argument_allocations == 80 && argument_copies == 80);
    assert(namespace_provider_opens == (TLS_FIXER_BROWSER_START_DIAGNOSTICS ? 0u : 80u));
    assert(global_provider_stats == (TLS_FIXER_BROWSER_START_DIAGNOSTICS ? 80u : 0u));
    assert(namespace_hash_opens == 80);
#if TLS_FIXER_INSPECT_CONNECT_PATCH
    assert(snapshot_calls == 320 && provider_info_queries == 80);
    snapshot_fail_stage = "code.before";
    int installed_before = loads;
    assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0 && loads == installed_before);
    clean();
    const char *const after_snapshots[] = {"code.after", "code.wrapper", "code.provider"};
    for (size_t i = 0; i < sizeof(after_snapshots) / sizeof(after_snapshots[0]); ++i) {
        snapshot_fail_stage = after_snapshots[i];
        installed_before = loads;
        assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0 && loads == installed_before + 1);
        clean();
    }
    snapshot_fail_stage = NULL;
    const int info_errors[] = {-72, 1};
    for (size_t i = 0; i < sizeof(info_errors) / sizeof(info_errors[0]); ++i) {
        provider_info_error = info_errors[i];
        installed_before = loads;
        assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0 && loads == installed_before + 1);
        clean();
    }
    provider_info_error = 0;
    clean();
#endif
    int *argument_failures[] = {&argument_alloc_fail, &argument_base_fail, &argument_null_base,
        &argument_copy_fail, &argument_readback_fail, &argument_corrupt};
    for (size_t i = 0; i < sizeof(argument_failures) / sizeof(argument_failures[0]); ++i) {
        int prior_loads = loads;
        *argument_failures[i] = 1;
        assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0 && loads == prior_loads);
        *argument_failures[i] = 0;
        clean();
    }
    argument_current_pid = 100;
    int prior_loads = loads;
    unsigned int prior_allocations = argument_allocations;
    assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0 && loads == prior_loads);
    assert(argument_allocations == prior_allocations);
    argument_current_pid = 99;
    clean();
    const char *provider_paths[] = {
        "sd062e8855c978:/tls_fixer/" TLS_FIXER_BROWSER_PROVIDER_FILENAME,
        "opaque:tls_fixer/" TLS_FIXER_BROWSER_PROVIDER_FILENAME
    };
    const char *module_paths[] = {
        "sd062e8855c978:/tls_fixer/ScePsp2Compat.suprx",
        "opaque:tls_fixer/ScePsp2Compat.suprx"
    };
    for (size_t i = 0; i < sizeof(provider_paths) / sizeof(provider_paths[0]); ++i) {
        expected_path = provider_paths[i];
        expected_module_path = module_paths[i];
        assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) == 0);
        clean();
    }
    expected_path = "wb0:/tls_fixer/" TLS_FIXER_BROWSER_PROVIDER_FILENAME;
    expected_module_path = "wb0:/tls_fixer/ScePsp2Compat.suprx";
    const char *invalid_paths[] = {"wb0:/tls_fixer/other.suprx", "wb0:/nottls_fixer/tls_fixer.suprx",
        ":/tls_fixer/tls_fixer.suprx"};
    for (size_t i = 0; i < sizeof(invalid_paths) / sizeof(invalid_paths[0]); ++i) {
        int prior_loads = loads;
        unsigned int prior_opens = namespace_provider_opens + namespace_hash_opens;
        assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, invalid_paths[i]) < 0 && loads == prior_loads);
        assert(namespace_provider_opens + namespace_hash_opens == prior_opens);
        clean();
    }
    int *namespace_failures[] = {&namespace_provider_error,
#if !TLS_FIXER_BROWSER_START_DIAGNOSTICS
        &namespace_stat_error, &namespace_close_error,
#endif
        &namespace_hash_error, &corrupt_browser};
    for (size_t i = 0; i < sizeof(namespace_failures) / sizeof(namespace_failures[0]); ++i) {
        *namespace_failures[i] = 1;
        int prior_loads = loads;
        assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0 && loads == prior_loads);
        clean();
        *namespace_failures[i] = 0;
    }
    named_provider_result = 0;
    int before = loads;
    unsigned int before_target = target_queries;
    assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) == 0);
    assert(loads == before && target_queries == before_target);
    clean();
    const int unknown[] = {-1, 1, (int32_t)UINT32_C(0x90010001)};
    for (size_t i = 0; i < sizeof(unknown) / sizeof(unknown[0]); ++i) {
        named_provider_result = unknown[i];
        assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0 && loads == before);
        clean();
    }
    named_provider_result = (int32_t)UINT32_C(0x90010002);
    named_target_result = -1;
    assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0 && loads == before);
    named_target_result = 0;
    named_target_id = 189;
    assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0 && loads == before);
    named_target_id = 188;
    malformed_name = 1;
    assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0 && loads == before);
    malformed_name = 0;
    clean();

    const int shared_outcomes[] = {1, -1, 2};
    for (size_t i = 0; i < sizeof(shared_outcomes) / sizeof(shared_outcomes[0]); ++i) {
        shared_result = shared_outcomes[i];
        assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0 && loads == before);
        clean();
    }
    shared_result = 0;
    missing_text = 1;
    unsigned int queries_before = shared_queries;
    assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0 && loads == before);
    assert(shared_queries == queries_before);
    missing_text = 0;
    clean();

    const char *const before_start_failures[] = {
        "reserve.enter", "reserve.return", "query.alloc.enter", "query.alloc.return",
        "query.base.enter", "query.base.return", "scan.enter", "name.target.enter",
        "name.target.return", "name.provider.enter", "name.provider.return", "scan.return",
        "hash.enter", "hash.return", "target.info.enter", "target.info.return",
        "args.alloc.enter", "args.alloc.return", "args.base.enter", "args.base.return",
        "args.copy.enter", "args.copy.return", "args.verify.enter", "args.verify.return",
        "target.shared.enter", "target.shared.return", "provider.start.enter"
    };
    for (size_t i = 0; i < sizeof(before_start_failures) / sizeof(before_start_failures[0]); ++i) {
        trace_fail = before_start_failures[i];
        assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0 && loads == before);
        clean();
    }
    trace_fail = NULL;
    const char *const after_start_failures[] = {
#if TLS_FIXER_INSPECT_CONNECT_PATCH
        "code.provider.info.enter", "code.provider.info.return",
#endif
        "provider.start.return", "provider.status", "query.free.enter", "query.free.return",
        "args.free.enter", "args.free.return",
        "stack.callback.return", "stack.extend.return"
    };
    for (size_t i = 0; i < sizeof(after_start_failures) / sizeof(after_start_failures[0]); ++i) {
        trace_fail = after_start_failures[i];
        before = loads;
        assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0 && loads == before + 1);
        clean();
    }
    trace_fail = NULL;
    load_error = 1;
    assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) == -456);
    load_error = 2;
    assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0);
    load_error = 0;
    override_start_status = 1;
    assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0);
    override_start_status = SCE_KERNEL_START_FAILED;
    assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0);
    override_start_status = -1;
    assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) == 0);
    clean();
    argument_free_fail = 1;
    before = loads;
    assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0 && loads == before + 1);
    argument_free_fail = 0;
    clean();
    reset();
    puts("browser activation: native start arguments, duplicate gate, pre-start failures and resident-hook safety PASS");
    return 0;
}
