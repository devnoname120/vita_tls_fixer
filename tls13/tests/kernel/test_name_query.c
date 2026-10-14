#define main tls_fixer_shared_loader_suite
#include "test_loader.c"
#undef main

#define NAME_NOT_FOUND ((int32_t)UINT32_C(0x90010002))

static int target_name_result, provider_name_result = NAME_NOT_FOUND;
static int target_name_uid = 188, provider_name_uid = 199;
static int wrong_target_name, wrong_provider_name, missing_target_nul, missing_provider_nul;
static unsigned int name_target_calls, name_provider_calls;
static int libc_result, libc_uid = 177, wrong_libc_name;
static unsigned int libc_queries;

int taiGetModuleInfoForKernel(SceUID pid, const char *name, tai_module_info_t *info) {
    assert(pid == 99 && !locked && info->size == sizeof(*info));
    require_query_workspace(info, sizeof(*info));
    assert(info->modid == 0 && info->name[sizeof(info->name) - 1] == 0);
    if (strcmp(name, "SceLibc") == 0) {
        assert(!TLS_FIXER_PREPARE_ONLY);
        assert(strstr(expected_path, "/" TLS_FIXER_BROWSER_PROVIDER_FILENAME) == NULL);
#if TLS_FIXER_ENABLE_BOOT_TRACE
        assert(strcmp(last_stage, "prereq.libc.enter") == 0);
#endif
        ++libc_queries;
        if (libc_result != 0) return libc_result;
        info->modid = libc_uid;
        strcpy(info->name, wrong_libc_name ? "wrong" : name);
        return 0;
    }
    int target = strcmp(name, "SceLibHttp") == 0 || strcmp(name, "ScePsp2Compat") == 0;
    int browser = strstr(expected_path, "/" TLS_FIXER_BROWSER_PROVIDER_FILENAME) != NULL;
    assert(strcmp(name, target ? (browser ? "ScePsp2Compat" : "SceLibHttp")
                              : (browser ? "tls_fixer" : "tls_fixer_http")) == 0);
#if TLS_FIXER_ENABLE_BOOT_TRACE
    assert(strcmp(last_stage, target ? "name.target.enter" : "name.provider.enter") == 0);
#endif
    if (target) ++name_target_calls;
    else ++name_provider_calls;
    int result = target ? target_name_result : provider_name_result;
    if (result != 0) return result;
    info->modid = target ? target_name_uid : provider_name_uid;
    int bad_name = target ? wrong_target_name : wrong_provider_name;
    strcpy(info->name, bad_name ? "different" : name);
    if (target ? missing_target_nul : missing_provider_nul) memset(info->name, 'x', sizeof(info->name));
    return 0;
}

#ifndef TLS_FIXER_NAME_QUERY_FIXTURE_ONLY
static void assert_clean(void) {
    assert(!query_live && query_allocations == query_frees);
    assert(!workspace_live && allocations == frees && open_descriptors == 0);
    assert(!locked && loads == 0 && unloads == 0 && list_queries == 0);
}

int main(void) {
    static const char *const failures[] = {
        "reserve.enter", "reserve.return", "query.alloc.enter", "query.alloc.return",
        "query.base.enter", "query.base.return", "scan.enter", "name.target.enter",
        "name.target.return", "name.provider.enter", "name.provider.return", "scan.return",
        "hash.enter", "hash.return", "hash.stat.enter", "hash.stat.return",
        "hash.alloc.enter", "hash.alloc.return", "hash.base.enter", "hash.base.return",
        "hash.open.enter", "hash.open.return", "hash.init.enter", "hash.init.return",
        "hash.stream.enter", "hash.stream.return", "hash.read.enter", "hash.read.return",
        "hash.update.enter", "hash.update.return", "hash.finish.enter", "hash.finish.return",
        "hash.close.enter", "hash.close.return", "hash.free.enter", "hash.free.return",
        "hash.compare.enter", "hash.compare.return", "target.info.enter", "target.info.return",
        "query.free.enter", "query.free.return", "stack.extend.enter", "stack.extend.return",
        "stack.callback.enter", "stack.callback.return"
    };
    test_extended_stack_contract();
    test_query_workspace_failures();
    test_workspace_failures();
    reset();
    assert(tls_fixer_kernel_loader_init() == 0);
    checking_hash_trace = 1;
    module_info_error = scan_error = 1;
    for (unsigned int i = 0; i < 80; ++i) {
        unsigned int before_target = name_target_calls, before_provider = name_provider_calls;
        unsigned int before_info = target_queries;
        expected_path = "vs0:/data/external/tls_fixer/native/tls_fixer_http.suprx";
        assert(tls_fixer_kernel_inject_for_pid(99, 88) == 0);
        expected_path = "wb0:/tls_fixer/tls_fixer.suprx";
        assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) == 0);
        assert(name_target_calls == before_target + 2 && name_provider_calls == before_provider + 2);
        assert(target_queries == before_info + 2);
        assert_clean();
    }
    provider_name_result = 0;
    unsigned int before_info = target_queries, before_hash = allocations;
    assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) == 0);
    assert(target_queries == before_info && allocations == before_hash);
    assert_clean();

    const int invalid_results[] = {-1, -42, 1, (int32_t)UINT32_C(0x90010000),
        (int32_t)UINT32_C(0x90010001), (int32_t)UINT32_C(0x9001000c)};
    for (size_t i = 0; i < sizeof(invalid_results) / sizeof(invalid_results[0]); ++i) {
        provider_name_result = invalid_results[i];
        assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0);
        assert_clean();
    }
    provider_name_result = NAME_NOT_FOUND;
    const int target_results[] = {NAME_NOT_FOUND, -1, 1};
    for (size_t i = 0; i < sizeof(target_results) / sizeof(target_results[0]); ++i) {
        target_name_result = target_results[i];
        unsigned int before = name_provider_calls;
        assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0);
        assert(name_provider_calls == before);
        assert_clean();
    }
    target_name_result = 0;
    int *const bad_names[] = {&wrong_target_name, &wrong_provider_name, &missing_target_nul, &missing_provider_nul};
    provider_name_result = 0;
    for (size_t i = 0; i < sizeof(bad_names) / sizeof(bad_names[0]); ++i) {
        *bad_names[i] = 1;
        assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0);
        *bad_names[i] = 0;
        assert_clean();
    }
    for (int id = 0; id >= -1; --id) {
        target_name_uid = id;
        assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0);
        target_name_uid = 188;
        provider_name_uid = id;
        assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0);
        provider_name_uid = 199;
        assert_clean();
    }
    provider_name_result = NAME_NOT_FOUND;
    target_name_uid = 189;
    assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0);
    target_name_uid = 188;
    int *const bad_target[] = {&target_info_error, &target_wrong_name, &corrupt_browser};
    for (size_t i = 0; i < sizeof(bad_target) / sizeof(bad_target[0]); ++i) {
        *bad_target[i] = 1;
        assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0);
        *bad_target[i] = 0;
        assert_clean();
    }
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        trace_fail = failures[i];
        assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0);
        assert_clean();
        trace_fail = NULL;
        assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) == 0);
        assert_clean();
    }
    reset();
    puts("name lookup: positive target control, explicit provider absence, duplicate rejection and cleanup PASS");
    return 0;
}
#endif
