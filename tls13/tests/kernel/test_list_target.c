#define main tls_fixer_shared_loader_suite
#include "test_loader.c"
#undef main

static void assert_clean(void) {
    assert(!query_live && query_allocations == query_frees);
    assert(!workspace_live && allocations == frees && open_descriptors == 0);
    assert(!locked && loads == 0 && unloads == 0);
}

int main(void) {
    static const char *const failures[] = {
        "reserve.enter", "reserve.return", "query.alloc.enter", "query.alloc.return",
        "query.base.enter", "query.base.return", "scan.enter", "module.list.enter",
        "module.list.return", "module.inspect.skipped", "scan.return", "hash.enter",
        "hash.return", "hash.stat.enter", "hash.stat.return", "hash.alloc.enter",
        "hash.alloc.return", "hash.base.enter", "hash.base.return", "hash.open.enter",
        "hash.open.return", "hash.init.enter", "hash.init.return", "hash.stream.enter",
        "hash.stream.return", "hash.read.enter", "hash.read.return", "hash.update.enter",
        "hash.update.return", "hash.finish.enter", "hash.finish.return", "hash.close.enter",
        "hash.close.return", "hash.free.enter", "hash.free.return", "hash.compare.enter",
        "hash.compare.return", "target.info.enter", "target.info.return", "query.free.enter",
        "query.free.return", "stack.extend.enter", "stack.extend.return",
        "stack.callback.enter", "stack.callback.return"
    };
    const int counts[] = {0, 1, 255, 256, 257};
    test_extended_stack_contract();
    test_query_workspace_failures();
    test_workspace_failures();
    reset();
    assert(tls_fixer_kernel_loader_init() == 0);
    checking_hash_trace = 1;
    module_info_error = 1;
    for (unsigned int i = 0; i < 80; ++i) {
        unsigned int before_list = list_queries, before_target = target_queries;
        expected_path = "vs0:/data/external/tls_fixer/native/tls_fixer_http.suprx";
        assert(tls_fixer_kernel_inject_for_pid(99, 88) == 0);
        expected_path = "wb0:/tls_fixer/tls_fixer.suprx";
        assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) == 0);
        assert(list_queries == before_list + 2 && target_queries == before_target + 2);
        assert_clean();
    }
    for (size_t i = 0; i < sizeof(counts) / sizeof(counts[0]); ++i) {
        unsigned int before_target = target_queries;
        list_count_override = counts[i];
        int result = tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path);
        assert(counts[i] < 256 ? result == 0 : result < 0);
        assert(target_queries == before_target + (counts[i] < 256 ? 1u : 0u));
        assert_clean();
    }
    list_count_override = -1;
    scan_error = 1;
    unsigned int before_target = target_queries;
    assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0);
    assert(target_queries == before_target);
    assert_clean();
    scan_error = 0;
    int *const rejected[] = {&target_info_error, &target_wrong_name, &corrupt_browser};
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        *rejected[i] = 1;
        assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0);
        *rejected[i] = 0;
        assert_clean();
        assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) == 0);
    }
    for (int id = 0; id >= -1; --id) {
        target_user_id = id;
        assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0);
        assert_clean();
    }
    target_user_id = 188;
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        trace_fail = failures[i];
        assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0);
        assert_clean();
        trace_fail = NULL;
        assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) == 0);
        assert_clean();
    }
    reset();
    puts("list-and-target diagnostic: enumeration and target query, no other metadata or provider starts PASS");
    return 0;
}
