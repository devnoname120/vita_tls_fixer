#define TLS_FIXER_NAME_QUERY_FIXTURE_ONLY 1
#include "test_name_query.c"

static void clean_context(void) {
    assert(!query_live && query_allocations == query_frees);
    assert(!workspace_live && allocations == frees && open_descriptors == 0);
    assert(!argument_live && argument_allocations == argument_frees);
    assert(!locked && list_queries == 0);
}

int main(void) {
    reset();
    assert(tls_fixer_kernel_loader_init() == 0);
    assert(tls_fixer_kernel_loader_ready() && tls_fixer_kernel_browser_loader_ready());
    scan_error = module_info_error = 1;
    const char *paths[] = {"vs0:/data/external/tls_fixer/tls_fixer_http.suprx",
        "wb0:/tls_fixer/tls_fixer.suprx"};
    for (unsigned int target = 0; target < 2; ++target) {
        expected_path = paths[target];
        unsigned int before_loads = (unsigned int)loads, before_stack = stack_calls;
        unsigned int before_queries = target_queries;
        int result = target ? tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path)
            : tls_fixer_kernel_inject_for_pid(99, 88);
        assert(result == 0 && (unsigned int)loads == before_loads + 1);
        assert(stack_calls == before_stack + 1 && target_queries == before_queries + 1);
        clean_context();
        provider_name_result = 0;
        result = target ? tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path)
            : tls_fixer_kernel_inject_for_pid(99, 88);
        assert(result == 0 && (unsigned int)loads == before_loads + 1);
        clean_context();
        provider_name_result = -42;
        result = target ? tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path)
            : tls_fixer_kernel_inject_for_pid(99, 88);
        assert(result < 0 && (unsigned int)loads == before_loads + 1);
        clean_context();
        provider_name_result = NAME_NOT_FOUND;
        stack_skip = 1;
        result = target ? tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path)
            : tls_fixer_kernel_inject_for_pid(99, 88);
        assert(result < 0 && (unsigned int)loads == before_loads + 1);
        clean_context();
        stack_skip = 0;
    }
    assert(name_target_calls == 6 && name_provider_calls == 6);
    reset();
    puts("normal providers: native stack, narrow lookup, duplicate/failure gates and both targets PASS");
    return 0;
}
