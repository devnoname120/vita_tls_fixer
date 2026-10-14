#define TLS_FIXER_NAME_QUERY_FIXTURE_ONLY 1
#include "test_name_query.c"

int main(void) {
    reset();
    assert(tls_fixer_kernel_loader_init() == 0);
    const char *excluded[] = {"NPXS10015", "NPXS10003", "NPXS10083", "OTHER0001"};
    for (size_t i=0;i<sizeof(excluded)/sizeof(excluded[0]);++i) {
        process_title = excluded[i];
        assert(tls_fixer_kernel_inject_for_pid(99,88)==0);
        assert(loads==0 && query_allocations==0 && argument_allocations==0 && stack_calls==0);
    }
    process_title="TLSCK0001";
    /* Shell identity wins even if a test title matches. No preparation or
     * namespace queries may run for its shared-library consumers. */
    shell_pid = 99;
    unsigned int previous_title_queries = process_title_queries;
    assert(tls_fixer_kernel_http_process_allowed(99) == 0);
    assert(tls_fixer_kernel_inject_for_pid(99,88) == 0);
    assert(process_title_queries == previous_title_queries && loads == 0 &&
        query_allocations == 0 && argument_allocations == 0 && stack_calls == 0);
    shell_pid = 77;
    main_shared = 1;
    assert(tls_fixer_kernel_http_process_allowed(99) == 0);
    assert(tls_fixer_kernel_inject_for_pid(99,88) == 0);
    main_shared = -1;
    assert(tls_fixer_kernel_http_process_allowed(99) < 0);
    assert(tls_fixer_kernel_inject_for_pid(99,88) < 0);
    assert(loads == 0 && query_allocations == 0 && argument_allocations == 0 && stack_calls == 0);
    main_shared = 0;
    expected_path="vs0:/data/external/tls_fixer/native/tls_fixer_http.suprx";
    libc_result=NAME_NOT_FOUND;
    http_shared_result = 1;
    assert(tls_fixer_kernel_inject_for_pid(99,88)==0 && loads==1);
    http_shared_result = -1;
    assert(tls_fixer_kernel_inject_for_pid(99,88)==0 && loads==2);
    http_shared_result = 0;
    unsigned int previous_allocations = argument_allocations;
    assert(tls_fixer_kernel_inject_for_pid(99,88)==0);
    assert(loads==3 && libc_queries==0 && argument_allocations==previous_allocations+1 && stack_calls==3);
    assert(query_allocations==query_frees && argument_allocations==argument_frees && !locked);
    tls_fixer_kernel_loader_destroy();
    return 0;
}
