#define main legacy_route_test_main
#include "test_route.c"
#undef main

int main(void) {
    reset();
    current_pid = 99;
    checking_startup = 1;
    assert(module_start(0, NULL) == SCE_KERNEL_START_SUCCESS);
    assert(disarm_calls == 1 && startup_operations > 0);
    checking_startup = 0;
    static const char *const paths[] = {
        "vs0:sys/external/libhttp.suprx", "vs0:/sys/external/libhttp.suprx",
        "vs0:sys/external/libssl.suprx", "vs0:sys/external/libpaf.suprx",
        "vs0:sys/external/np_utility.suprx", "ux0:/unrelated.suprx"};
    const uint32_t flags[] = {0, 1, 0x8000, 0x08008001, 0x08000001};
    for (unsigned int p = 0; p < sizeof(paths)/sizeof(paths[0]); ++p) {
        for (unsigned int f = 0; f < sizeof(flags)/sizeof(flags[0]); ++f) {
            reset();
            g_replace_iap = 1;
            g_dns_fix_state = 0;
            http_mapping_private = 1; /* Must not force even a late NP/PAF client private. */
            assert(load_for_pid_patched(99, paths[p], flags[f], NULL) == 88);
            const char *expected = p < 2 ? TLS_FIXER_HTTP_REPLACEMENT_PATH :
                p == 2 ? g_replacement_modules[2] : paths[p];
            assert(strcmp(selected_path, expected) == 0);
            assert(seen_flags == flags[f] && injections == 0 && http_mapping_queries == 0);
        }
    }
    reset();
    g_replace[0] = 1;
    assert(load_for_pid_patched(99, "wb0:/webcore/ScePsp2Compat.suprx", 0x8001, NULL) == 88);
    assert(strcmp(selected_path, "wb0:/tls_fixer/ScePsp2Compat.suprx") == 0 && injections == 1);
    puts("Embedded HTTP: disarm precedes activation; native flags retained; no HTTP injection/private GUI routing; Browser route retained");
    return 0;
}
