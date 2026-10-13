#define main unused_route_suite
#include "test_route.c"
#undef main

int main(void) {
    reset();
    g_dns_fix_state = 2;
    assert(load_for_pid_patched(0, "vs0:sys/external/libssl.suprx", 0, NULL) == 88);
    assert(dns_loads == 0 && g_dns_fix_state == 2);
    assert(strcmp(selected_path, g_replacement_modules[2]) == 0);
    reset();
    assert(load_for_pid_patched(99, "vs0:sys/external/libhttp.suprx", 0, NULL) == 88);
    assert(injections == 1 && injected_pid == 99);
    reset();
    assert(load_for_pid_patched(99, "wb0:/webcore/ScePsp2Compat.suprx", 0x1000, NULL) == 88);
    assert(injections == 1 && injected_pid == 99);
    puts("DNS isolation: only helper startup excluded; both TLS routes and module redirection retained PASS");
    return 0;
}
