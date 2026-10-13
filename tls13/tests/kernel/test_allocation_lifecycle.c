#define main unused_route_suite
#include "test_route.c"
#undef main
static int preparation_result, installation_result, probe_resident;
int tls_fixer_allocation_probe_prepare(void) { assert(disarm_calls == 1); return preparation_result; }
int tls_fixer_allocation_probe_install(void) {
    assert(status_starts == 1 && hook_installations == 0);
    probe_resident = installation_result >= 0; return installation_result;
}
int tls_fixer_allocation_probe_resident(void) { return probe_resident; }
void tls_fixer_allocation_probe_drain(void) {}
int main(int argc, char **argv) {
    assert(argc == 2); reset(); checking_startup = 1;
    if (strcmp(argv[1], "prepare-fail") == 0) preparation_result = -1;
    if (strcmp(argv[1], "install-fail") == 0) installation_result = -2;
    if (strcmp(argv[1], "after-publication") == 0) trace_fail_stage = "hook.install.enter";
    int result = module_start(0, NULL);
    if (preparation_result || installation_result) {
        assert(result == SCE_KERNEL_START_FAILED && hook_installations == 0 && !probe_resident);
        assert(loader_destructions == 1 && trace_closes == 1);
    } else {
        assert(result == SCE_KERNEL_START_SUCCESS && probe_resident);
        assert(loader_destructions == 0 && trace_closes == 0 && status_stops == 0);
        assert(module_stop(0, NULL) == SCE_KERNEL_STOP_FAIL);
        assert(hook_installations == (strcmp(argv[1], "after-publication") == 0 ? 0 : 1));
    }
    puts("allocation observer: refuse before publication; retain code and worker after publication PASS");
}
