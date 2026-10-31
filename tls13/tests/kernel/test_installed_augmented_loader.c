#define main unused_legacy_loader_main
#define ksceIoGetstat fixture_getstat
#include "test_loader.c"
#undef ksceIoGetstat
#undef main

static unsigned legacy_provider_stats;
int ksceIoGetstat(const char *path, SceIoStat *info) {
    if (strstr(path, "tls_fixer_http.suprx")) ++legacy_provider_stats;
    return fixture_getstat(path, info);
}

int main(void) {
    reset();
    http_file = browser_file = 0;
    assert(tls_fixer_kernel_loader_init() == 0);
    assert(!tls_fixer_kernel_loader_ready() && !tls_fixer_kernel_browser_loader_ready());
    assert(!mutex_live && legacy_provider_stats == 0 && allocations == frees);

    reset();
    http_file = 0; corrupt_http = 1;
    assert(tls_fixer_kernel_loader_init() == 0);
    assert(!tls_fixer_kernel_loader_ready() && tls_fixer_kernel_browser_loader_ready());
    assert(mutex_live && legacy_provider_stats == 0 && allocations == frees);

    reset();
    corrupt_browser = 1;
    assert(tls_fixer_kernel_loader_init() == 0);
    assert(!tls_fixer_kernel_loader_ready() && !tls_fixer_kernel_browser_loader_ready());
    assert(!mutex_live && legacy_provider_stats == 0);
    reset();
    puts("installed augmented HTTP: no legacy provider dependency; independent Browser gate PASS");
    return 0;
}
