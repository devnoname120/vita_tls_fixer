#include "tls_fixer/path.h"
#include "tls_fixer/browser_start_diagnostics.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    const char *modules[] = {"sd7b188fa1e8ed:/tls_fixer/ScePsp2Compat.suprx", "sd7b188fa1e8ed:tls_fixer/ScePsp2Compat.suprx"};
    const char *providers[] = {"sd7b188fa1e8ed:/tls_fixer/tls_fixer_startdiag.suprx", "sd7b188fa1e8ed:tls_fixer/tls_fixer_startdiag.suprx"};
    char provider[256], module[256], tiny[4] = "abc";
    for (size_t i = 0; i < sizeof(modules) / sizeof(modules[0]); ++i) {
        assert(tls_fixer_browser_provider_path(modules[i], provider, sizeof(provider)) == 1);
        assert(strcmp(provider, providers[i]) == 0);
        assert(tls_fixer_browser_module_path(provider, module, sizeof(module)) == 1);
        assert(strcmp(module, modules[i]) == 0);
        assert(tls_fixer_browser_provider_path(modules[i], tiny, sizeof(tiny)) == 0);
        assert(strcmp(tiny, "abc") == 0);
    }
    assert(tls_fixer_browser_module_path("wb0:/tls_fixer/tls_fixer.suprx", module, sizeof(module)) == 0);
    assert(tls_fixer_browser_module_path("wb0:/nottls_fixer/tls_fixer_startdiag.suprx", module, sizeof(module)) == 0);
    assert(tls_fixer_browser_module_path(NULL, module, sizeof(module)) == 0);
    puts("separate startup-diagnostic provider namespace: PASS");
    return 0;
}
