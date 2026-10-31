#include "system_payloads.h"
#include "options.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    const char *paths[16];
    unsigned count, calls, fail_at, coordinator_calls;
    const char *sources[8], *destinations[8];
    TlsFixerSystemBackend backend;
} Files;
static int exists(void *context, const char *path) {
    Files *f = context;
    for (unsigned i = 0; i < f->count; ++i) if (!strcmp(f->paths[i], path)) return 1;
    return 0;
}
static int replace(void *context, const char *source, const char *destination) {
    Files *f = context;
    unsigned at = f->calls++;
    assert(at < 8); f->sources[at] = source; f->destinations[at] = destination;
    if (f->fail_at && f->calls == f->fail_at) return -77;
    if (!exists(f, destination)) { assert(f->count < 16); f->paths[f->count++] = destination; }
    return 0;
}
static int remove_file(void *context, const char *path) {
    Files *f = context;
    ++f->calls;
    if (f->fail_at && f->calls == f->fail_at) return -77;
    for (unsigned i = 0; i < f->count; ++i) if (!strcmp(f->paths[i], path)) {
        f->paths[i] = f->paths[--f->count]; break;
    }
    return 0;
}
static TlsFixerSystemFiles ops(Files *f) {
    TlsFixerSystemFiles o = {exists, replace, remove_file, f}; return o;
}
static void helpers(Files *f) {
    f->paths[f->count++] = "vs0:/data/external/tls_fixer/native/tls_fixer_psn.suprx";
    f->paths[f->count++] = "vs0:/data/external/tls_fixer/native/tls_fixer_store.suprx";
}
static int component(void *context, unsigned which, int removing) {
    Files *f = context; TlsFixerSystemFiles o = ops(f);
    if (which == TLS_FIXER_COMPONENT_CONFLICTS) { assert(!removing); return 0; }
    if (which == TLS_FIXER_COMPONENT_SYSTEM)
        return tls_fixer_update_system_payloads(f->backend, removing, &o);
    assert(which == TLS_FIXER_COMPONENT_COORDINATOR); ++f->coordinator_calls; return 0;
}
int main(void) {
    Files f = {0}; TlsFixerSystemFiles o = ops(&f);
    assert(!tls_fixer_system_payloads_present(TLS_FIXER_SYSTEM_AUGMENTED, &o));
    assert(tls_fixer_update_system_payloads(TLS_FIXER_SYSTEM_AUGMENTED, 0, &o) == 0);
    assert(f.calls == 2 && !strcmp(f.sources[0], "app0:libhttp_augmented.suprx"));
    assert(!strcmp(f.destinations[0], "ux0:/data/tls_fixer-runtime-installer/libhttp.suprx"));
    assert(!strcmp(f.sources[1], "app0:lssl.suprx"));
    assert(!exists(&f, "vs0:/data/external/tls_fixer/libhttp.suprx"));
    assert(!exists(&f, "vs0:/data/external/tls_fixer/native/tls_fixer_http.suprx"));
    assert(!tls_fixer_system_payloads_complete(TLS_FIXER_SYSTEM_AUGMENTED, &o));
    f.paths[f.count++] = TLS_FIXER_AUGMENTED_PSN_MODULE_PATH;
    f.paths[f.count++] = TLS_FIXER_AUGMENTED_STORE_MODULE_PATH;
    assert(tls_fixer_system_payloads_complete(TLS_FIXER_SYSTEM_AUGMENTED, &o));
    assert(!tls_fixer_system_payloads_complete(TLS_FIXER_SYSTEM_HOOKED, &o));
    assert(tls_fixer_system_payloads_present(TLS_FIXER_SYSTEM_AUGMENTED, &o));

    memset(&f, 0, sizeof(f));
    assert(tls_fixer_update_system_payloads(TLS_FIXER_SYSTEM_HOOKED, 0, &o) == 0);
    assert(f.calls == 3 && !strcmp(f.sources[0], "app0:tls_fixer_http.suprx"));
    assert(!strcmp(f.sources[1], "app0:lhttp.suprx") && !strcmp(f.sources[2], "app0:lssl.suprx"));
    helpers(&f);
    /* Current installers remove the old DNS/Commerce payloads, even on 3.60. */
    assert(tls_fixer_system_payloads_complete(TLS_FIXER_SYSTEM_HOOKED, &o));
    assert(!exists(&f, "vs0:/data/external/tls_fixer/old_dns_fix.suprx"));
    assert(!exists(&f, "vs0:/data/external/tls_fixer/np_commerce2.suprx"));
    assert(tls_fixer_update_system_payloads(TLS_FIXER_SYSTEM_AUGMENTED, 0, &o) == 0);
    const char *browser = "vs0:/data/external/tls_fixer/native/tls_fixer.suprx";
    const char *cert = "vs0:/data/external/cert/CA_LIST.cer";
    const char *redirect = "ux0:data/tls_fixer/redirects.txt";
    f.paths[f.count++] = browser; f.paths[f.count++] = cert; f.paths[f.count++] = redirect;
    f.calls = 0;
    assert(tls_fixer_update_system_payloads(TLS_FIXER_SYSTEM_HOOKED, 1, &o) == 0);
    assert(f.calls == 3 && exists(&f, browser) && exists(&f, cert) && exists(&f, redirect));
    assert(exists(&f, TLS_FIXER_AUGMENTED_HTTP_MODULE_PATH));
    assert(!exists(&f, "vs0:/data/external/tls_fixer/libhttp.suprx"));
    assert(!exists(&f, "vs0:/data/external/tls_fixer/libssl.suprx"));
    assert(!tls_fixer_system_payloads_complete(TLS_FIXER_SYSTEM_HOOKED, &o));

    memset(&f, 0, sizeof(f));
    assert(tls_fixer_update_system_payloads(TLS_FIXER_SYSTEM_HOOKED, 0, &o) == 0);
    helpers(&f);
    f.paths[f.count++] = browser; f.paths[f.count++] = cert; f.paths[f.count++] = redirect;
    f.calls = 0;
    assert(tls_fixer_update_system_payloads(TLS_FIXER_SYSTEM_AUGMENTED_RELEASE, 0, &o) == 0);
    assert(f.calls == 2 && !strcmp(f.sources[0], "app0:libhttp_augmented.suprx"));
    assert(!strcmp(f.destinations[0], TLS_FIXER_RELEASE_HTTP_MODULE_PATH));
    assert(!strcmp(f.destinations[1], TLS_FIXER_RELEASE_SSL_MODULE_PATH));
    assert(tls_fixer_system_payloads_complete(TLS_FIXER_SYSTEM_AUGMENTED_RELEASE, &o));
    assert(tls_fixer_system_payloads_present(TLS_FIXER_SYSTEM_AUGMENTED_RELEASE, &o));
    assert(exists(&f, "vs0:/data/external/tls_fixer/libhttp.suprx"));
    f.calls = 0;
    assert(tls_fixer_update_system_payloads(TLS_FIXER_SYSTEM_AUGMENTED_RELEASE, 1, &o) == 0);
    assert(f.calls == 5 && exists(&f, browser) && exists(&f, cert) && exists(&f, redirect));
    assert(!exists(&f, TLS_FIXER_RELEASE_HTTP_MODULE_PATH) && !exists(&f, TLS_FIXER_RELEASE_SSL_MODULE_PATH));
    assert(!exists(&f, "vs0:/data/external/tls_fixer/libhttp.suprx"));
    assert(!exists(&f, "vs0:/data/external/tls_fixer/native/tls_fixer_http.suprx"));
    assert(!tls_fixer_system_payloads_complete(TLS_FIXER_SYSTEM_AUGMENTED_RELEASE, &o));

    for (unsigned failure = 1; failure <= 2; ++failure) {
        memset(&f, 0, sizeof(f)); f.fail_at = failure; f.backend = TLS_FIXER_SYSTEM_AUGMENTED_RELEASE;
        TlsFixerInstallPlan plan;
        assert(tls_fixer_plan_option(TLS_FIXER_OPTION_SYSTEM, 0, 1, 0, &plan) == 0);
        assert(tls_fixer_execute_plan(&plan, component, &f) == -77);
        assert(f.calls == failure && f.coordinator_calls == 0);
    }
    for (unsigned failure = 1; failure <= 2; ++failure) {
        memset(&f, 0, sizeof(f)); f.fail_at = failure; f.backend = TLS_FIXER_SYSTEM_AUGMENTED;
        TlsFixerInstallPlan plan;
        assert(tls_fixer_plan_option(TLS_FIXER_OPTION_SYSTEM, 0, 1, 0, &plan) == 0);
        assert(tls_fixer_execute_plan(&plan, component, &f) == -77);
        assert(f.calls == failure && f.coordinator_calls == 0);
    }
    for (unsigned failure = 1; failure <= 2; ++failure) {
        memset(&f, 0, sizeof(f)); f.fail_at = failure; f.backend = TLS_FIXER_SYSTEM_AUGMENTED;
        TlsFixerInstallPlan plan;
        assert(tls_fixer_plan_option(TLS_FIXER_OPTION_SYSTEM, 1, 0, 1, &plan) == 0);
        assert(tls_fixer_execute_plan(&plan, component, &f) == -77);
        assert(f.calls == failure && f.coordinator_calls == 0);
    }
    f.calls = 0;
    assert(tls_fixer_update_system_payloads((TlsFixerSystemBackend)99, 0, &o) == -1 && f.calls == 0);
    puts("PASS system payload installation, inventory, removal and failure ordering");
    return 0;
}
