#include "options.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
typedef struct { unsigned present, calls[5], count, fail; } State;
static int apply(void *context, unsigned component, int removing) {
    State *s = context;
    assert(s->count < 5);
    s->calls[s->count++] = component;
    if (component == s->fail) return -71;
    if (component == TLS_FIXER_COMPONENT_CONFLICTS) { assert(!removing); return 0; }
    if (removing) s->present &= ~component;
    else s->present |= component;
    return 0;
}
static State run(enum TlsFixerOption option, int removing, unsigned present) {
    TlsFixerInstallPlan p;
    assert(tls_fixer_plan_option(option, removing, present & TLS_FIXER_COMPONENT_BROWSER,
                                present & TLS_FIXER_COMPONENT_SYSTEM, &p) == 0);
    State s = {.present = present};
    assert(tls_fixer_execute_plan(&p, apply, &s) == 0);
    return s;
}
int main(void) {
    const unsigned k = TLS_FIXER_COMPONENT_COORDINATOR, b = TLS_FIXER_COMPONENT_BROWSER,
                   h = TLS_FIXER_COMPONENT_SYSTEM, c = TLS_FIXER_COMPONENT_CERTIFICATES;
    assert(run(TLS_FIXER_OPTION_FULL, 0, 0).present == (k|b|h|c));
    State full = run(TLS_FIXER_OPTION_FULL, 0, 0);
    assert(full.calls[0] == TLS_FIXER_COMPONENT_CONFLICTS);
    assert(full.calls[full.count - 1] == k);
    assert(run(TLS_FIXER_OPTION_BROWSER, 0, 0).present == (k|b));
    assert(run(TLS_FIXER_OPTION_SYSTEM, 0, 0).present == (k|h));
    assert(run(TLS_FIXER_OPTION_CERTIFICATES, 0, 0).present == c);
    assert(run(TLS_FIXER_OPTION_BROWSER, 0, k|h|c).present == (k|b|h|c));
    assert(run(TLS_FIXER_OPTION_SYSTEM, 0, k|b|c).present == (k|b|h|c));
    assert(run(TLS_FIXER_OPTION_BROWSER, 1, k|b|h|c).present == (k|h|c));
    assert(run(TLS_FIXER_OPTION_SYSTEM, 1, k|b|h|c).present == (k|b|c));
    assert(run(TLS_FIXER_OPTION_BROWSER, 1, k|b|c).present == c);
    assert(run(TLS_FIXER_OPTION_SYSTEM, 1, k|h|c).present == c);
    assert(run(TLS_FIXER_OPTION_CERTIFICATES, 1, k|b|h|c).present == (k|b|h));
    assert(run(TLS_FIXER_OPTION_FULL, 1, k|b|h|c).present == 0);
    /* Every installation/refresh, including certs-only, removes conflicts
     * first; uninstall must not remove another plugin as a side effect. */
    for (int option = TLS_FIXER_OPTION_FULL; option <= TLS_FIXER_OPTION_CERTIFICATES; ++option) {
        assert(run((enum TlsFixerOption)option, 0, 0).calls[0] == TLS_FIXER_COMPONENT_CONFLICTS);
        assert(run((enum TlsFixerOption)option, 1, k|b|h|c).calls[0] != TLS_FIXER_COMPONENT_CONFLICTS);
        TlsFixerInstallPlan blocked_plan;
        assert(tls_fixer_plan_option((enum TlsFixerOption)option, 0, 0, 0, &blocked_plan) == 0);
        State blocked = {.fail = TLS_FIXER_COMPONENT_CONFLICTS};
        assert(tls_fixer_execute_plan(&blocked_plan, apply, &blocked) == -71);
        assert(blocked.count == 1 && blocked.present == 0);
    }
    TlsFixerInstallPlan p;
    assert(tls_fixer_plan_option(TLS_FIXER_OPTION_FULL, 0, 0, 0, &p) == 0);
    State failed = {.fail = c};
    assert(tls_fixer_execute_plan(&p, apply, &failed) == -71);
    assert(failed.present == (b|h) && !(failed.present & k));
    assert(tls_fixer_plan_option(TLS_FIXER_OPTION_FULL, 1, 1, 1, &p) == 0);
    failed = (State){.present = k|b|h|c, .fail = h};
    assert(tls_fixer_execute_plan(&p, apply, &failed) == -71);
    assert(failed.present == (k|h|c));
    assert(tls_fixer_plan_option(TLS_FIXER_OPTION_EXIT, 0, 0, 0, &p) < 0);
    assert(tls_fixer_plan_option((enum TlsFixerOption)-1, 0, 0, 0, &p) < 0);
    assert(tls_fixer_plan_option(TLS_FIXER_OPTION_FULL, 0, 0, 0, NULL) < 0);
    puts("Installer component isolation, shared coordinator, refresh and failure ordering: PASS");
}
