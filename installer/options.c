#include "options.h"
#include <stddef.h>
int tls_fixer_plan_option(enum TlsFixerOption option, int removing,
    int browser_present, int system_present, TlsFixerInstallPlan *plan) {
    if (!plan) return -1;
    plan->components = 0;
    plan->removing = !!removing;
    switch (option) {
    case TLS_FIXER_OPTION_FULL:
        plan->components = TLS_FIXER_COMPONENT_COORDINATOR | TLS_FIXER_COMPONENT_BROWSER |
            TLS_FIXER_COMPONENT_SYSTEM | TLS_FIXER_COMPONENT_CERTIFICATES;
        break;
    case TLS_FIXER_OPTION_BROWSER:
        plan->components = TLS_FIXER_COMPONENT_BROWSER;
        if (!removing || !system_present) plan->components |= TLS_FIXER_COMPONENT_COORDINATOR;
        break;
    case TLS_FIXER_OPTION_SYSTEM:
        plan->components = TLS_FIXER_COMPONENT_SYSTEM;
        if (!removing || !browser_present) plan->components |= TLS_FIXER_COMPONENT_COORDINATOR;
        break;
    case TLS_FIXER_OPTION_CERTIFICATES:
        plan->components = TLS_FIXER_COMPONENT_CERTIFICATES;
        break;
    default: return -1;
    }
    if (!removing) plan->components |= TLS_FIXER_COMPONENT_CONFLICTS;
    return 0;
}
int tls_fixer_execute_plan(const TlsFixerInstallPlan *plan, TlsFixerInstallAction action, void *context) {
    if (!plan || !action) return -1;
    /* Install/enable the shared coordinator only after its payloads are ready.
     * Remove it only after selected payload removals have succeeded. */
    static const unsigned order[] = {TLS_FIXER_COMPONENT_CONFLICTS, TLS_FIXER_COMPONENT_BROWSER, TLS_FIXER_COMPONENT_SYSTEM,
        TLS_FIXER_COMPONENT_CERTIFICATES, TLS_FIXER_COMPONENT_COORDINATOR};
    for (unsigned i = 0; i < sizeof(order) / sizeof(order[0]); ++i) {
        if (!(plan->components & order[i])) continue;
        int result = action(context, order[i], plan->removing);
        if (result < 0) return result;
    }
    return 0;
}
