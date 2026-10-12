#include "application.h"
#include "crypto_platform.h"
#include "nonce.h"
#include "platform_vita.h"
#include "probe_config.h"
#include "screen.h"
#include "trust.h"
#include <psa/crypto.h>
#include <psp2/ctrl.h>
#include <psp2/kernel/processmgr.h>
#include <psp2/kernel/threadmgr.h>
#include <stdio.h>

unsigned int _newlib_heap_size_user = 8u * 1024u * 1024u;
extern unsigned char msx[];

typedef struct ProbeRuntime {
    TlsFixerProbeScreen screen;
    TlsFixerProbeNetwork network;
    mbedtls_x509_crt ca;
    int platform_owned, psa_attempted, ca_initialized, network_attempted;
} ProbeRuntime;

static ProbeRuntime runtime;

static int fresh_nonce(void *unused, char *output) {
    (void)unused;
    return tls_fixer_probe_vita_nonce(output, TLS_FIXER_PROBE_NONCE_TEXT);
}

static int display(void *opaque, const char *text) {
    ProbeRuntime *state = opaque;
    return tls_fixer_probe_screen_text(&state->screen, msx, 128u * 8u, text);
}

static int prepare(void *opaque, const TlsFixerProbeIdentity *identity, const char **stage) {
    ProbeRuntime *state = opaque;
    *stage = "crypto_platform";
    int rc = tls_fixer_crypto_platform_init();
    if (rc != 0) return rc;
    state->platform_owned = 1;
    *stage = "psa";
    state->psa_attempted = 1;
    rc = (int)psa_crypto_init();
    if (rc != 0) return rc;
    *stage = "ca";
    mbedtls_x509_crt_init(&state->ca);
    state->ca_initialized = 1;
    rc = tls_fixer_probe_load_ca("app0:/probe-ca.pem", identity->ca_sha256, &state->ca);
    if (rc != 0) return rc;
    *stage = "network";
    state->network_attempted = 1;
    rc = tls_fixer_probe_network_init(&state->network);
    if (rc != 0) return rc;
    *stage = "network_ready";
    rc = tls_fixer_probe_network_ready(&state->network);
    if (rc == 0) *stage = "ready";
    return rc;
}

static int exchange(void *opaque, const TlsFixerProbeIdentity *identity, unsigned int version,
    const char *nonce, TlsFixerProbeResult *result) {
    ProbeRuntime *state = opaque;
    return tls_fixer_probe_run(&state->network.io, &state->ca, identity->address, identity->dns_name,
        version == 0x0304 ? identity->tls13_port : identity->tls12_port, version, nonce, result);
}

static int cleanup(void *opaque) {
    ProbeRuntime *state = opaque;
    int rc = state->network_attempted ? tls_fixer_probe_network_free(&state->network) : 0;
    if (state->ca_initialized) mbedtls_x509_crt_free(&state->ca);
    if (state->psa_attempted) mbedtls_psa_crypto_free();
    if (state->platform_owned) tls_fixer_crypto_platform_free();
    return rc;
}

static int wait_for_exit(void) {
    int released = 0;
    int rc = sceCtrlSetSamplingMode(SCE_CTRL_MODE_DIGITAL);
    if (rc < 0) return rc;
    for (unsigned int i = 0; i < 1200; ++i) {
        SceCtrlData buttons;
        rc = sceCtrlPeekBufferPositive(0, &buttons, 1);
        if (rc < 0) return rc;
        if (rc > 0) {
            if ((buttons.buttons & SCE_CTRL_CROSS) == 0) released = 1;
            else if (released) return 0;
        }
        rc = sceKernelDelayThread(50000);
        if (rc < 0) return rc;
    }
    return 0;
}

int main(void) {
    const TlsFixerProbeIdentity identity = {TLS_FIXER_PROBE_ADDRESS, TLS_FIXER_PROBE_DNS_NAME,
        TLS_FIXER_PROBE_BUILD_ID, TLS_FIXER_PROBE_CA_SHA256, TLS_FIXER_PROBE_TLS13_PORT, TLS_FIXER_PROBE_TLS12_PORT};
    const TlsFixerProbeApplicationOps ops = {&runtime, fresh_nonce, display, prepare, exchange, cleanup};
    TlsFixerProbeReportOps report_ops = tls_fixer_probe_report_vita_ops();
    TlsFixerProbeScreenOps screen_ops = tls_fixer_probe_screen_vita_ops();
    TlsFixerProbeApplicationResult result;
    int rc = tls_fixer_probe_screen_init(&runtime.screen, &screen_ops);
    if (rc != 0) { printf("PROBE display initialization error=%d\n", rc); return 1; }
    rc = tls_fixer_probe_application_run(&identity, &ops, &report_ops, &result);
    printf("PROBE local_success=%d nonce=%s build_id=%s report_error=%d display_error=%d\n",
        result.local_success, result.nonce, identity.build_id, result.report_error, result.display_error);
    int input_error = wait_for_exit();
    int screen_error = tls_fixer_probe_screen_close(&runtime.screen);
    printf("PROBE exit input_error=%d screen_cleanup_error=%d\n", input_error, screen_error);
    return rc == 0 && input_error == 0 && screen_error == 0 ? 0 : 1;
}
