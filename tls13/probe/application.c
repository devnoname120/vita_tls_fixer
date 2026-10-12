#include "application.h"
#include <stdio.h>
#include <string.h>

static int successful(const TlsFixerProbeResult *result, unsigned int version) {
    return result->error == 0 && result->cleanup_error == 0 && result->requested_version == version &&
        result->handshake_complete && result->peer_verified && result->exchange_complete && result->verify_flags == 0 &&
        result->elapsed_ms < TLS_FIXER_PROBE_DEADLINE_MS &&
        memchr(result->negotiated, '\0', sizeof(result->negotiated)) != NULL &&
        strcmp(result->negotiated, version == 0x0304 ? "TLSv1.3" : "TLSv1.2") == 0;
}

int tls_fixer_probe_application_run(const TlsFixerProbeIdentity *identity,
    const TlsFixerProbeApplicationOps *ops, const TlsFixerProbeReportOps *report_ops,
    TlsFixerProbeApplicationResult *result) {
    TlsFixerProbeReport report = {0};
    char page[1536];
    int prepared = 0;
    if (result == NULL) return TLS_FIXER_PROBE_INVALID;
    memset(result, 0, sizeof(*result));
    result->stage = "arguments";
    if (!tls_fixer_probe_identity_valid(identity) || ops == NULL || ops->nonce == NULL || ops->display == NULL ||
        ops->prepare == NULL || ops->exchange == NULL || ops->cleanup == NULL) return TLS_FIXER_PROBE_INVALID;
    result->stage = "display";
    result->display_error = ops->display(ops->context,
        "tls_fixer standalone probe\nPreparing one TLS 1.3 and one TLS 1.2 test.\nNo browser hooks or boot changes.\n");
    if (result->display_error != 0) return TLS_FIXER_PROBE_INVALID;
    result->stage = "nonce";
    result->setup_error = ops->nonce(ops->context, result->nonce);
    if (result->setup_error != 0 || !tls_fixer_probe_nonce_valid(result->nonce)) {
        if (result->setup_error == 0) result->setup_error = TLS_FIXER_PROBE_INVALID;
        result->nonce[0] = '\0';
        goto display_result;
    }
    result->stage = "report";
    result->report_error = tls_fixer_probe_report_begin(&report, report_ops, identity, result->nonce);
    if (result->report_error != 0) goto display_result;
    memcpy(result->report_path, report.path, sizeof(result->report_path));
    result->stage = "prepare";
    prepared = 1;
    result->setup_error = ops->prepare(ops->context, identity, &result->stage);
    report.setup_stage = result->stage;
    if (result->setup_error != 0) goto cleanup;
    for (size_t i = 0; i < 2; ++i) {
        unsigned int version = i == 0 ? 0x0304u : 0x0303u;
        result->stage = i == 0 ? "tls13" : "tls12";
        result->display_error = ops->display(ops->context, i == 0 ?
            "tls_fixer standalone probe\nRunning strict TLS 1.3.\nCertificate and hostname verification required.\n" :
            "tls_fixer standalone probe\nRunning strict TLS 1.2 independently.\nThis is not a protocol fallback test.\n");
        if (result->display_error != 0) break;
        TlsFixerProbeResult *attempt = &result->attempts[i];
        int rc = ops->exchange(ops->context, identity, version, result->nonce, attempt);
        ++result->attempted;
        if (attempt->error != rc || (rc == 0 && !successful(attempt, version))) {
            attempt->stage = "result";
            attempt->error = TLS_FIXER_PROBE_INVALID;
        }
        result->report_error = tls_fixer_probe_report_result(&report, attempt);
        if (result->report_error != 0 || attempt->cleanup_error != 0) break;
    }
cleanup:
    if (prepared) result->cleanup_error = ops->cleanup(ops->context);
    int report_error = tls_fixer_probe_report_finish(&report, result->setup_error,
        result->cleanup_error, result->display_error, result->attempted);
    if (result->report_error == 0) result->report_error = report_error;
    result->local_success = result->setup_error == 0 && result->cleanup_error == 0 &&
        result->report_error == 0 && result->display_error == 0 && result->attempted == 2 &&
        successful(&result->attempts[0], 0x0304) && successful(&result->attempts[1], 0x0303);
display_result:
    int length = snprintf(page, sizeof(page),
        "tls_fixer standalone probe\n\nLocal checks: %s\n"
        "Run: %s\nBuild: %.16s\n\n"
        "TLS 1.3: handshake=%d verified=%d exchange=%d\nerror=%d cleanup=%d\n"
        "TLS 1.2: handshake=%d verified=%d exchange=%d\nerror=%d cleanup=%d\n\n"
        "Attempts=%u setup=%d cleanup=%d\nReport error=%d display error=%d\n"
        "Report: %s\n\n"
        "Match BOTH versions and nonce with the server.\nBrowser compatibility is NOT tested.\n"
        "Deadline is cooperative, not preemptive.\n\nX to exit; automatic exit after 60 seconds.\n",
        result->local_success ? "PASS - server confirmation still required" : "FAILED or INCOMPLETE",
        *result->nonce ? result->nonce : "no nonce", identity->build_id,
        result->attempts[0].handshake_complete, result->attempts[0].peer_verified, result->attempts[0].exchange_complete,
        result->attempts[0].error, result->attempts[0].cleanup_error,
        result->attempts[1].handshake_complete, result->attempts[1].peer_verified, result->attempts[1].exchange_complete,
        result->attempts[1].error, result->attempts[1].cleanup_error,
        result->attempted, result->setup_error, result->cleanup_error, result->report_error, result->display_error,
        *result->report_path ? result->report_path : "not opened");
    int display_error = length > 0 && (size_t)length < sizeof(page) ?
        ops->display(ops->context, page) : TLS_FIXER_PROBE_INVALID;
    if (display_error != 0) {
        if (result->display_error == 0) result->display_error = display_error;
        result->local_success = 0;
    }
    if (result->local_success) result->stage = "complete";
    return result->local_success ? 0 : TLS_FIXER_PROBE_INVALID;
}
