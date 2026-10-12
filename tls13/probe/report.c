#include "report.h"
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static int hex_digest(const char *text) {
    if (text == NULL) return 0;
    for (size_t i = 0; i < 64; ++i)
        if (!((text[i] >= '0' && text[i] <= '9') || (text[i] >= 'a' && text[i] <= 'f'))) return 0;
    return text[64] == '\0';
}

static int ipv4(const char *text, unsigned int octets[4]) {
    if (text == NULL) return 0;
    size_t cursor = 0;
    for (size_t part = 0; part < 4; ++part) {
        size_t begin = cursor;
        unsigned int value = 0;
        while (cursor < 15 && text[cursor] >= '0' && text[cursor] <= '9') {
            value = 10 * value + (unsigned int)(text[cursor++] - '0');
            if (value > 255 || cursor - begin > 3) return 0;
        }
        if (begin == cursor || (cursor - begin > 1 && text[begin] == '0')) return 0;
        octets[part] = value;
        if (part == 3) return text[cursor] == '\0';
        if (text[cursor] != '.') return 0;
        ++cursor;
    }
    return 0;
}

int tls_fixer_probe_identity_valid(const TlsFixerProbeIdentity *identity) {
    unsigned int octets[4], unused[4];
    return identity != NULL && ipv4(identity->address, octets) &&
        (octets[0] == 10 || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31) ||
         (octets[0] == 192 && octets[1] == 168)) &&
        tls_fixer_probe_dns_name(identity->dns_name) && !ipv4(identity->dns_name, unused) &&
        hex_digest(identity->build_id) && hex_digest(identity->ca_sha256) &&
        identity->tls13_port >= 1024 && identity->tls13_port <= 65535 &&
        identity->tls12_port >= 1024 && identity->tls12_port <= 65535 &&
        identity->tls13_port != identity->tls12_port;
}

static int fail(TlsFixerProbeReport *report, int rc) {
    if (report->error == 0) report->error = rc < 0 ? rc : TLS_FIXER_PROBE_INVALID;
    return report->error;
}

static int append(TlsFixerProbeReport *report, const char *data, size_t size) {
    if (!report->initialized || report->fd < 0 || report->error) return fail(report, TLS_FIXER_PROBE_INVALID);
    if (report->written > TLS_FIXER_PROBE_REPORT_LIMIT || size > TLS_FIXER_PROBE_REPORT_LIMIT - report->written)
        return fail(report, TLS_FIXER_PROBE_INVALID);
    size_t sent = 0;
    while (sent < size) {
        int rc = report->ops.write(report->ops.context, report->fd, data + sent, size - sent);
        if (rc <= 0 || (size_t)rc > size - sent) return fail(report, rc);
        sent += (size_t)rc;
        report->written += (size_t)rc;
    }
    int rc = report->ops.sync(report->ops.context, report->fd);
    return rc == 0 ? 0 : fail(report, rc);
}

static int close_report(TlsFixerProbeReport *report) {
    if (report->fd >= 0) {
        int rc = report->ops.close(report->ops.context, report->fd);
        report->fd = -1;
        if (rc != 0) (void)fail(report, rc);
    }
    return report->error;
}

int tls_fixer_probe_report_begin(TlsFixerProbeReport *report, const TlsFixerProbeReportOps *ops,
    const TlsFixerProbeIdentity *identity, const char *nonce) {
    char header[2048];
    if (report == NULL || report->initialized || ops == NULL || ops->directory == NULL ||
        ops->open_exclusive == NULL || ops->write == NULL || ops->sync == NULL || ops->close == NULL ||
        !tls_fixer_probe_identity_valid(identity) || !tls_fixer_probe_nonce_valid(nonce)) return TLS_FIXER_PROBE_INVALID;
    memset(report, 0, sizeof(*report));
    report->ops = *ops;
    report->fd = -1;
    report->initialized = 1;
    report->setup_stage = "not_started";
    int size = snprintf(report->path, sizeof(report->path), "ux0:/data/tls_fixer-probe/run-%s.log", nonce);
    if (size <= 0 || (size_t)size >= sizeof(report->path)) return fail(report, TLS_FIXER_PROBE_INVALID);
    int rc = ops->directory(ops->context);
    if (rc != 0) return fail(report, rc);
    report->fd = ops->open_exclusive(ops->context, report->path);
    if (report->fd < 0) return fail(report, report->fd);
    size = snprintf(header, sizeof(header),
        "TLS_FIXER-PROBE 1\nstate=INCOMPLETE\nnonce=%s\nbuild_id=%s\nca_sha256=%s\n"
        "address=%s\ndns_name=%s\ntls13_port=%u\ntls12_port=%u\n"
        "hostname_verification=required\nversion_policy=strict_independent\n"
        "deadline_ms=15000\ndeadline_policy=cooperative\n"
        "browser_compatibility=NOT_TESTED\nserver_correlation=REQUIRED\n"
        "runtime=ordinary_VitaSDK_application_not_injected_Sony_libc\n",
        nonce, identity->build_id, identity->ca_sha256, identity->address, identity->dns_name,
        identity->tls13_port, identity->tls12_port);
    if (size <= 0 || (size_t)size >= sizeof(header)) (void)fail(report, TLS_FIXER_PROBE_INVALID);
    else (void)append(report, header, (size_t)size);
    if (report->error) (void)close_report(report);
    return report->error;
}

static int token(const char *value, size_t capacity, int allow_empty) {
    if (value == NULL) return 0;
    for (size_t i = 0; i < capacity; ++i) {
        unsigned char c = (unsigned char)value[i];
        if (c == 0) return allow_empty || i != 0;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.')) return 0;
    }
    return 0;
}

int tls_fixer_probe_report_result(TlsFixerProbeReport *report, const TlsFixerProbeResult *result) {
    char text[1024];
    if (report == NULL) return TLS_FIXER_PROBE_INVALID;
    if (result == NULL || !token(result->stage, 64, 0) ||
        !token(result->negotiated, sizeof(result->negotiated), 1) ||
        !token(result->cipher, sizeof(result->cipher), 1) ||
        (result->requested_version != 0x0304 && result->requested_version != 0x0303))
        return fail(report, TLS_FIXER_PROBE_INVALID);
    int size = snprintf(text, sizeof(text),
        "\nrequested=%s\nnegotiated=%s\ncipher=%s\nstage=%s\n"
        "handshake_complete=%d\npeer_verified=%d\nexchange_complete=%d\n"
        "verify_flags=%08" PRIx32 "\nerror=%d\nnative_error=%d\ncleanup_error=%d\nelapsed_ms=%" PRIu64 "\n",
        result->requested_version == 0x0304 ? "TLSv1.3" : "TLSv1.2",
        *result->negotiated ? result->negotiated : "not_observed",
        *result->cipher ? result->cipher : "not_observed", result->stage,
        !!result->handshake_complete, !!result->peer_verified, !!result->exchange_complete,
        result->verify_flags, result->error, result->native_error, result->cleanup_error, result->elapsed_ms);
    if (size <= 0 || (size_t)size >= sizeof(text)) return fail(report, TLS_FIXER_PROBE_INVALID);
    return append(report, text, (size_t)size);
}

int tls_fixer_probe_report_finish(TlsFixerProbeReport *report, int setup_error, int cleanup_error,
    int display_error, unsigned int completed) {
    char text[384];
    if (report == NULL || !report->initialized || report->fd < 0) return TLS_FIXER_PROBE_INVALID;
    if (completed > 2 || !token(report->setup_stage, 64, 0)) (void)fail(report, TLS_FIXER_PROBE_INVALID);
    if (report->error == 0) {
        int size = snprintf(text, sizeof(text),
            "\nsetup_stage=%s\nsetup_error=%d\nnetwork_cleanup_error=%d\ndisplay_error=%d\nattempts=%u\n"
            "persistence=check_application_close_result\npayload_complete=1\nEND\n",
            report->setup_stage, setup_error, cleanup_error, display_error, completed);
        if (size <= 0 || (size_t)size >= sizeof(text)) (void)fail(report, TLS_FIXER_PROBE_INVALID);
        else (void)append(report, text, (size_t)size);
    }
    return close_report(report);
}
