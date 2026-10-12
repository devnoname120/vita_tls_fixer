#include "application.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static const char *scenario;
static char disk[16385];
static size_t disk_size;
static unsigned int displays, nonces, opened, synced, closed, prepared, exchanges, cleaned;
static int nonce(void *ctx, char *output) {
    (void)ctx; ++nonces; assert(displays > 0 && !opened && !prepared);
    if (!strcmp(scenario, "entropy")) return -91;
    strcpy(output, "0123456789abcdef0123456789abcdef"); return 0;
}
static int display(void *ctx, const char *text) {
    (void)ctx; ++displays; assert(text && strlen(text) < 2048);
    if (!strcmp(scenario, "display-first") && displays == 1) return -92;
    if (!strcmp(scenario, "display-second") && displays == 3) return -92;
    if (!strcmp(scenario, "display-last") && closed) return -92;
    return 0;
}
static int prepare(void *ctx, const TlsFixerProbeIdentity *identity, const char **stage) {
    (void)ctx; assert(identity && opened == 1 && synced && !closed && !prepared++);
    *stage = "ca";
    return !strcmp(scenario, "prepare") ? -93 : 0;
}
static int exchange(void *ctx, const TlsFixerProbeIdentity *id, unsigned int version,
    const char *n, TlsFixerProbeResult *r) {
    (void)ctx; assert(id && prepared && !cleaned && !closed && synced);
    assert(tls_fixer_probe_nonce_valid(n) && version == (exchanges ? 0x0303u : 0x0304u));
    *r = (TlsFixerProbeResult){.stage="complete", .requested_version=version,
        .handshake_complete=1, .peer_verified=1, .exchange_complete=1};
    strcpy(r->negotiated, exchanges ? "TLSv1.2" : "TLSv1.3");
    strcpy(r->cipher, "TEST-CIPHER");
    if (!strcmp(scenario, "first-failed") && !exchanges) {
        r->error = -94; r->stage = "handshake"; r->handshake_complete = r->peer_verified = r->exchange_complete = 0;
    }
    if (!strcmp(scenario, "connection-cleanup") && !exchanges) { r->cleanup_error = r->error = -95; }
    if (!strcmp(scenario, "false-success") && !exchanges) r->peer_verified = 0;
    ++exchanges;
    return r->error;
}
static int cleanup(void *ctx) { (void)ctx; assert(prepared && !cleaned++); return !strcmp(scenario, "cleanup") ? -96 : 0; }
static int directory(void *ctx) { (void)ctx; return 0; }
static int open_report(void *ctx, const char *path) {
    (void)ctx; assert(strstr(path, "ux0:/data/tls_fixer-probe/run-") == path); ++opened;
    return !strcmp(scenario, "report-open") ? -97 : 7;
}
static int write_report(void *ctx, int fd, const void *bytes, size_t size) {
    (void)ctx; assert(fd == 7 && !closed && size < sizeof(disk) - disk_size);
    if (!strcmp(scenario, "report-result") && exchanges) return -98;
    memcpy(disk + disk_size, bytes, size); disk_size += size; disk[disk_size] = 0;
    return (int)size;
}
static int sync_report(void *ctx, int fd) { (void)ctx; assert(fd == 7); ++synced; return 0; }
static int close_report(void *ctx, int fd) {
    (void)ctx; assert(fd == 7 && !closed++);
    return !strcmp(scenario, "report-close") ? -99 : 0;
}
int main(int argc, char **argv) {
    assert(argc == 2); scenario = argv[1];
    static const char hash[] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const TlsFixerProbeIdentity identity = {"192.168.1.249", "probe.test", hash, hash, 5443, 5444};
    const TlsFixerProbeApplicationOps ops = {NULL, nonce, display, prepare, exchange, cleanup};
    const TlsFixerProbeReportOps reports = {NULL, directory, open_report, write_report, sync_report, close_report};
    TlsFixerProbeApplicationResult r;
    int rc = tls_fixer_probe_application_run(&identity, &ops, &reports, &r);
    int success = !strcmp(scenario, "valid");
    assert((rc == 0) == success && !!r.local_success == success);
    assert(exchanges <= 2 && cleaned == prepared);
    if (!strcmp(scenario, "display-first")) assert(!nonces && !opened && !prepared && !exchanges);
    else if (!strcmp(scenario, "entropy")) assert(nonces == 1 && !opened && !prepared && !exchanges);
    else if (!strcmp(scenario, "report-open")) assert(opened == 1 && !prepared && !exchanges && !closed);
    else {
        assert(closed == 1 && prepared == 1 && cleaned == 1);
        if (!strcmp(scenario, "prepare")) assert(!exchanges && r.setup_error == -93 && strstr(disk, "setup_stage=ca\n"));
        else if (!strcmp(scenario, "connection-cleanup") || !strcmp(scenario, "report-result") ||
                 !strcmp(scenario, "display-second")) assert(exchanges == 1);
        else assert(exchanges == 2);
    }
    if (!strcmp(scenario, "first-failed")) assert(r.attempts[0].error == -94 && r.attempts[1].error == 0);
    if (!strcmp(scenario, "false-success")) assert(r.attempts[0].error != 0);
    if (!strcmp(scenario, "report-result")) assert(r.report_error == -98 && strstr(disk, "payload_complete=1") == NULL);
    if (!strcmp(scenario, "report-close")) assert(r.report_error == -99);
    if (!strcmp(scenario, "display-last")) assert(r.display_error == -92);
    if (success) assert(strstr(disk, "attempts=2\n") && strstr(disk, "browser_compatibility=NOT_TESTED\n"));
    printf("probe application: %s PASS\n", scenario);
    return 0;
}
