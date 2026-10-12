#include "report.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static char disk[TLS_FIXER_PROBE_REPORT_LIMIT + 1], opened_path[96];
static size_t used;
static int directory_calls, opens, writes, syncs, closes;
static int directory_error, open_error, write_error, sync_error, close_error, partial, oversized;
static int directory(void *ctx) { (void)ctx; ++directory_calls; return directory_error; }
static int open_exclusive(void *ctx, const char *path) {
    (void)ctx; ++opens;
    assert(strlen(path) < sizeof(opened_path));
    strcpy(opened_path, path);
    return open_error ? open_error : 5;
}
static int write_data(void *ctx, int fd, const void *data, size_t size) {
    (void)ctx; assert(fd == 5 && size > 0); ++writes;
    if (write_error) return write_error;
    if (oversized) return (int)size + 1;
    if (partial && size > 7) size = 7;
    assert(size <= TLS_FIXER_PROBE_REPORT_LIMIT - used);
    memcpy(disk + used, data, size); used += size; disk[used] = 0;
    return (int)size;
}
static int sync_data(void *ctx, int fd) { (void)ctx; assert(fd == 5); ++syncs; return sync_error; }
static int close_data(void *ctx, int fd) { (void)ctx; assert(fd == 5); ++closes; return close_error; }
static const TlsFixerProbeReportOps ops = {NULL, directory, open_exclusive, write_data, sync_data, close_data};
static const char hash[] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
static const char nonce[] = "0123456789abcdef0123456789abcdef";
static TlsFixerProbeIdentity identity = {"192.168.1.249", "probe.test", hash, hash, 5443, 5444};
static void reset(void) {
    used = 0; disk[0] = 0;
    directory_calls = opens = writes = syncs = closes = 0;
    directory_error = open_error = write_error = sync_error = close_error = partial = oversized = 0;
}
static TlsFixerProbeResult result(void) {
    TlsFixerProbeResult r = {.stage="complete", .requested_version=0x0304, .elapsed_ms=123,
        .handshake_complete=1, .peer_verified=1, .exchange_complete=1};
    strcpy(r.negotiated, "TLSv1.3"); strcpy(r.cipher, "TLS1-3-AES-128-GCM-SHA256");
    return r;
}
int main(void) {
    TlsFixerProbeReport report = {0};
    TlsFixerProbeResult r = result();
    assert(tls_fixer_probe_identity_valid(&identity));
    assert(tls_fixer_probe_report_begin(&report, &ops, &identity, nonce) == 0);
    assert(opens == 1 && directory_calls == 1 && syncs == 1 && used > 0);
    assert(strcmp(opened_path, "ux0:/data/tls_fixer-probe/run-0123456789abcdef0123456789abcdef.log") == 0);
    assert(strstr(disk, "state=INCOMPLETE\n") && strstr(disk, "browser_compatibility=NOT_TESTED\n"));
    assert(strstr(disk, "server_correlation=REQUIRED\n") && strstr(disk, "deadline_policy=cooperative\n"));
    assert(tls_fixer_probe_report_begin(&report, &ops, &identity, nonce) < 0 && opens == 1);
    partial = 1;
    assert(tls_fixer_probe_report_result(&report, &r) == 0);
    assert(strstr(disk, "requested=TLSv1.3\n") && strstr(disk, "peer_verified=1\n"));
    r.requested_version = 0x0303; strcpy(r.negotiated, "TLSv1.2");
    assert(tls_fixer_probe_report_result(&report, &r) == 0);
    assert(tls_fixer_probe_report_finish(&report, 0, 0, 0, 2) == 0 && closes == 1);
    assert(strstr(disk, "attempts=2\n") && strstr(disk, "payload_complete=1\nEND\n"));
    assert(used < TLS_FIXER_PROBE_REPORT_LIMIT);
    assert(tls_fixer_probe_report_finish(&report, 0, 0, 0, 2) < 0 && closes == 1);

    int *failures[] = {&directory_error, &open_error, &write_error, &sync_error};
    for (size_t i = 0; i < sizeof(failures)/sizeof(failures[0]); ++i) {
        reset(); report = (TlsFixerProbeReport){0}; *failures[i] = -77;
        assert(tls_fixer_probe_report_begin(&report, &ops, &identity, nonce) == -77);
        assert(closes == (i >= 2));
        assert(tls_fixer_probe_report_finish(&report, 0, 0, 0, 0) < 0);
        assert(closes == (i >= 2));
    }
    for (int n = 0; n < 5; ++n) {
        reset(); report = (TlsFixerProbeReport){0}; r = result();
        assert(tls_fixer_probe_report_begin(&report, &ops, &identity, nonce) == 0);
        size_t before = used;
        if (n == 0) r.stage = "complete\nforged=1";
        if (n == 1) memset(r.cipher, 'X', sizeof(r.cipher));
        if (n == 2) report.written = TLS_FIXER_PROBE_REPORT_LIMIT - 1;
        if (n == 3) oversized = 1;
        if (n == 4) write_error = -88;
        assert(tls_fixer_probe_report_result(&report, &r) < 0);
        assert(used == before);
        assert(tls_fixer_probe_report_finish(&report, 0, 0, 0, 0) < 0 && closes == 1);
        assert(strstr(disk, "payload_complete=1") == NULL);
    }
    reset(); report = (TlsFixerProbeReport){0};
    assert(tls_fixer_probe_report_begin(&report, &ops, &identity, nonce) == 0);
    close_error = -91;
    assert(tls_fixer_probe_report_finish(&report, -42, 0, 0, 0) == -91 && closes == 1);
    reset(); report = (TlsFixerProbeReport){0};
    TlsFixerProbeIdentity bad = identity; bad.build_id = "bad";
    assert(tls_fixer_probe_report_begin(&report, &ops, &bad, nonce) < 0 && opens == 0);
    assert(tls_fixer_probe_report_begin(&report, &ops, &identity, "../invalid") < 0 && opens == 0);
    bad = identity; bad.address = "8.8.8.8";
    assert(!tls_fixer_probe_identity_valid(&bad));
    bad = identity; bad.tls12_port = bad.tls13_port;
    assert(!tls_fixer_probe_identity_valid(&bad));
    puts("probe report: exclusive identity, bounded writes, incomplete failures and checked completion PASS");
    return 0;
}
