#ifndef TLS_FIXER_PROBE_REPORT_H
#define TLS_FIXER_PROBE_REPORT_H

#include "core.h"

#define TLS_FIXER_PROBE_REPORT_LIMIT 16384u
#define TLS_FIXER_PROBE_REPORT_PATH_LIMIT 96u

typedef struct TlsFixerProbeIdentity {
    const char *address, *dns_name, *build_id, *ca_sha256;
    unsigned int tls13_port, tls12_port;
} TlsFixerProbeIdentity;

typedef struct TlsFixerProbeReportOps {
    void *context;
    int (*directory)(void *);
    int (*open_exclusive)(void *, const char *);
    int (*write)(void *, int, const void *, size_t);
    int (*sync)(void *, int);
    int (*close)(void *, int);
} TlsFixerProbeReportOps;

typedef struct TlsFixerProbeReport {
    TlsFixerProbeReportOps ops;
    char path[TLS_FIXER_PROBE_REPORT_PATH_LIMIT];
    const char *setup_stage;
    size_t written;
    int fd, initialized, error;
} TlsFixerProbeReport;

int tls_fixer_probe_identity_valid(const TlsFixerProbeIdentity *identity);
int tls_fixer_probe_report_begin(TlsFixerProbeReport *report, const TlsFixerProbeReportOps *ops,
    const TlsFixerProbeIdentity *identity, const char *nonce);
int tls_fixer_probe_report_result(TlsFixerProbeReport *report, const TlsFixerProbeResult *result);
int tls_fixer_probe_report_finish(TlsFixerProbeReport *report, int setup_error,
    int cleanup_error, int display_error, unsigned int completed);
TlsFixerProbeReportOps tls_fixer_probe_report_vita_ops(void);

#endif
