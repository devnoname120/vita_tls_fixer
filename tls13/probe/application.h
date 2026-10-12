#ifndef TLS_FIXER_PROBE_APPLICATION_H
#define TLS_FIXER_PROBE_APPLICATION_H

#include "report.h"

typedef struct TlsFixerProbeApplicationOps {
    void *context;
    int (*nonce)(void *, char *);
    int (*display)(void *, const char *);
    int (*prepare)(void *, const TlsFixerProbeIdentity *, const char **);
    int (*exchange)(void *, const TlsFixerProbeIdentity *, unsigned int, const char *, TlsFixerProbeResult *);
    int (*cleanup)(void *);
} TlsFixerProbeApplicationOps;

typedef struct TlsFixerProbeApplicationResult {
    char nonce[TLS_FIXER_PROBE_NONCE_SIZE + 1];
    char report_path[TLS_FIXER_PROBE_REPORT_PATH_LIMIT];
    const char *stage;
    TlsFixerProbeResult attempts[2];
    unsigned int attempted;
    int setup_error, cleanup_error, display_error, report_error, local_success;
} TlsFixerProbeApplicationResult;

int tls_fixer_probe_application_run(const TlsFixerProbeIdentity *identity,
    const TlsFixerProbeApplicationOps *ops, const TlsFixerProbeReportOps *report_ops,
    TlsFixerProbeApplicationResult *result);

#endif
