#ifndef TLS_FIXER_TRACE_STATUS_H
#define TLS_FIXER_TRACE_STATUS_H

#include <stdint.h>

#ifndef TLS_FIXER_TRACE_MODULE_PATHS
#define TLS_FIXER_TRACE_MODULE_PATHS 0
#endif

enum {
    TLS_FIXER_TRACE_ERROR_NONE = 0,
    TLS_FIXER_TRACE_ERROR_THREAD = 1,
    TLS_FIXER_TRACE_ERROR_STACK = 2,
    TLS_FIXER_TRACE_ERROR_WRITE = 3,
    TLS_FIXER_TRACE_ERROR_SYNC = 4,
    TLS_FIXER_TRACE_ERROR_LIMIT = 5,
    TLS_FIXER_TRACE_ERROR_QUEUE = 6
};

typedef struct {
    int32_t error;
    uint32_t operation;
    uint32_t attempts;
    uint32_t loads;
} TlsFixerTraceStatus;

#define TLS_FIXER_TRACE_STATUS_MAX_UPDATES 128u

#if TLS_FIXER_TRACE_MODULE_PATHS
void tls_fixer_trace_status_snapshot(TlsFixerTraceStatus *status);
void tls_fixer_trace_status_note_load(void);
int tls_fixer_trace_status_start(void);
int tls_fixer_trace_status_stop(void);
#else
static inline void tls_fixer_trace_status_note_load(void) {}
static inline int tls_fixer_trace_status_start(void) { return 0; }
static inline int tls_fixer_trace_status_stop(void) { return 0; }
#endif

#endif
