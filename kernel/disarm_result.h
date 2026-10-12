#ifndef TLS_FIXER_DISARM_RESULT_H
#define TLS_FIXER_DISARM_RESULT_H

#include "self_disarm.h"
#include "trace_status.h"

#define TLS_FIXER_DISARM_RESULT_PATH "ur0:tai/tls_fixer-disarm-result.txt"
#define TLS_FIXER_DISARM_RESULT_SIZE 256u

int tls_fixer_write_disarm_result(int outcome, const TlsFixerDisarmReport *report);
int tls_fixer_write_trace_setup_result(int outcome);
#if TLS_FIXER_TRACE_MODULE_PATHS
int tls_fixer_write_trace_runtime_result(const TlsFixerTraceStatus *status, unsigned int monitor);
#endif

#endif
