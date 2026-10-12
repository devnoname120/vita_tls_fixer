#ifndef TLS_FIXER_TRACE_H
#define TLS_FIXER_TRACE_H

#define TLS_FIXER_TRACE_LINE_LIMIT 512
#define TLS_FIXER_TRACE_RECORD_LIMIT 512

void tls_fixer_trace(const char *format, ...) __attribute__((format(printf, 1, 2)));

#endif
