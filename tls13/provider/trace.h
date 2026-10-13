#ifndef TLS_FIXER_TRACE_H
#define TLS_FIXER_TRACE_H

#define TLS_FIXER_TRACE_LINE_LIMIT 512
#ifndef TLS_FIXER_TRACE_RECORD_LIMIT
#define TLS_FIXER_TRACE_RECORD_LIMIT 512
#endif
#ifndef TLS_FIXER_TRACE_COMPONENT
#define TLS_FIXER_TRACE_COMPONENT "browser"
#endif

void tls_fixer_trace(const char *format, ...) __attribute__((format(printf, 1, 2)));

#endif
