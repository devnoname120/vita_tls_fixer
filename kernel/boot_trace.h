#ifndef TLS_FIXER_BOOT_TRACE_H
#define TLS_FIXER_BOOT_TRACE_H

#include <stdint.h>

#ifndef TLS_FIXER_ENABLE_BOOT_TRACE
#define TLS_FIXER_ENABLE_BOOT_TRACE 0
#endif

#ifndef TLS_FIXER_TRACE_MODULE_PATHS
#define TLS_FIXER_TRACE_MODULE_PATHS 0
#endif

#ifndef TLS_FIXER_TRACE_ACTIVATION_ONLY
#define TLS_FIXER_TRACE_ACTIVATION_ONLY 0
#endif
#if TLS_FIXER_TRACE_ACTIVATION_ONLY && (!TLS_FIXER_ENABLE_BOOT_TRACE || !TLS_FIXER_TRACE_MODULE_PATHS)
#error "Activation tracing requires the asynchronous diagnostic recorder"
#endif

#define TLS_FIXER_BOOT_TRACE_PATH "ur0:tai/tls_fixer-startup.log"
#define TLS_FIXER_BOOT_TRACE_LIMIT 512u
#define TLS_FIXER_BOOT_TRACE_RECORD_SIZE (TLS_FIXER_TRACE_MODULE_PATHS ? 512u : 192u)
#define TLS_FIXER_BOOT_TRACE_PATH_BYTES 128u

#if TLS_FIXER_ENABLE_BOOT_TRACE
int tls_fixer_boot_trace_open(void);
int tls_fixer_boot_trace_event(const char *stage, int32_t pid, int32_t object, int32_t result);
int tls_fixer_boot_trace_close(void);
#if TLS_FIXER_TRACE_MODULE_PATHS
enum { TLS_FIXER_BOOT_TRACE_QUEUE_RECORDS = 64 };
int tls_fixer_boot_trace_enable_async(void);
int tls_fixer_boot_trace_drain(void);
int tls_fixer_boot_trace_path(const char *stage, int32_t pid, int32_t object, int32_t result,
    const char *path);
#endif
#else
static inline int tls_fixer_boot_trace_open(void) { return 0; }
static inline int tls_fixer_boot_trace_event(const char *stage, int32_t pid, int32_t object, int32_t result) {
    (void)stage; (void)pid; (void)object; (void)result;
    return 0;
}
static inline int tls_fixer_boot_trace_close(void) { return 0; }
#endif

#endif
