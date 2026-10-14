#ifndef TLS_FIXER_MAPPING_PROBE_H
#define TLS_FIXER_MAPPING_PROBE_H
#include <stdint.h>
#ifndef TLS_FIXER_MAPPING_PROBE
#define TLS_FIXER_MAPPING_PROBE 0
#endif
#if TLS_FIXER_MAPPING_PROBE
void tls_fixer_mapping_probe_record(const char *stage, int32_t pid, const void *address);
#else
static inline void tls_fixer_mapping_probe_record(const char *stage, int32_t pid, const void *address) {
    (void)stage; (void)pid; (void)address;
}
#endif
#endif
