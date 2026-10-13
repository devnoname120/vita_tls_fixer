#ifndef TLS_FIXER_MEMORY_PROBE_H
#define TLS_FIXER_MEMORY_PROBE_H

#include <stdint.h>
#ifndef TLS_FIXER_MEMORY_PROBE
#define TLS_FIXER_MEMORY_PROBE 0
#endif

#if TLS_FIXER_MEMORY_PROBE
/* Snapshot output ABI, audited only for retail 3.60 SceSysmem. */
typedef struct PhysicalPartitionInfo {
    uint32_t physical_base;
    uint32_t total_bytes;
    uint32_t free_bytes;
    uint32_t internal_statistic;
} PhysicalPartitionInfo;
int tls_fixer_memory_probe_init(void);
void tls_fixer_memory_probe_record(const char *stage, int32_t pid);
#else
static inline int tls_fixer_memory_probe_init(void) { return 0; }
static inline void tls_fixer_memory_probe_record(const char *stage, int32_t pid) {
    (void)stage;
    (void)pid;
}
#endif
#endif
