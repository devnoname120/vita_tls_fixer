#ifndef TLS_FIXER_TEST_MEMORY_TRACKER_H
#define TLS_FIXER_TEST_MEMORY_TRACKER_H

#include <stddef.h>

typedef struct TlsFixerMemoryStats {
    size_t current_bytes;
    size_t peak_bytes;
    size_t live_allocations;
    size_t peak_allocations;
    size_t total_allocations;
    int overflow;
} TlsFixerMemoryStats;

void tls_fixer_memory_tracker_reset(void);
TlsFixerMemoryStats tls_fixer_memory_tracker_snapshot(void);

#endif
