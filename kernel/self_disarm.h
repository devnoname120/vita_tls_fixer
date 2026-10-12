#ifndef TLS_FIXER_SELF_DISARM_H
#define TLS_FIXER_SELF_DISARM_H

#include <stdint.h>

#define TLS_FIXER_SELF_DISARM_MAX_CONFIG 65536
#define TLS_FIXER_REMOVABLE_KERNEL_PATH "ux0:/data/tls_fixer-one-shot/tls_fixer.skprx"
#define TLS_FIXER_REMOVABLE_KERNEL_PATH_NO_SLASH "ux0:data/tls_fixer-one-shot/tls_fixer.skprx"

typedef struct TlsFixerDisarmReport {
    const char *stage;
    int32_t native_result;
    int32_t config_index;
    uint32_t written_entries;
    uint32_t verified_configs;
    int32_t cleanup_result;
} TlsFixerDisarmReport;

int tls_fixer_self_disarm(void);
const TlsFixerDisarmReport *tls_fixer_self_disarm_report(void);

#endif
