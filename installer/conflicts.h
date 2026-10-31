#ifndef TLS_FIXER_INSTALLER_CONFLICTS_H
#define TLS_FIXER_INSTALLER_CONFLICTS_H
#include "config.h"

typedef struct {
    /* exists: 1 present, 0 missing, negative on an I/O error. Removal is
     * idempotent; directory removal is limited to the package-owned roots. */
    int (*exists)(void *context, const char *path);
    int (*remove)(void *context, const char *path, int directory);
    int (*sync)(void *context);
    void *context;
} TlsFixerConflictFiles;

/* Missing config files must be supplied as empty buffers by the read callback.
 * Configs are checked together, disarmed and synchronized before file removal.
 * No whole-config replacement or restoration of another installer's backup. */
int tls_fixer_conflicts_present(const TlsFixerConfigIo *configs, size_t count,
    const TlsFixerConflictFiles *files);
int tls_fixer_remove_conflicts(const TlsFixerConfigIo *configs, size_t count,
    const TlsFixerConflictFiles *files);
#endif
