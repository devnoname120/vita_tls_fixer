#ifndef TLS_FIXER_CODE_SNAPSHOT_H
#define TLS_FIXER_CODE_SNAPSHOT_H

#include <psp2kern/kernel/modulemgr.h>
#include <stddef.h>

int tls_fixer_code_snapshot(SceUID pid, const SceKernelModuleInfo *module,
    size_t offset, const char *stage);

#endif
