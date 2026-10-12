#ifndef TLS_FIXER_HOOK_GUARD_H
#define TLS_FIXER_HOOK_GUARD_H

#include <stddef.h>
#include <psp2kern/types.h>

#define TLS_FIXER_MODULEMGR_LOAD_OFFSET ((size_t)0x21ec)
#define TLS_FIXER_MODULEMGR_START_OFFSET ((size_t)0x286c)

int tls_fixer_validate_loader_hook(SceUID module_id);

#endif
