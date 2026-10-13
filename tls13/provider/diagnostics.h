#ifndef TLS_FIXER_DIAGNOSTICS_H
#define TLS_FIXER_DIAGNOSTICS_H

#ifndef TLS_FIXER_ENABLE_DEBUG_LOG
#define TLS_FIXER_ENABLE_DEBUG_LOG 0
#endif

#if TLS_FIXER_ENABLE_DEBUG_LOG
#if defined(TLS_FIXER_FILE_LOG) || defined(TLS_FIXER_BROWSER_FILE_LOG)
#include "trace.h"
#define TLS_FIXER_LOG(format, ...) tls_fixer_trace(format, ##__VA_ARGS__)
#else
#include <psp2/kernel/clib.h>
#define TLS_FIXER_LOG(format, ...) \
    sceClibPrintf("tls_fixer: " format "\n", ##__VA_ARGS__)
#endif
#else
#define TLS_FIXER_LOG(format, ...) ((void)0)
#endif

#endif
