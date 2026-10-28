#ifndef TLS_FIXER_NATIVE_CONTINUATIONS_H
#define TLS_FIXER_NATIVE_CONTINUATIONS_H

#include <stddef.h>
#include <stdint.h>

typedef struct TlsFixerNativeContinuations {
    uintptr_t map_io_import;
    uintptr_t map_io_resume;
    uintptr_t shutdown_import;
    uintptr_t shutdown_resume;
} TlsFixerNativeContinuations;

extern TlsFixerNativeContinuations g_tls_fixer_native_continuations;

/* Bind only the audited Sony prologues, before publishing either hook. */
int tls_fixer_native_continuations_bind(TlsFixerNativeContinuations *out,
    const void *text, size_t size);
int tls_fixer_native_map_io(void *connection, int result);
int tls_fixer_native_shutdown(void *connection);

#endif
