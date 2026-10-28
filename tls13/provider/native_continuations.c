#include "native_continuations.h"
#include "tls_fixer/sony_abi.h"

#include <string.h>

TlsFixerNativeContinuations g_tls_fixer_native_continuations;

#if defined(__arm__)
_Static_assert(sizeof(TlsFixerNativeContinuations) == 16, "continuation assembly layout");
_Static_assert(offsetof(TlsFixerNativeContinuations, shutdown_import) == 8,
    "continuation assembly layout");
#endif

int tls_fixer_native_continuations_bind(TlsFixerNativeContinuations *out,
    const void *text, size_t size) {
    static const uint8_t map_io[] = {
        0x70, 0xb5, 0x04, 0x1c, 0x20, 0x6c, 0x0d, 0x1c, 0x10, 0xf0, 0x84, 0xe9,
    };
    static const uint8_t shutdown[] = {
        0x10, 0xb5, 0x04, 0x1c, 0x10, 0xf0, 0x2e, 0xe9,
    };
    if (out == NULL) return -1;
    memset(out, 0, sizeof(*out));
    uintptr_t base = (uintptr_t)text;
    if (text == NULL || size != TLS_FIXER_LIBHTTP_TEXT_SIZE || (base & 3u) != 0 ||
        base > UINTPTR_MAX - size) return -1;
    const uint8_t *bytes = text;
    if (memcmp(bytes + TLS_FIXER_HOOK_MAP_IO_OFFSET, map_io, sizeof(map_io)) != 0 ||
        memcmp(bytes + TLS_FIXER_HOOK_SHUTDOWN_OFFSET, shutdown, sizeof(shutdown)) != 0)
        return -1;

    /* Both displaced BLX instructions call ARM import stubs. Older taiHEN
     * relocators retain Thumb state (and miss PC alignment for map_io).
     * Our continuations replay only these prologues, then resume Sony's body. */
    out->map_io_import = base + 0x18910;
    out->map_io_resume = (base + TLS_FIXER_HOOK_MAP_IO_OFFSET + sizeof(map_io)) | 1u;
    out->shutdown_import = base + 0x189b0;
    out->shutdown_resume = (base + TLS_FIXER_HOOK_SHUTDOWN_OFFSET + sizeof(shutdown)) | 1u;
    return 0;
}
