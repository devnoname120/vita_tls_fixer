#include "native_continuations.h"
#include "tls_fixer/sony_abi.h"
#include <assert.h>
#include <string.h>

static _Alignas(16) unsigned char text[TLS_FIXER_LIBHTTP_TEXT_SIZE];

int main(void) {
    const unsigned char map_io[] = {0x70,0xb5,0x04,0x1c,0x20,0x6c,0x0d,0x1c,0x10,0xf0,0x84,0xe9};
    const unsigned char shutdown[] = {0x10,0xb5,0x04,0x1c,0x10,0xf0,0x2e,0xe9};
    TlsFixerNativeContinuations targets, zero = {0};
    memcpy(text + TLS_FIXER_HOOK_MAP_IO_OFFSET, map_io, sizeof(map_io));
    memcpy(text + TLS_FIXER_HOOK_SHUTDOWN_OFFSET, shutdown, sizeof(shutdown));
    assert(tls_fixer_native_continuations_bind(&targets, text, sizeof(text)) == 0);
    assert(targets.map_io_import == (uintptr_t)text + 0x18910);
    assert(targets.map_io_resume == (((uintptr_t)text + 0x860a) | 1u));
    assert(targets.shutdown_import == (uintptr_t)text + 0x189b0);
    assert(targets.shutdown_resume == (((uintptr_t)text + 0x8754) | 1u));
    assert((targets.map_io_import & 3u) == 0 && (targets.shutdown_import & 3u) == 0);
    for (size_t i = 0; i < sizeof(map_io) + sizeof(shutdown); ++i) {
        size_t offset = i < sizeof(map_io) ? TLS_FIXER_HOOK_MAP_IO_OFFSET + i
            : TLS_FIXER_HOOK_SHUTDOWN_OFFSET + i - sizeof(map_io);
        text[offset] ^= 1;
        assert(tls_fixer_native_continuations_bind(&targets, text, sizeof(text)) < 0);
        assert(memcmp(&targets, &zero, sizeof(zero)) == 0);
        text[offset] ^= 1;
    }
    assert(tls_fixer_native_continuations_bind(NULL, text, sizeof(text)) < 0);
    assert(tls_fixer_native_continuations_bind(&targets, NULL, sizeof(text)) < 0);
    assert(tls_fixer_native_continuations_bind(&targets, text, sizeof(text) - 1) < 0);
    assert(tls_fixer_native_continuations_bind(&targets, text + 1, sizeof(text)) < 0);
    return 0;
}
