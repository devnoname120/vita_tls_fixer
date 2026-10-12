#include "screen.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static _Alignas(64) unsigned char pixels[TLS_FIXER_PROBE_SCREEN_BYTES];
static int failure, allocations, presentations, detachments, releases;
static int allocate(void *unused) { (void)unused; ++allocations; return failure == 1 ? -101 : 9; }
static int base(void *unused, int block, void **out) {
    (void)unused; assert(block == 9);
    if (failure == 2) return -102;
    *out = failure == 6 ? NULL : failure == 7 ? pixels + 1 : pixels;
    return 0;
}
static int present(void *unused, void *out) {
    (void)unused; assert(out == pixels); ++presentations;
    return failure == 3 ? -103 : 0;
}
static int detach(void *unused) { (void)unused; ++detachments; return failure == 4 ? -104 : 0; }
static int release(void *unused, int block) { (void)unused; assert(block == 9); ++releases; return failure == 5 ? -105 : 0; }

int main(void) {
    const TlsFixerProbeScreenOps ops = {NULL, allocate, base, present, detach, release};
    for (failure = 0; failure <= 7; ++failure) {
        TlsFixerProbeScreen screen = {0};
        allocations = presentations = detachments = releases = 0;
        memset(pixels, 0xa5, sizeof(pixels));
        int rc = tls_fixer_probe_screen_init(&screen, &ops);
        int init_ok = failure == 0 || failure == 4 || failure == 5;
        assert((rc == 0) == init_ok);
        assert(allocations == 1);
        if (!init_ok) {
            assert(!screen.active && screen.pixels == NULL);
            assert(releases == (failure != 1));
            assert(presentations == (failure == 3));
            assert(tls_fixer_probe_screen_close(&screen) == 0);
            continue;
        }
        assert(tls_fixer_probe_screen_init(&screen, &ops) < 0 && allocations == 1);
        unsigned char font[128 * 8] = {0};
        memset(font + 'A' * 8, 0xff, 8);
        assert(tls_fixer_probe_screen_text(&screen, font, sizeof(font), "A\nA") == 0);
        assert(((uint32_t *)pixels)[0] == UINT32_C(0xffffffff));
        assert(((uint32_t *)pixels)[16] == UINT32_C(0xff000000));
        assert(((uint32_t *)pixels)[16 * TLS_FIXER_PROBE_SCREEN_WIDTH] == UINT32_C(0xffffffff));
        for (size_t i = TLS_FIXER_PROBE_SCREEN_WIDTH * TLS_FIXER_PROBE_SCREEN_HEIGHT * 4; i < sizeof(pixels); ++i)
            assert(pixels[i] == 0xa5);
        char long_text[TLS_FIXER_PROBE_SCREEN_TEXT_LIMIT + 1];
        memset(long_text, 'A', sizeof(long_text));
        long_text[sizeof(long_text) - 1] = 0;
        assert(tls_fixer_probe_screen_text(&screen, font, sizeof(font), long_text) < 0);
        long_text[2041] = 0;
        assert(tls_fixer_probe_screen_text(&screen, font, sizeof(font), long_text) < 0);
        assert(tls_fixer_probe_screen_text(&screen, font, 8, "A") < 0);
        assert(tls_fixer_probe_screen_text(&screen, font, sizeof(font), NULL) < 0);
        rc = tls_fixer_probe_screen_close(&screen);
        assert((rc < 0) == (failure == 4 || failure == 5));
        if (failure == 4) {
            assert(screen.active && releases == 0 && screen.pixels != NULL);
            failure = 0;
            assert(tls_fixer_probe_screen_close(&screen) == 0);
            failure = 4;
        } else if (failure == 5) {
            assert(!screen.active && screen.block == 9);
            failure = 0;
            assert(tls_fixer_probe_screen_close(&screen) == 0);
            failure = 5;
        }
        assert(!screen.active && screen.pixels == NULL);
        assert(tls_fixer_probe_screen_close(&screen) == 0);
    }
    TlsFixerProbeScreen screen = {0};
    assert(tls_fixer_probe_screen_init(NULL, &ops) < 0);
    assert(tls_fixer_probe_screen_init(&screen, NULL) < 0);
    assert(tls_fixer_probe_screen_text(&screen, pixels, sizeof(pixels), "A") < 0);
    puts("probe display: checked ownership, fail-closed cleanup and bounded rendering PASS");
    return 0;
}
