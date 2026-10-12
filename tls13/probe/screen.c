#include "screen.h"
#include <string.h>

int tls_fixer_probe_screen_init(TlsFixerProbeScreen *screen, const TlsFixerProbeScreenOps *ops) {
    if (screen == NULL || ops == NULL || screen->initialized || ops->allocate == NULL ||
        ops->base == NULL || ops->present == NULL || ops->detach == NULL || ops->release == NULL) return -1;
    memset(screen, 0, sizeof(*screen));
    screen->ops = *ops;
    screen->initialized = 1;
    screen->block = ops->allocate(ops->context);
    int rc = screen->block;
    if (rc < 0) goto failed;
    void *pixels = NULL;
    rc = ops->base(ops->context, screen->block, &pixels);
    if (rc < 0) goto failed;
    if (pixels == NULL || (uintptr_t)pixels % 4 != 0) { rc = -1; goto failed; }
    screen->pixels = pixels;
    for (size_t i = 0; i < TLS_FIXER_PROBE_SCREEN_WIDTH * TLS_FIXER_PROBE_SCREEN_HEIGHT; ++i)
        screen->pixels[i] = UINT32_C(0xff000000);
    screen->active = 1;
    rc = ops->present(ops->context, pixels);
    if (rc >= 0) return 0;
failed:
    (void)tls_fixer_probe_screen_close(screen);
    return rc;
}

int tls_fixer_probe_screen_text(TlsFixerProbeScreen *screen, const unsigned char *font,
    size_t font_size, const char *text) {
    if (screen == NULL || !screen->initialized || !screen->active || screen->pixels == NULL ||
        font == NULL || font_size < 128 * 8 || text == NULL) return -1;
    size_t length = 0;
    while (length < TLS_FIXER_PROBE_SCREEN_TEXT_LIMIT && text[length] != '\0') ++length;
    if (length == TLS_FIXER_PROBE_SCREEN_TEXT_LIMIT) return -1;
    size_t row = 0, column = 0;
    for (size_t i = 0; i < length; ++i) {
        if (text[i] == '\n') { column = 0; ++row; continue; }
        if (column == TLS_FIXER_PROBE_SCREEN_WIDTH / 16) { column = 0; ++row; }
        if (row >= TLS_FIXER_PROBE_SCREEN_HEIGHT / 16) return -1;
        ++column;
    }
    for (size_t i = 0; i < TLS_FIXER_PROBE_SCREEN_WIDTH * TLS_FIXER_PROBE_SCREEN_HEIGHT; ++i)
        screen->pixels[i] = UINT32_C(0xff000000);
    row = column = 0;
    for (size_t i = 0; i < length; ++i) {
        unsigned char character = (unsigned char)text[i];
        if (character == '\n') { column = 0; ++row; continue; }
        if (column == TLS_FIXER_PROBE_SCREEN_WIDTH / 16) { column = 0; ++row; }
        if (character < 32 || character > 126) character = '?';
        for (size_t y = 0; y < 8; ++y) {
            unsigned char bits = font[(size_t)character * 8 + y];
            for (size_t x = 0; x < 8; ++x) {
                if ((bits & (128u >> x)) == 0) continue;
                size_t offset = (row * 16 + y * 2) * TLS_FIXER_PROBE_SCREEN_WIDTH + column * 16 + x * 2;
                screen->pixels[offset] = screen->pixels[offset + 1] = UINT32_C(0xffffffff);
                screen->pixels[offset + TLS_FIXER_PROBE_SCREEN_WIDTH] =
                    screen->pixels[offset + TLS_FIXER_PROBE_SCREEN_WIDTH + 1] = UINT32_C(0xffffffff);
            }
        }
        ++column;
    }
    return 0;
}

int tls_fixer_probe_screen_close(TlsFixerProbeScreen *screen) {
    if (screen == NULL) return -1;
    if (!screen->initialized) return 0;
    if (screen->active) {
        int rc = screen->ops.detach(screen->ops.context);
        if (rc < 0) return rc;
        screen->active = 0;
    }
    if (screen->block >= 0) {
        int rc = screen->ops.release(screen->ops.context, screen->block);
        if (rc < 0) return rc;
        screen->block = -1;
    }
    screen->pixels = NULL;
    screen->initialized = 0;
    return 0;
}
