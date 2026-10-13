#include "font.h"
#include "ui.h"
#include <stdlib.h>
#include <string.h>
#define CACHE_SIZE 384

typedef struct {
    unsigned code, size;
    int valid;
    CheckGlyph glyph;
} CachedGlyph;
static CachedGlyph *cache;
static unsigned next_slot;

int check_font_init(void) {
    int rc = check_font_backend_init();
    if (rc < 0)
        return rc;
    cache = calloc(CACHE_SIZE, sizeof(*cache));
    if (!cache) {
        check_font_backend_close();
        return -1;
    }
    return 0;
}
void check_font_close(void) {
    free(cache);
    cache = NULL;
    check_font_backend_close();
}
static const CheckGlyph *glyph(unsigned code, unsigned size) {
    if (!cache || size < 12 || size > 40)
        return NULL;
    if (code < 32 || code > 126)
        code = '?';
    for (unsigned i = 0; i < CACHE_SIZE; ++i)
        if (cache[i].valid && cache[i].code == code && cache[i].size == size)
            return &cache[i].glyph;
    CachedGlyph *c = &cache[next_slot++ % CACHE_SIZE];
    memset(c, 0, sizeof(*c));
    if (check_font_raster(code, size, &c->glyph) < 0 || c->glyph.width > CHECK_GLYPH_SIDE ||
        c->glyph.height > CHECK_GLYPH_SIDE || c->glyph.width < 0 || c->glyph.height < 0)
        return NULL;
    c->code = code;
    c->size = size;
    c->valid = 1;
    return &c->glyph;
}
int check_font_width(const char *s, unsigned size) {
    int width = 0;
    for (; *s; ++s) {
        const CheckGlyph *g = glyph((unsigned char)*s, size);
        if (g)
            width += g->advance;
    }
    return width;
}
void check_font_draw(uint32_t *p, int x, int top, const char *s, unsigned size, uint32_t color,
                     int right) {
    if (right > CHECK_WIDTH)
        right = CHECK_WIDTH;
    int baseline = top + (int)size;
    for (; *s; ++s) {
        const CheckGlyph *g = glyph((unsigned char)*s, size);
        if (!g)
            continue;
        if (x + g->advance > right)
            break;
        for (int yy = 0; yy < g->height; ++yy)
            for (int xx = 0; xx < g->width; ++xx) {
                int px = x + g->left + xx, py = baseline - g->top + yy;
                if (px < 0 || px >= right || py < 0 || py >= CHECK_HEIGHT)
                    continue;
                unsigned a = g->alpha[yy * CHECK_GLYPH_SIDE + xx];
                if (!a)
                    continue;
                uint32_t old = p[py * CHECK_WIDTH + px], result = 0xff000000;
                for (unsigned shift = 0; shift < 24; shift += 8) {
                    unsigned fg = (color >> shift) & 255, bg = (old >> shift) & 255;
                    result |= ((fg * a + bg * (255 - a) + 127) / 255) << shift;
                }
                p[py * CHECK_WIDTH + px] = result;
            }
        x += g->advance;
    }
}
