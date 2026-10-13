#ifndef TLS_CHECK_FONT_H
#define TLS_CHECK_FONT_H
#include <stdint.h>
#define CHECK_GLYPH_SIDE 64

typedef struct {
    uint8_t alpha[CHECK_GLYPH_SIDE * CHECK_GLYPH_SIDE];
    int width, height, left, top, advance;
} CheckGlyph;
int check_font_backend_init(void);
void check_font_backend_close(void);
int check_font_raster(unsigned code, unsigned size, CheckGlyph *glyph);
int check_font_init(void);
void check_font_close(void);
int check_font_width(const char *text, unsigned size);
void check_font_draw(uint32_t *pixels, int x, int top, const char *text, unsigned size,
                     uint32_t color, int right);
#endif
