#include "font.h"
#include <ft2build.h>
#include FT_FREETYPE_H
#include <stdlib.h>
#include <string.h>
static FT_Library library;
static FT_Face face;
int check_font_backend_init(void) {
    const char *path = getenv("TLS_CHECK_PREVIEW_FONT");
    if (!path)
        path = "/System/Library/Fonts/Supplemental/Arial.ttf";
    if (FT_Init_FreeType(&library) || FT_New_Face(library, path, 0, &face))
        return -1;
    return 0;
}
void check_font_backend_close(void) {
    if (face)
        FT_Done_Face(face);
    face = NULL;
    if (library)
        FT_Done_FreeType(library);
    library = NULL;
}
int check_font_raster(unsigned code, unsigned size, CheckGlyph *g) {
    memset(g, 0, sizeof(*g));
    if (FT_Set_Pixel_Sizes(face, 0, size) || FT_Load_Char(face, code, FT_LOAD_RENDER))
        return -1;
    FT_GlyphSlot s = face->glyph;
    if (s->bitmap.width > CHECK_GLYPH_SIDE || s->bitmap.rows > CHECK_GLYPH_SIDE)
        return -1;
    g->width = (int)s->bitmap.width;
    g->height = (int)s->bitmap.rows;
    g->left = s->bitmap_left;
    g->top = s->bitmap_top;
    g->advance = (int)((s->advance.x + 32) >> 6);
    for (int y = 0; y < g->height; ++y)
        memcpy(g->alpha + y * CHECK_GLYPH_SIDE, s->bitmap.buffer + y * s->bitmap.pitch,
               (size_t)g->width);
    return 0;
}
