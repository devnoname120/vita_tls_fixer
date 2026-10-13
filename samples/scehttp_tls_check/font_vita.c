#include "font.h"
#include <psp2/pvf.h>
#include <stdlib.h>
#include <string.h>

static ScePvfLibId library;
static ScePvfFontId face;
static void *allocate(void *context, unsigned size) {
    (void)context;
    return malloc(size);
}
static void *resize(void *context, void *old, unsigned size) {
    (void)context;
    return realloc(old, size);
}
static void release(void *context, void *p) {
    (void)context;
    free(p);
}
int check_font_backend_init(void) {
    ScePvfInitRec init = {0};
    init.maxNumFonts = 1;
    init.allocFunc = allocate;
    init.reallocFunc = resize;
    init.freeFunc = release;
    ScePvfError error = 0;
    library = scePvfNewLib(&init, &error);
    if (!library || error < 0)
        return error < 0 ? error : -1;
    /* Pixel-sized Latin system glyphs, rendered by Sony's vector font engine. */
    int rc = scePvfSetEM(library, 72.0f / (10.125f * 128.0f));
    if (rc < 0)
        goto fail;
    rc = scePvfSetResolution(library, 128.0f, 128.0f);
    if (rc < 0)
        goto fail;
    ScePvfFontStyleInfo style = {0};
    style.languageCode = SCE_PVF_LANGUAGE_LATIN;
    style.familyCode = SCE_PVF_FAMILY_SANSERIF;
    style.style = SCE_PVF_STYLE_REGULAR;
    int index = scePvfFindOptimumFont(library, &style, &error);
    if (index < 0 || error < 0) {
        rc = error < 0 ? error : -1;
        goto fail;
    }
    face = scePvfOpen(library, index, SCE_PVF_FILEBASEDSTREAM, &error);
    if (!face || error < 0) {
        rc = error < 0 ? error : -1;
        goto fail;
    }
    return 0;
fail:
    check_font_backend_close();
    return rc;
}
void check_font_backend_close(void) {
    if (face)
        scePvfClose(face);
    face = NULL;
    if (library)
        scePvfDoneLib(library);
    library = NULL;
}
int check_font_raster(unsigned code, unsigned size, CheckGlyph *g) {
    memset(g, 0, sizeof(*g));
    float points = (float)size * 72.0f / 128.0f;
    int rc = scePvfSetCharSize(face, points, points);
    if (rc < 0)
        return rc;
    ScePvfCharInfo info;
    memset(&info, 0, sizeof(info));
    rc = scePvfGetCharInfo(face, (ScePvfCharCode)code, &info);
    if (rc < 0)
        return rc;
    ScePvfIrect rect = {0};
    rc = scePvfGetCharImageRect(face, (ScePvfCharCode)code, &rect);
    if (rc < 0)
        return rc;
    if (rect.width + 2 > CHECK_GLYPH_SIDE || rect.height + 2 > CHECK_GLYPH_SIDE)
        return -1;
    g->width = rect.width + 2;
    g->height = rect.height + 2;
    g->left = (info.glyphMetrics.horizontalBearingX64 >> 6) - 1;
    g->top = (info.glyphMetrics.horizontalBearingY64 >> 6) + 1;
    g->advance = (info.glyphMetrics.horizontalAdvance64 + 32) >> 6;
    ScePvfUserImageBufferRec image = {0};
    image.pixelFormat = SCE_PVF_USERIMAGE_DIRECT8;
    image.xPos64 = 64 - info.glyphMetrics.horizontalBearingX64;
    image.yPos64 = 64 + info.glyphMetrics.horizontalBearingY64;
    image.rect.width = CHECK_GLYPH_SIDE;
    image.rect.height = CHECK_GLYPH_SIDE;
    image.bytesPerLine = CHECK_GLYPH_SIDE;
    image.buffer = g->alpha;
    return scePvfGetCharGlyphImage(face, (ScePvfCharCode)code, &image);
}
