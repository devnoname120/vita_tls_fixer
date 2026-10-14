#ifndef VITA_TLS_CHECK_UI_H
#define VITA_TLS_CHECK_UI_H
#include "model.h"
#define CHECK_WIDTH 960
#define CHECK_HEIGHT 544
#define CHECK_VISIBLE_CIPHERS 5
void check_draw(uint32_t *pixels, const CheckService *service, int page,
                unsigned scroll, int busy, const char *notice);
#endif
