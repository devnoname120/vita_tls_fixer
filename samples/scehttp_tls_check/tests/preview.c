#include "font.h"
#include "model.h"
#include "ui.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    if (argc < 3)
        return 2;
    FILE *f = fopen(argv[1], "rb");
    assert(f);
    char *body = calloc(1, CHECK_BODY_MAX + 1);
    size_t n = fread(body, 1, CHECK_BODY_MAX, f);
    fclose(f);
    CheckService *s = calloc(1, sizeof(*s));
    assert(s);
    assert(check_parse_browserleaks(body, n, &s->handshake) == 0);
    free(body);
    s->connection.state = CHECK_PASS;
    s->tls_fixer_enabled = argc > 5 ? atoi(argv[5]) : 1;
    for (int i = 0; i < 4; ++i) {
        s->protocols[i].state = i < 2 && !(argc > 4 && !strcmp(argv[4], "insecure"))
                                    ? CHECK_FAIL : CHECK_PASS;
        int connected = s->protocols[i].state == CHECK_PASS;
        s->protocols[i].http_code = connected ? 200 : 0;
        s->protocols[i].elapsed_ms = 173 + i * 20;
        s->protocols[i].error = connected ? 0 : (int)0x80431075;
        snprintf(s->protocols[i].message, sizeof(s->protocols[i].message), "%s",
                 connected ? "Connected to version-specific endpoint" : "TLS handshake failed");
    }
    uint32_t *allocation = malloc((CHECK_WIDTH * CHECK_HEIGHT + 2) * sizeof(uint32_t));
    assert(allocation);
    allocation[0] = allocation[CHECK_WIDTH * CHECK_HEIGHT + 1] = 0xabcdef01;
    assert(check_font_init() == 0);
    check_draw(allocation + 1, s, argc > 3 ? atoi(argv[3]) : 0, 0, 0,
               "HOST UI FIXTURE - these are not Vita test results");
    for (int y = 53; y < 89; ++y)
        for (int x = 24; x < 570; ++x)
            allocation[1 + y * CHECK_WIDTH + x] = 0xff1b1410;
    check_font_draw(allocation + 1, 28, 58, "Layout preview / simulated results", 16, 0xffc4b1a2,
                    570);
    assert(allocation[0] == 0xabcdef01 && allocation[CHECK_WIDTH * CHECK_HEIGHT + 1] == 0xabcdef01);
    f = fopen(argv[2], "wb");
    assert(f);
    fprintf(f, "P6\n960 544\n255\n");
    for (int i = 0; i < CHECK_WIDTH * CHECK_HEIGHT; ++i) {
        uint32_t c = allocation[i + 1];
        unsigned char rgb[3] = {(unsigned char)c, (unsigned char)(c >> 8),
                                (unsigned char)(c >> 16)};
        assert(fwrite(rgb, 1, 3, f) == 3);
    }
    fclose(f);
    check_font_close();
    free(allocation);
    free(s);
    return 0;
}
