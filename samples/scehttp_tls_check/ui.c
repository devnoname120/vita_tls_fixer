#include "ui.h"
#include "font.h"
#include <stdio.h>
#include <string.h>
#define RGB(r, g, b) (0xff000000u | ((unsigned)(b) << 16) | ((unsigned)(g) << 8) | (r))
static const uint32_t bg = RGB(16, 20, 27), panel = RGB(27, 34, 45), white = RGB(239, 244, 251),
                      muted = RGB(162, 177, 196), green = RGB(72, 211, 151),
                      red = RGB(255, 115, 125), blue = RGB(111, 186, 255),
                      amber = RGB(242, 198, 116), orange = RGB(255, 173, 80);
static void rect(uint32_t *p, int x, int y, int w, int h, uint32_t c) {
    for (int yy = y; yy < y + h && yy < CHECK_HEIGHT; ++yy)
        for (int xx = x; xx < x + w && xx < CHECK_WIDTH; ++xx)
            if (xx >= 0 && yy >= 0)
                p[yy * CHECK_WIDTH + xx] = c;
}
static void card(uint32_t *p, int x, int y, int w, int h, uint32_t c) {
    const int radius = 10;
    rect(p, x + radius, y, w - 2 * radius, h, c);
    rect(p, x, y + radius, w, h - 2 * radius, c);
    for (int dy = 0; dy < radius; ++dy)
        for (int dx = 0; dx < radius; ++dx)
            if ((radius - dx) * (radius - dx) + (radius - dy) * (radius - dy) <= radius * radius) {
                rect(p, x + dx, y + dy, 1, 1, c);
                rect(p, x + w - 1 - dx, y + dy, 1, 1, c);
                rect(p, x + dx, y + h - 1 - dy, 1, 1, c);
                rect(p, x + w - 1 - dx, y + h - 1 - dy, 1, 1, c);
            }
}
static void text(uint32_t *p, int x, int y, const char *s, uint32_t c, unsigned size) {
    check_font_draw(p, x, y, s, size, c, 932);
}
static uint32_t tone(enum CheckState s) {
    return s == CHECK_PASS      ? green
           : s == CHECK_FAIL    ? red
           : s == CHECK_RUNNING ? blue
           : s == CHECK_WARNING ? orange
           : s == CHECK_INFO    ? amber
                                : muted;
}
static void mark(uint32_t *p, int x, int y, enum CheckState s) {
    uint32_t c = tone(s);
    if (s == CHECK_PASS) {
        for (int i = 0; i < 6; ++i)
            rect(p, x + i, y + 8 + i, 3, 3, c);
        for (int i = 0; i < 13; ++i)
            rect(p, x + 5 + i, y + 13 - i, 3, 3, c);
    } else if (s == CHECK_FAIL) {
        for (int i = 0; i < 15; ++i) {
            rect(p, x + i, y + i, 3, 3, c);
            rect(p, x + 14 - i, y + i, 3, 3, c);
        }
    } else if (s == CHECK_WARNING) {
        rect(p, x + 7, y, 4, 11, c);
        rect(p, x + 7, y + 14, 4, 4, c);
    } else
        text(p, x, y - 7, s == CHECK_RUNNING ? ">" : s == CHECK_INFO ? "?" : "-", c, 24);
}
void check_draw(uint32_t *p, const CheckService *s, int page, unsigned scroll, int busy,
                const char *notice) {
    char line[256];
    rect(p, 0, 0, 960, 544, bg);
    text(p, 28, 17, "TLS Check", white, 32);
    text(p, 30, 58, "BrowserLeaks / sceHttp", muted, 17);
    const char *provider_status = s->tls_fixer_enabled < 0 ? "checking..."
                                 : s->tls_fixer_enabled ? "enabled" : "not enabled";
    enum CheckState provider_style = s->tls_fixer_enabled < 0 ? CHECK_WAIT
                                    : s->tls_fixer_enabled ? CHECK_PASS : CHECK_FAIL;
    int label_width = check_font_width("tls_fix:", 20);
    int status_width = check_font_width(provider_status, 20);
    int status_box_width = 36 + label_width + 14 + 18 + 12 + status_width;
    int status_left = 932 - status_box_width;
    int icon_left = status_left + 18 + label_width + 14;
    card(p, status_left, 27, status_box_width, 42, panel);
    text(p, status_left + 18, 34, "tls_fix:", muted, 20);
    mark(p, icon_left, 39, provider_style);
    text(p, icon_left + 30, 34, provider_status, tone(provider_style), 20);
    for (unsigned col = 0; col < 4; ++col) {
        unsigned v = 3 - col;
        int left = 28 + (int)col * 232;
        const CheckResult *r = &s->protocols[v];
        card(p, left, 97, 208, 101, panel);
        snprintf(line, sizeof(line), "TLS 1.%u", v);
        text(p, left + 16, 109, line, white, 24);
        CheckProtocolDisplay display = check_protocol_display(v, r->state);
        mark(p, left + 170, 119, display.style);
        text(p, left + 16, 151, display.label, tone(display.style), 20);
        if (display.qualifier) {
            int x = left + 192 - check_font_width(display.qualifier, 16);
            text(p, x, 156, display.qualifier, muted, 16);
        }
    }
    text(p, 28, 213, "CONNECTION", muted, 15);
    if (s->connection.state == CHECK_PASS) {
        text(p, 28, 236, s->handshake.cipher.name, white, 23);
        snprintf(line, sizeof(line), "%s   /   %s   /   0x%04X", s->handshake.version.name,
                 s->handshake.group.name[0] ? s->handshake.group.name : "Key exchange not reported",
                 s->handshake.cipher.id);
        text(p, 28, 269, line, muted, 18);
    } else {
        const char *msg = s->connection.state == CHECK_RUNNING ? "Reading connection details..."
                          : s->connection.message[0]           ? s->connection.message
                                                               : "Ready to test";
        if (!s->started && notice && notice[0])
            msg = notice;
        text(p, 28, 236, msg, s->connection.state == CHECK_FAIL ? red : white, 23);
        if (s->connection.state == CHECK_FAIL) {
            snprintf(line, sizeof(line), "HTTP %d   /   Request 0x%08X   /   SSL 0x%08X",
                     s->connection.http_code, (unsigned)s->connection.error,
                     (unsigned)s->connection.ssl_error);
            text(p, 28, 269, line, muted, 17);
        } else
            text(p, 28, 269, "Certificate verification enabled. Each check uses a new connection.",
                 muted, 17);
    }
    rect(p, 28, 306, 904, 1, panel);
    if (page == 0) {
        text(p, 28, 318, "Cipher suites", white, 23);
        if (s->handshake.cipher_count)
            snprintf(line, sizeof(line), "%u offered / Hold arrows or stick",
                     s->handshake.cipher_count);
        else
            snprintf(line, sizeof(line), "Report unavailable");
        text(p, 621, 326, line, muted, 16);
        for (unsigned i = 0; i < CHECK_VISIBLE_CIPHERS && scroll + i < s->handshake.cipher_count;
             ++i) {
            const CheckNamed *c = &s->handshake.ciphers[scroll + i];
            int y = 356 + (int)i * 29;
            snprintf(line, sizeof(line), "%02u", scroll + i + 1);
            text(p, 30, y, line, muted, 16);
            snprintf(line, sizeof(line), "0x%04X", c->id);
            text(p, 65, y, line, muted, 16);
            text(p, 138, y - 1, c->name, white, 18);
        }
        if (!s->handshake.cipher_count) {
            text(p, 28, 365, "No cipher report received.", muted, 20);
            text(p, 28, 398, "Square opens the request errors and handshake details.", muted, 17);
        }
    } else if (page == 1) {
        text(p, 28, 318, "Request details", white, 23);
        text(p, 608, 326, "Request / SSL error", muted, 16);
        text(p, 878, 326, "Time", muted, 16);
        for (unsigned i = 0; i < 4; ++i) {
            const CheckResult *r = &s->protocols[3 - i];
            int y = 357 + (int)i * 36;
            snprintf(line, sizeof(line), "TLS 1.%u", 3 - i);
            text(p, 30, y, line, white, 18);
            CheckProtocolDisplay display = check_protocol_display(3 - i, r->state);
            check_protocol_detail(3 - i, r, line, sizeof(line));
            check_font_draw(p, 150, y, line, 18, tone(display.detail_style),
                            590);
            if (r->error || r->ssl_error)
                snprintf(line, sizeof(line), "0x%08X / 0x%08X", (unsigned)r->error,
                         (unsigned)r->ssl_error);
            else
                snprintf(line, sizeof(line), "%s", r->state == CHECK_PASS ? "OK" : "-");
            text(p, 608, y + 2, line, muted, 16);
            if (r->elapsed_ms)
                snprintf(line, sizeof(line), "%u ms", r->elapsed_ms);
            else
                snprintf(line, sizeof(line), "-");
            text(p, 856, y + 2, line, muted, 16);
        }
    } else {
        text(p, 28, 318, "Handshake details", white, 23);
        snprintf(line, sizeof(line), "Signature   %s",
                 s->handshake.signature.name[0] ? s->handshake.signature.name : "Not reported");
        text(p, 28, 358, line, white, 18);
        snprintf(line, sizeof(line), "ALPN offered   %s",
                 s->handshake.alpn[0] ? s->handshake.alpn : "Not reported");
        text(p, 28, 386, line, white, 18);
        snprintf(line, sizeof(line), "JA3   %s",
                 s->handshake.ja3[0] ? s->handshake.ja3 : "Not reported");
        text(p, 28, 414, line, muted, 17);
        snprintf(line, sizeof(line), "JA4   %s",
                 s->handshake.ja4[0] ? s->handshake.ja4 : "Not reported");
        text(p, 28, 442, line, muted, 17);
        if (s->handshake.valid)
            snprintf(line, sizeof(line),
                     "%u offered groups   /   %u extensions   /   Full lists saved in the report",
                     s->handshake.group_count, s->handshake.extension_count);
        else
            snprintf(line, sizeof(line), "No handshake report received.");
        text(p, 28, 470, line, muted, 16);
    }
    rect(p, 0, 509, 960, 35, panel);
    text(p, 28, 516,
         busy ? "Triangle  Cancel     Hold arrows / stick  Scroll     Square  Details     Circle  Exit"
              : "Cross  Retry     Hold arrows / stick  Scroll     Square  Details     Circle  Exit",
         white, 16);
}
