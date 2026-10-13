#include "ui.h"
#include "font.h"
#include <stdio.h>
#include <string.h>
#define RGB(r, g, b) (0xff000000u | ((unsigned)(b) << 16) | ((unsigned)(g) << 8) | (r))
static const uint32_t bg = RGB(16, 20, 27), panel = RGB(27, 34, 45), white = RGB(239, 244, 251),
                      muted = RGB(162, 177, 196), green = RGB(72, 211, 151),
                      red = RGB(255, 115, 125), blue = RGB(111, 186, 255),
                      amber = RGB(242, 198, 116);
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
    } else
        text(p, x, y - 7, s == CHECK_RUNNING ? ">" : s == CHECK_INFO ? "?" : "-", c, 24);
}
void check_draw(uint32_t *p, const CheckService *s, int id, int page, unsigned scroll, int busy,
                const char *notice) {
    char line[256];
    rect(p, 0, 0, 960, 544, bg);
    text(p, 28, 17, "TLS Check", white, 32);
    text(p, 30, 58, "Vita network diagnostics", muted, 17);
    card(p, 594, 27, 187, 42, id == 0 ? RGB(32, 66, 98) : panel);
    text(p, 615, 34, "BrowserLeaks", id == 0 ? blue : muted, 20);
    card(p, 791, 27, 141, 42, id == 1 ? RGB(32, 66, 98) : panel);
    text(p, 820, 34, "SSL Labs", id == 1 ? blue : muted, 20);
    for (unsigned col = 0; col < 4; ++col) {
        unsigned v = 3 - col;
        int left = 28 + (int)col * 232;
        const CheckResult *r = &s->protocols[v];
        card(p, left, 97, 208, 101, panel);
        snprintf(line, sizeof(line), "TLS 1.%u", v);
        text(p, left + 16, 109, line, white, 24);
        mark(p, left + 170, 119, r->state);
        const char *label = r->state == CHECK_PASS      ? "Connected"
                            : r->state == CHECK_FAIL    ? "Failed"
                            : r->state == CHECK_RUNNING ? "Checking..."
                            : r->state == CHECK_INFO    ? "Not tested"
                                                        : "Waiting";
        text(p, left + 16, 151, label, tone(r->state), 20);
        if (v < 2) {
            text(p, left + 139, 156, "legacy", muted, 16);
        } else if (r->state == CHECK_PASS) {
            snprintf(line, sizeof(line), "%u ms", r->elapsed_ms);
            check_font_draw(p, left + 131, 157, line, 15, muted, left + 195);
        }
    }
    text(p, 28, 213, "CONNECTION", muted, 15);
    if (s->connection.state == CHECK_PASS && id == 0) {
        text(p, 28, 236, s->handshake.cipher.name, white, 23);
        snprintf(line, sizeof(line), "%s   /   %s   /   0x%04X", s->handshake.version.name,
                 s->handshake.group.name[0] ? s->handshake.group.name : "Key exchange not reported",
                 s->handshake.cipher.id);
        text(p, 28, 269, line, muted, 18);
    } else if (s->connection.state == CHECK_PASS) {
        text(p, 28, 236, "Offered cipher suites received", white, 23);
        text(p, 28, 269, "SSL Labs does not report the negotiated cipher here.", muted, 18);
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
            snprintf(line, sizeof(line), "%u offered  /  Up-Down to scroll",
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
            snprintf(line, sizeof(line), "%04X", c->id);
            text(p, 65, y, line, muted, 16);
            text(p, 122, y - 1, c->name, white, 18);
        }
        if (!s->handshake.cipher_count) {
            text(p, 28, 365, "No cipher report received.", muted, 20);
            text(p, 28, 398, "Square opens the request errors and handshake details.", muted, 17);
        }
    } else if (page == 1) {
        text(p, 28, 318, "Request details", white, 23);
        text(p, 608, 326, "Request / SSL", muted, 16);
        text(p, 878, 326, "Time", muted, 16);
        for (unsigned i = 0; i < 4; ++i) {
            const CheckResult *r = &s->protocols[3 - i];
            int y = 357 + (int)i * 36;
            snprintf(line, sizeof(line), "TLS 1.%u", 3 - i);
            text(p, 30, y, line, white, 18);
            check_font_draw(p, 150, y, r->message[0] ? r->message : "Waiting", 18, tone(r->state),
                            590);
            if (r->error || r->ssl_error)
                snprintf(line, sizeof(line), "%08X / %08X", (unsigned)r->error,
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
        text(p, 28, 490, "Failures may involve the network, certificates or TLS negotiation.",
             muted, 14);
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
         busy ? "Triangle  Cancel     L/R  Source     Square  Details     Circle  Exit"
              : "Cross  Retry     L/R  Source     Square  Details     Circle  Exit",
         white, 16);
}
