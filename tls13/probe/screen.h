#ifndef TLS_FIXER_PROBE_SCREEN_H
#define TLS_FIXER_PROBE_SCREEN_H

#include <stddef.h>
#include <stdint.h>

#define TLS_FIXER_PROBE_SCREEN_WIDTH 960u
#define TLS_FIXER_PROBE_SCREEN_HEIGHT 544u
#define TLS_FIXER_PROBE_SCREEN_BYTES (2u * 1024u * 1024u)
#define TLS_FIXER_PROBE_SCREEN_TEXT_LIMIT 4096u

typedef struct TlsFixerProbeScreenOps {
    void *context;
    int (*allocate)(void *);
    int (*base)(void *, int, void **);
    int (*present)(void *, void *);
    int (*detach)(void *);
    int (*release)(void *, int);
} TlsFixerProbeScreenOps;

typedef struct TlsFixerProbeScreen {
    TlsFixerProbeScreenOps ops;
    uint32_t *pixels;
    int block, active, initialized;
} TlsFixerProbeScreen;

int tls_fixer_probe_screen_init(TlsFixerProbeScreen *screen, const TlsFixerProbeScreenOps *ops);
int tls_fixer_probe_screen_text(TlsFixerProbeScreen *screen, const unsigned char *font,
    size_t font_size, const char *text);
int tls_fixer_probe_screen_close(TlsFixerProbeScreen *screen);
TlsFixerProbeScreenOps tls_fixer_probe_screen_vita_ops(void);

#endif
