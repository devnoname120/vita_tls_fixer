#include "screen.h"
#include <string.h>
#if defined(TLS_FIXER_PROBE_SCREEN_NATIVE_TEST)
#include "screen_native_fixture.h"
#else
#include <psp2/display.h>
#include <psp2/kernel/sysmem.h>
#endif

static int display_allocate(void *unused) {
    (void)unused;
    SceKernelAllocMemBlockOpt options;
    memset(&options, 0, sizeof(options));
    options.size = sizeof(options);
    options.attr = 4;
    options.alignment = 256 * 1024;
    return sceKernelAllocMemBlock("tls_fixer probe display", SCE_KERNEL_MEMBLOCK_TYPE_USER_CDRAM_RW,
        TLS_FIXER_PROBE_SCREEN_BYTES, &options);
}

static int display_base(void *unused, int block, void **pixels) {
    (void)unused;
    return sceKernelGetMemBlockBase(block, pixels);
}

static int display_present(void *unused, void *pixels) {
    (void)unused;
    SceDisplayFrameBuf frame;
    memset(&frame, 0, sizeof(frame));
    frame.size = sizeof(frame);
    frame.base = pixels;
    frame.pitch = TLS_FIXER_PROBE_SCREEN_WIDTH;
    frame.pixelformat = SCE_DISPLAY_PIXELFORMAT_A8B8G8R8;
    frame.width = TLS_FIXER_PROBE_SCREEN_WIDTH;
    frame.height = TLS_FIXER_PROBE_SCREEN_HEIGHT;
    int rc = sceDisplaySetFrameBuf(&frame, SCE_DISPLAY_SETBUF_NEXTFRAME);
    return rc < 0 ? rc : sceDisplayWaitSetFrameBuf();
}

static int display_detach(void *unused) {
    (void)unused;
    int rc = sceDisplaySetFrameBuf(NULL, SCE_DISPLAY_SETBUF_NEXTFRAME);
    if (rc < 0) return rc;
    /* The display may still read the buffer until the queued update takes effect. */
    return sceDisplayWaitSetFrameBuf();
}

static int display_release(void *unused, int block) {
    (void)unused;
    return sceKernelFreeMemBlock(block);
}

TlsFixerProbeScreenOps tls_fixer_probe_screen_vita_ops(void) {
    TlsFixerProbeScreenOps ops = {NULL, display_allocate, display_base,
        display_present, display_detach, display_release};
    return ops;
}
