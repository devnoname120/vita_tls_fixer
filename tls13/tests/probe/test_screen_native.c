#include "screen.h"
#include "screen_native_fixture.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static int failure, allocated, released, submitted, blanked, waited;
static _Alignas(64) unsigned char framebuffer[TLS_FIXER_PROBE_SCREEN_BYTES];

int sceKernelAllocMemBlock(const char *name, int type, unsigned int size, SceKernelAllocMemBlockOpt *options) {
    assert(strcmp(name, "tls_fixer probe display") == 0);
    assert(type == SCE_KERNEL_MEMBLOCK_TYPE_USER_CDRAM_RW && size == sizeof(framebuffer));
    assert(options != NULL && options->size == sizeof(*options) && options->attr == 4);
    assert(options->alignment == 256 * 1024);
    ++allocated;
    return failure == 1 ? -101 : 17;
}
int sceKernelGetMemBlockBase(int block, void **base) {
    assert(block == 17);
    *base = framebuffer;
    return failure == 2 ? -102 : 0;
}
int sceKernelFreeMemBlock(int block) { assert(block == 17); ++released; return failure == 6 ? -106 : 0; }
int sceDisplaySetFrameBuf(const SceDisplayFrameBuf *frame, int timing) {
    assert(timing == SCE_DISPLAY_SETBUF_NEXTFRAME);
    if (frame == NULL) { ++blanked; return failure == 5 ? -105 : 0; }
    assert(frame->size == sizeof(*frame) && frame->base == framebuffer);
    assert(frame->width == TLS_FIXER_PROBE_SCREEN_WIDTH && frame->height == TLS_FIXER_PROBE_SCREEN_HEIGHT);
    assert(frame->pitch == TLS_FIXER_PROBE_SCREEN_WIDTH && frame->pixelformat == SCE_DISPLAY_PIXELFORMAT_A8B8G8R8);
    ++submitted;
    return failure == 3 ? -103 : 0;
}
int sceDisplayWaitSetFrameBuf(void) { ++waited; return failure == 4 ? -104 : 0; }

int main(void) {
    for (failure = 0; failure <= 6; ++failure) {
        TlsFixerProbeScreen screen = {0};
        TlsFixerProbeScreenOps ops = tls_fixer_probe_screen_vita_ops();
        allocated = released = submitted = blanked = waited = 0;
        int rc = tls_fixer_probe_screen_init(&screen, &ops);
        assert((rc == 0) == (failure == 0 || failure == 5 || failure == 6));
        assert(allocated == 1);
        if (failure == 1) assert(released == 0 && submitted == 0 && blanked == 0);
        if (failure == 2) assert(released == 1 && submitted == 0 && blanked == 0);
        if (failure == 3) assert(released == 1 && submitted == 1 && blanked == 1 && waited == 1);
        if (failure == 4) assert(released == 0 && screen.active && blanked == 1 && waited == 2);
        if (rc == 0) {
            int stopped = tls_fixer_probe_screen_close(&screen);
            assert((stopped == 0) == (failure == 0));
            if (failure == 5) assert(screen.active && released == 0);
            if (failure == 6) assert(!screen.active && released == 1);
        }
        int prior = failure;
        failure = 0;
        assert(tls_fixer_probe_screen_close(&screen) == 0);
        failure = prior;
    }
    puts("Vita display adapter: exact descriptors and no release before detach completion PASS");
    return 0;
}
