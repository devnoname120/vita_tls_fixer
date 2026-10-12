#include "nonce.h"
#if defined(TLS_FIXER_PROBE_NONCE_NATIVE_TEST)
typedef unsigned int SceSize;
int sceKernelGetRandomNumber(void *output, SceSize size);
#else
#include <psp2/kernel/rng.h>
#endif

static int native_random(void *unused, unsigned char *output, size_t size) {
    (void)unused;
    if (size != TLS_FIXER_PROBE_NONCE_BYTES) return -1;
    return sceKernelGetRandomNumber(output, (SceSize)size);
}

int tls_fixer_probe_vita_nonce(char *output, size_t capacity) {
    return tls_fixer_probe_generate_nonce(native_random, NULL, output, capacity);
}
