#include "nonce.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static int calls, outcome;
static int random_bytes(void *context, unsigned char *output, size_t size) {
    assert(context == &calls && output != NULL && size == TLS_FIXER_PROBE_NONCE_BYTES);
    ++calls;
    for (size_t i = 0; i < size; ++i) output[i] = (unsigned char)(i * 17);
    return outcome;
}

#if defined(TLS_FIXER_PROBE_NONCE_NATIVE_TEST)
int sceKernelGetRandomNumber(void *output, unsigned int size) {
    assert(size == 16);
    return random_bytes(&calls, output, size);
}
#endif

int main(void) {
    char text[TLS_FIXER_PROBE_NONCE_TEXT + 2];
    memset(text, 'X', sizeof(text));
    assert(tls_fixer_probe_generate_nonce(random_bytes, &calls, text, TLS_FIXER_PROBE_NONCE_TEXT) == 0);
    assert(calls == 1 && strcmp(text, "00112233445566778899aabbccddeeff") == 0);
    assert(text[33] == 'X' && text[34] == 'X');
    outcome = -71;
    assert(tls_fixer_probe_generate_nonce(random_bytes, &calls, text, TLS_FIXER_PROBE_NONCE_TEXT) == -71);
    assert(calls == 2);
    for (size_t i = 0; i < TLS_FIXER_PROBE_NONCE_TEXT; ++i) assert(text[i] == 0);
    outcome = 1;
    assert(tls_fixer_probe_generate_nonce(random_bytes, &calls, text, TLS_FIXER_PROBE_NONCE_TEXT) < 0 && calls == 3);
    assert(text[0] == 0 && text[33] == 'X');
    assert(tls_fixer_probe_generate_nonce(NULL, &calls, text, TLS_FIXER_PROBE_NONCE_TEXT) < 0 && calls == 3);
    assert(tls_fixer_probe_generate_nonce(random_bytes, &calls, NULL, TLS_FIXER_PROBE_NONCE_TEXT) < 0 && calls == 3);
    memset(text, 'X', sizeof(text));
    assert(tls_fixer_probe_generate_nonce(random_bytes, &calls, text, 4) < 0 && calls == 3);
    assert(text[0] == 0 && text[4] == 'X');
#if defined(TLS_FIXER_PROBE_NONCE_NATIVE_TEST)
    outcome = 0;
    calls = 0;
    assert(tls_fixer_probe_vita_nonce(text, TLS_FIXER_PROBE_NONCE_TEXT) == 0 && calls == 1);
    assert(strcmp(text, "00112233445566778899aabbccddeeff") == 0);
    outcome = -19;
    assert(tls_fixer_probe_vita_nonce(text, TLS_FIXER_PROBE_NONCE_TEXT) == -19 && calls == 2);
    for (size_t i = 0; i < TLS_FIXER_PROBE_NONCE_TEXT; ++i) assert(text[i] == 0);
#endif
    puts("probe nonce: one entropy request, exact encoding and failure without fallback PASS");
    return 0;
}
