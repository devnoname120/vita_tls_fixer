#include "nonce.h"
#include <string.h>

int tls_fixer_probe_generate_nonce(TlsFixerProbeRandom random, void *context, char *output, size_t capacity) {
    static const char hex[] = "0123456789abcdef";
    unsigned char bytes[TLS_FIXER_PROBE_NONCE_BYTES] = {0};
    if (output != NULL && capacity != 0) output[0] = '\0';
    if (random == NULL || output == NULL || capacity < TLS_FIXER_PROBE_NONCE_TEXT) return -1;
    memset(output, 0, TLS_FIXER_PROBE_NONCE_TEXT);
    int rc = random(context, bytes, sizeof(bytes));
    if (rc != 0) {
        memset(bytes, 0, sizeof(bytes));
        return rc < 0 ? rc : -1;
    }
    for (size_t i = 0; i < sizeof(bytes); ++i) {
        output[2 * i] = hex[bytes[i] >> 4];
        output[2 * i + 1] = hex[bytes[i] & 15];
    }
    memset(bytes, 0, sizeof(bytes));
    return 0;
}
