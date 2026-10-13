#include "provider.h"
#include "crypto_platform.h"
#include "ca_file.h"
#include "diagnostics.h"

#include <psp2/io/fcntl.h>
#include <psp2/types.h>
#include <mbedtls/x509_crt.h>
#include <psa/crypto.h>
#include <psa/crypto_extra.h>

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* VitaSDK supplies this syscall stub but the bundled header omits its prototype.
 * FW 3.60 uses a 16-byte reserved option and caps the output at 0x124 bytes. */
int _sceAppMgrConvertVs0UserDrivePath(const char *path, char *converted_path,
    SceSize capacity, const void *options);

int tls_fixer_trust_store_init(void) {
    int result;
    char converted_path[0x124] = {0};
    const char *ca_path = TLS_FIXER_DEFAULT_CA_PATH;

    if (strncmp(ca_path, "vs0:", 4) == 0) {
        const uint32_t options[4] = {0};
        result = _sceAppMgrConvertVs0UserDrivePath(ca_path, converted_path,
            sizeof(converted_path), options);
        TLS_FIXER_LOG("event=ca.namespace rc=%08X path=%.291s", result, converted_path);
        if (result < 0 || memchr(converted_path, '\0', sizeof(converted_path)) == NULL ||
            converted_path[0] == '\0') return MBEDTLS_ERR_X509_FILE_IO_ERROR;
        ca_path = converted_path;
    }

    result = tls_fixer_crypto_platform_init();
    TLS_FIXER_LOG("event=crypto.platform rc=%08X", result);
    if (result != 0) {
        return result;
    }
    g_tls_fixer_http.crypto_initialized = 1;
    result = (int)psa_crypto_init();
    TLS_FIXER_LOG("event=crypto.psa rc=%08X", result);
    if (result != PSA_SUCCESS) {
        tls_fixer_trust_store_free();
        return result;
    }

    mbedtls_x509_crt_init(&g_tls_fixer_http.ca_chain);
    g_tls_fixer_http.ca_chain_initialized = 1;
    result = tls_fixer_load_ca_file(&g_tls_fixer_http.ca_chain, ca_path);
#if TLS_FIXER_ENABLE_DEBUG_LOG
    size_t certificate_count = 0;
    for (const mbedtls_x509_crt *crt = &g_tls_fixer_http.ca_chain; crt != NULL; crt = crt->next) {
        if (crt->raw.p != NULL) ++certificate_count;
    }
    TLS_FIXER_LOG("event=trust.ready rc=%08X roots=%u path=%s", result,
        (unsigned int)certificate_count, ca_path);
#endif
    if (result != 0) {
        tls_fixer_trust_store_free();
    }
    return result;
}

void tls_fixer_trust_store_free(void) {
    if (g_tls_fixer_http.ca_chain_initialized) {
        mbedtls_x509_crt_free(&g_tls_fixer_http.ca_chain);
        g_tls_fixer_http.ca_chain_initialized = 0;
    }
    if (g_tls_fixer_http.crypto_initialized) {
        mbedtls_psa_crypto_free();
        tls_fixer_crypto_platform_free();
        g_tls_fixer_http.crypto_initialized = 0;
    }
}
