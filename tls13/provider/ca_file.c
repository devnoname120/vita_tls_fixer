#include "ca_file.h"
#include "diagnostics.h"

#include <psp2/io/fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define TLS_FIXER_MAX_CA_FILE_SIZE (4 * 1024 * 1024)

int tls_fixer_load_ca_file(mbedtls_x509_crt *chain, const char *path) {
    SceUID descriptor;
    unsigned char *data = NULL;
    int64_t file_size;
    size_t consumed = 0;
    int result = MBEDTLS_ERR_X509_FILE_IO_ERROR;

    if (chain == NULL || path == NULL || *path == '\0') return result;
    descriptor = sceIoOpen(path, SCE_O_RDONLY, 0);
    TLS_FIXER_LOG("event=ca.open path=%s fd=%08X", path, descriptor);
    if (descriptor < 0) return result;
    file_size = sceIoLseek(descriptor, 0, SCE_SEEK_END);
    TLS_FIXER_LOG("event=ca.size bytes=%lld", (long long)file_size);
    if (file_size <= 0 || file_size > TLS_FIXER_MAX_CA_FILE_SIZE ||
        sceIoLseek(descriptor, 0, SCE_SEEK_SET) < 0) goto cleanup;
    data = malloc((size_t)file_size + 1);
    if (data == NULL) {
        result = MBEDTLS_ERR_X509_ALLOC_FAILED;
        goto cleanup;
    }
    while (consumed < (size_t)file_size) {
        int count = sceIoRead(descriptor, data + consumed, (SceSize)((size_t)file_size - consumed));
        if (count <= 0 || (size_t)count > (size_t)file_size - consumed) goto cleanup;
        consumed += (size_t)count;
    }
    if (memchr(data, '\0', consumed) != NULL) goto cleanup;
    data[consumed] = '\0';
    result = mbedtls_x509_crt_parse(chain, data, consumed + 1);
    TLS_FIXER_LOG("event=ca.parse bytes=%u rc=%08X", (unsigned int)consumed, result);
    if (result == 0 && chain->raw.p == NULL) result = MBEDTLS_ERR_X509_INVALID_FORMAT;

cleanup:
    if (sceIoClose(descriptor) < 0 && result == 0) result = MBEDTLS_ERR_X509_FILE_IO_ERROR;
    free(data);
    return result;
}
