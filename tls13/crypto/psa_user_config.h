#ifndef TLS_FIXER_PSA_USER_CONFIG_H
#define TLS_FIXER_PSA_USER_CONFIG_H

#include <stdint.h>

#undef MBEDTLS_FS_IO
#undef MBEDTLS_PSA_ITS_FILE_C
#undef MBEDTLS_PSA_CRYPTO_STORAGE_C
#undef MBEDTLS_SELF_TEST
#undef MBEDTLS_THREADING_PTHREAD
#undef MBEDTLS_PSA_BUILTIN_GET_ENTROPY
#define MBEDTLS_THREADING_C
#define MBEDTLS_THREADING_ALT
#define MBEDTLS_PSA_DRIVER_GET_ENTROPY
#define MBEDTLS_PLATFORM_MS_TIME_ALT
#define MBEDTLS_PLATFORM_GMTIME_R_ALT
#define MBEDTLS_PLATFORM_TIME_TYPE_MACRO int64_t
#define MBEDTLS_PLATFORM_TIME_MACRO tls_fixer_crypto_time

#ifdef __cplusplus
extern "C" {
#endif
int64_t tls_fixer_crypto_time(int64_t *output);
#ifdef __cplusplus
}
#endif

#endif
