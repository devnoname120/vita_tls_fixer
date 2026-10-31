#ifndef TLS_FIXER_MBED36_CONFIG_H
#define TLS_FIXER_MBED36_CONFIG_H
#include "../../../crypto/mbedtls_user_config.h"
#include <stdint.h>
#undef MBEDTLS_FS_IO
#undef MBEDTLS_PSA_ITS_FILE_C
#undef MBEDTLS_PSA_CRYPTO_STORAGE_C
#undef MBEDTLS_SELF_TEST
#undef MBEDTLS_THREADING_PTHREAD
#undef MBEDTLS_ENTROPY_NV_SEED
#define MBEDTLS_NO_PLATFORM_ENTROPY
#define MBEDTLS_ENTROPY_HARDWARE_ALT
/* PSA initialization is the measured small-stack peak. Use the supported
 * 32-bit-friendly SHA-256 accumulator and one Vita RNG-sized gather buffer;
 * keep the standard AES-256 CTR_DRBG and the kernel entropy source. */
#define MBEDTLS_ENTROPY_FORCE_SHA256
#define MBEDTLS_ENTROPY_MAX_GATHER 64
#define MBEDTLS_THREADING_C
#define MBEDTLS_THREADING_ALT
#define MBEDTLS_USE_PSA_CRYPTO
/* Avoid runtime AES table generation (600-byte ARM stack frame) and keep
 * lookup tables in shared read-only storage instead of each process's RW data. */
#define MBEDTLS_AES_ROM_TABLES
#define MBEDTLS_PLATFORM_MS_TIME_ALT
#define MBEDTLS_PLATFORM_GMTIME_R_ALT
#define MBEDTLS_PLATFORM_TIME_TYPE_MACRO int64_t
#define MBEDTLS_PLATFORM_TIME_MACRO tls_fixer_crypto_time
int64_t tls_fixer_crypto_time(int64_t *output);
#endif
