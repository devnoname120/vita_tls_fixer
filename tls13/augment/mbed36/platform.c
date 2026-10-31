/* Experimental Mbed TLS 3.6 adapter. Upstream sources remain unchanged. */
#include "crypto_platform.h"
#include "platform.h"
#include <psp2/kernel/processmgr.h>
#include <psp2/kernel/rng.h>
#include <psp2/kernel/threadmgr/mutex.h>
#include <psp2/rtc.h>
#include <mbedtls/entropy.h>
#include <mbedtls/platform.h>
#include <mbedtls/platform_time.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/threading.h>
#include <psa/crypto.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#define TLS_FIXER_UNIX_EPOCH_TICKS UINT64_C(62135596800000000)
#define TLS_FIXER_UNIX_EPOCH_SECONDS INT64_C(62135596800)
static int g_threading_initialized;
static void mutex_init(mbedtls_threading_mutex_t *m) {
    m->uid = sceKernelCreateMutex("tls_fixer crypto", 0, 0, NULL);
}
static void mutex_free(mbedtls_threading_mutex_t *m) {
    if (m->uid >= 0) (void)sceKernelDeleteMutex(m->uid);
    m->uid = -1;
}
static int mutex_lock(mbedtls_threading_mutex_t *m) {
    return m->uid < 0 || sceKernelLockMutex(m->uid, 1, NULL) < 0 ? MBEDTLS_ERR_THREADING_MUTEX_ERROR : 0;
}
static int mutex_unlock(mbedtls_threading_mutex_t *m) {
    return m->uid < 0 || sceKernelUnlockMutex(m->uid, 1) < 0 ? MBEDTLS_ERR_THREADING_MUTEX_ERROR : 0;
}
int mbedtls_hardware_poll(void *unused, unsigned char *output, size_t length, size_t *written) {
    (void)unused;
    if (written == NULL) return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    *written = 0;
    if (output == NULL && length != 0) return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    size_t offset = 0;
    while (offset < length) {
        size_t count = length - offset;
        if (count > 64) count = 64;
        if (sceKernelGetRandomNumber(output + offset, (SceSize)count) < 0) {
            mbedtls_platform_zeroize(output, length);
            return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
        }
        offset += count;
    }
    *written = length;
    return 0;
}

int64_t tls_fixer_crypto_time(int64_t *output) {
    SceRtcTick tick;
    int64_t seconds = -1;

    if (sceRtcGetCurrentTick(&tick) >= 0 && tick.tick >= TLS_FIXER_UNIX_EPOCH_TICKS) {
        seconds = (int64_t)((tick.tick - TLS_FIXER_UNIX_EPOCH_TICKS) / UINT64_C(1000000));
    }
    if (output != NULL) {
        *output = seconds;
    }
    return seconds;
}

mbedtls_ms_time_t mbedtls_ms_time(void) {
    return (mbedtls_ms_time_t)(sceKernelGetSystemTimeWide() / UINT64_C(1000));
}

struct tm *mbedtls_platform_gmtime_r(const mbedtls_time_t *seconds, struct tm *result) {
    SceDateTime date;
    SceRtcTick tick;
    int month;
    int yday;
    int wday;

    if (seconds == NULL || result == NULL ||
        *seconds < -TLS_FIXER_UNIX_EPOCH_SECONDS || *seconds > INT64_C(253402300799)) {
        return NULL;
    }
    tick.tick = (uint64_t)(*seconds + TLS_FIXER_UNIX_EPOCH_SECONDS) * UINT64_C(1000000);
    if (sceRtcSetTick(&date, &tick) < 0) {
        return NULL;
    }
    yday = date.day - 1;
    for (month = 1; month < date.month; ++month) {
        int days = sceRtcGetDaysInMonth(date.year, month);
        if (days < 0) {
            return NULL;
        }
        yday += days;
    }
    wday = sceRtcGetDayOfWeek(date.year, date.month, date.day);
    if (wday < 0) {
        return NULL;
    }
    memset(result, 0, sizeof(*result));
    result->tm_year = date.year - 1900;
    result->tm_mon = date.month - 1;
    result->tm_mday = date.day;
    result->tm_hour = date.hour;
    result->tm_min = date.minute;
    result->tm_sec = date.second;
    result->tm_yday = yday;
    result->tm_wday = wday;
    return result;
}

int tls_fixer_crypto_platform_init(void) {
    if (g_threading_initialized || tls_fixer_crypto_time(NULL) < 0) return PSA_ERROR_BAD_STATE;
    mbedtls_threading_set_alt(mutex_init, mutex_free, mutex_lock, mutex_unlock);
    g_threading_initialized = 1;
    return 0;
}
void tls_fixer_crypto_platform_free(void) {
    if (g_threading_initialized) { mbedtls_threading_free_alt(); g_threading_initialized = 0; }
}
