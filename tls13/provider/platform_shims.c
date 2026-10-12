#include "crypto_platform.h"

#include <psp2/kernel/processmgr.h>
#include <psp2/kernel/rng.h>
#include <psp2/kernel/threadmgr/cond.h>
#include <psp2/kernel/threadmgr/mutex.h>
#include <psp2/rtc.h>

#include <mbedtls/platform.h>
#include <mbedtls/platform_time.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/threading.h>
#include <psa/crypto.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#define TLS_FIXER_UNIX_EPOCH_TICKS UINT64_C(62135596800000000)
#define TLS_FIXER_UNIX_EPOCH_SECONDS INT64_C(62135596800)
#define TLS_FIXER_RNG_MAX_REQUEST ((size_t)64)

static int g_threading_initialized;

static int platform_mutex_init(mbedtls_platform_mutex_t *mutex) {
    mutex->uid = sceKernelCreateMutex("tls_fixer crypto", 0, 0, NULL);
    return mutex->uid < 0 ? PSA_ERROR_INSUFFICIENT_MEMORY : 0;
}

static void platform_mutex_destroy(mbedtls_platform_mutex_t *mutex) {
    if (mutex->uid >= 0) {
        (void)sceKernelDeleteMutex(mutex->uid);
        mutex->uid = -1;
    }
}

static int platform_mutex_lock(mbedtls_platform_mutex_t *mutex) {
    if (mutex->uid < 0 || sceKernelLockMutex(mutex->uid, 1, NULL) < 0) {
        return MBEDTLS_ERR_THREADING_USAGE_ERROR;
    }
    return 0;
}

static int platform_mutex_unlock(mbedtls_platform_mutex_t *mutex) {
    if (mutex->uid < 0 || sceKernelUnlockMutex(mutex->uid, 1) < 0) {
        return MBEDTLS_ERR_THREADING_USAGE_ERROR;
    }
    return 0;
}

static int platform_cond_init(mbedtls_platform_condition_variable_t *condition) {
    condition->mutex_uid = -1;
    __atomic_store_n(&condition->uid, -1, __ATOMIC_RELEASE);
    return 0;
}

static void platform_cond_destroy(mbedtls_platform_condition_variable_t *condition) {
    int uid = __atomic_load_n(&condition->uid, __ATOMIC_ACQUIRE);
    if (uid >= 0) {
        (void)sceKernelDeleteCond(uid);
        __atomic_store_n(&condition->uid, -1, __ATOMIC_RELEASE);
    }
    condition->mutex_uid = -1;
}

static int platform_cond_signal(mbedtls_platform_condition_variable_t *condition) {
    int uid = __atomic_load_n(&condition->uid, __ATOMIC_ACQUIRE);
    if (uid < 0) {
        return 0;
    }
    return sceKernelSignalCond(uid) < 0 ? MBEDTLS_ERR_THREADING_USAGE_ERROR : 0;
}

static int platform_cond_broadcast(mbedtls_platform_condition_variable_t *condition) {
    int uid = __atomic_load_n(&condition->uid, __ATOMIC_ACQUIRE);
    if (uid < 0) {
        return 0;
    }
    return sceKernelSignalCondAll(uid) < 0 ? MBEDTLS_ERR_THREADING_USAGE_ERROR : 0;
}

static int platform_cond_wait(
    mbedtls_platform_condition_variable_t *condition,
    mbedtls_platform_mutex_t *mutex) {
    int uid = __atomic_load_n(&condition->uid, __ATOMIC_ACQUIRE);

    if (mutex->uid < 0) {
        return MBEDTLS_ERR_THREADING_USAGE_ERROR;
    }
    /* Vita binds a condition to its mutex at creation; the ALT init API does not supply it. */
    if (uid < 0) {
        uid = sceKernelCreateCond("tls_fixer crypto", 0, mutex->uid, NULL);
        if (uid < 0) {
            return PSA_ERROR_INSUFFICIENT_MEMORY;
        }
        condition->mutex_uid = mutex->uid;
        __atomic_store_n(&condition->uid, uid, __ATOMIC_RELEASE);
    }
    if (condition->mutex_uid != mutex->uid) {
        return MBEDTLS_ERR_THREADING_USAGE_ERROR;
    }
    return sceKernelWaitCond(uid, NULL) < 0 ? MBEDTLS_ERR_THREADING_USAGE_ERROR : 0;
}

int mbedtls_platform_get_entropy(
    psa_driver_get_entropy_flags_t flags,
    size_t *estimate_bits,
    unsigned char *output,
    size_t output_size) {
    size_t offset = 0;

    if (estimate_bits == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    *estimate_bits = 0;
    if (flags != PSA_DRIVER_GET_ENTROPY_FLAGS_NONE) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if ((output == NULL && output_size != 0) || output_size > SIZE_MAX / 8) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    while (offset < output_size) {
        size_t count = output_size - offset;
        if (count > TLS_FIXER_RNG_MAX_REQUEST) {
            count = TLS_FIXER_RNG_MAX_REQUEST;
        }
        if (sceKernelGetRandomNumber(output + offset, (SceSize)count) < 0) {
            mbedtls_platform_zeroize(output, output_size);
            return PSA_ERROR_INSUFFICIENT_ENTROPY;
        }
        offset += count;
    }
    *estimate_bits = output_size * 8;
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
    if (g_threading_initialized || tls_fixer_crypto_time(NULL) < 0) {
        return PSA_ERROR_BAD_STATE;
    }
    mbedtls_threading_set_alt(
        platform_mutex_init,
        platform_mutex_destroy,
        platform_mutex_lock,
        platform_mutex_unlock,
        platform_cond_init,
        platform_cond_destroy,
        platform_cond_signal,
        platform_cond_broadcast,
        platform_cond_wait);
    g_threading_initialized = 1;
    return 0;
}

void tls_fixer_crypto_platform_free(void) {
    if (g_threading_initialized) {
        mbedtls_threading_free_alt();
        g_threading_initialized = 0;
    }
}
