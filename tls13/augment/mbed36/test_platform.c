#include <vita_mock.h>
#include "crypto_platform.h"
#include <mbedtls/entropy.h>
#include "platform.h"
#include <mbedtls/platform_util.h>
#include <mbedtls/threading.h>
#include <psa/crypto.h>
#include <psa/crypto_extra.h>
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static mbedtls_threading_mutex_t mutex;
static int predicate;
static void *worker(void *unused) {
    (void)unused;
    assert(mbedtls_mutex_lock(&mutex) == 0);
    predicate = 1;
    assert(mbedtls_mutex_unlock(&mutex) == 0);
    return NULL;
}
int main(void) {
    unsigned char random[200];
    size_t written = 999;
    int64_t seconds = INT64_C(1709164800);
    struct tm date;
    pthread_t thread;
    assert(mbedtls_hardware_poll(NULL, random, sizeof(random), &written) == 0);
    assert(written == sizeof(random) && mock_entropy_calls == 4 && mock_entropy_max_request == 64);
    mock_entropy_calls = 0; mock_entropy_fail_after = 1;
    memset(random, 0xab, sizeof(random));
    assert(mbedtls_hardware_poll(NULL, random, sizeof(random), &written) == MBEDTLS_ERR_ENTROPY_SOURCE_FAILED);
    assert(written == 0);
    for (size_t i = 0; i < sizeof(random); ++i) assert(random[i] == 0);
    mock_entropy_fail_after = -1;
    mock_clock_failure = 1;
    assert(tls_fixer_crypto_platform_init() != 0);
    mock_clock_failure = 0;
    assert(tls_fixer_crypto_platform_init() == 0 && psa_crypto_init() == PSA_SUCCESS);
    assert(psa_generate_random(random, sizeof(random)) == PSA_SUCCESS);
    assert(mbedtls_platform_gmtime_r(&seconds, &date) == &date);
    assert(date.tm_year == 124 && date.tm_mon == 1 && date.tm_mday == 29 && date.tm_yday == 59);
    assert(tls_fixer_crypto_time(NULL) >= (int64_t)time(NULL) - 2);
    mbedtls_mutex_init(&mutex);
    assert(mbedtls_mutex_lock(&mutex) == 0);
    assert(pthread_create(&thread, NULL, worker, NULL) == 0);
    assert(mbedtls_mutex_unlock(&mutex) == 0);
    assert(pthread_join(thread, NULL) == 0 && predicate == 1);
    mbedtls_mutex_free(&mutex);
    assert(mbedtls_mutex_lock(&mutex) != 0);
    mbedtls_psa_crypto_free(); tls_fixer_crypto_platform_free();
    puts("Mbed3 platform: entropy bounds/failure, PSA, UTC, mutex PASS");
    return 0;
}
