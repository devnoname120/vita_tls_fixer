#include <vita_mock.h>
#include "crypto_platform.h"
#include <mbedtls/platform.h>
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
static mbedtls_threading_condition_variable_t condition;
static int predicate;

static void *signal_worker(void *unused) {
    (void)unused;
    assert(mbedtls_mutex_lock(&mutex) == 0);
    predicate = 1;
    assert(mbedtls_condition_variable_signal(&condition) == 0);
    assert(mbedtls_mutex_unlock(&mutex) == 0);
    return NULL;
}

int main(void) {
    unsigned char random[200];
    size_t bits = 999;
    int64_t seconds = INT64_C(1709164800);
    struct tm date;
    pthread_t worker;

    assert(mbedtls_platform_get_entropy(0, &bits, random, sizeof(random)) == 0);
    assert(bits == sizeof(random) * 8);
    assert(mock_entropy_calls == 4 && mock_entropy_max_request == 64);
    mock_entropy_calls = 0;
    mock_entropy_fail_after = 1;
    memset(random, 0xab, sizeof(random));
    assert(mbedtls_platform_get_entropy(0, &bits, random, sizeof(random)) == PSA_ERROR_INSUFFICIENT_ENTROPY);
    assert(bits == 0);
    for (size_t i = 0; i < sizeof(random); ++i) assert(random[i] == 0);
    mock_entropy_fail_after = -1;

    mock_clock_failure = 1;
    assert(tls_fixer_crypto_platform_init() != 0);
    mock_clock_failure = 0;
    assert(tls_fixer_crypto_platform_init() == 0);
    assert(psa_crypto_init() == PSA_SUCCESS);
    assert(psa_generate_random(random, sizeof(random)) == PSA_SUCCESS);
    assert(mbedtls_platform_gmtime_r(&seconds, &date) == &date);
    assert(date.tm_year == 124 && date.tm_mon == 1 && date.tm_mday == 29 && date.tm_yday == 59);
    assert(tls_fixer_crypto_time(NULL) >= (int64_t)time(NULL) - 2);

    mbedtls_mutex_init(&mutex);
    assert(mbedtls_condition_variable_init(&condition) == 0);
    assert(mbedtls_condition_variable_signal(&condition) == 0);
    assert(mbedtls_mutex_lock(&mutex) == 0);
    assert(pthread_create(&worker, NULL, signal_worker, NULL) == 0);
    while (!predicate) assert(mbedtls_condition_variable_wait(&condition, &mutex) == 0);
    assert(mbedtls_mutex_unlock(&mutex) == 0);
    assert(pthread_join(worker, NULL) == 0);
    mbedtls_condition_variable_free(&condition);
    mbedtls_mutex_free(&mutex);
    mbedtls_psa_crypto_free();
    tls_fixer_crypto_platform_free();
    puts("crypto platform: entropy bounds/failure, PSA, UTC, mutex/condition PASS");
    return 0;
}
