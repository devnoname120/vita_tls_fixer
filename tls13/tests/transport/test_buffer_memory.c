#include <vita_mock.h>
#include "crypto_platform.h"
#include "memory_tracker.h"
#include <mbedtls/ssl.h>
#include <psa/crypto.h>
#include <psa/crypto_extra.h>
#include <assert.h>
#include <stdio.h>

int main(void) {
    enum { COUNT=64 };
    mbedtls_ssl_context connections[COUNT];
    mbedtls_ssl_config config;
    tls_fixer_memory_tracker_reset();
    assert(!tls_fixer_crypto_platform_init());
    assert(psa_crypto_init()==PSA_SUCCESS);
    mbedtls_ssl_config_init(&config);
    assert(!mbedtls_ssl_config_defaults(&config,MBEDTLS_SSL_IS_CLIENT,
        MBEDTLS_SSL_TRANSPORT_STREAM,MBEDTLS_SSL_PRESET_DEFAULT));
    TlsFixerMemoryStats before=tls_fixer_memory_tracker_snapshot();
    for(unsigned i=0;i<COUNT;++i) {
        mbedtls_ssl_init(&connections[i]);
        assert(!mbedtls_ssl_setup(&connections[i],&config));
    }
    TlsFixerMemoryStats active=tls_fixer_memory_tracker_snapshot();
    printf("64 TLS contexts: incremental=%zu bytes, per-context=%zu, peak=%zu\n",
        active.current_bytes-before.current_bytes,
        (active.current_bytes-before.current_bytes)/COUNT,active.peak_bytes);
#if defined(TLS_FIXER_SSL_IN_BUFFER_INITIAL_LEN)
    /* A full-sized receive allocation alone exceeds this total. */
    assert(active.current_bytes-before.current_bytes < COUNT*16384u);
#endif
    for(unsigned i=0;i<COUNT;++i)mbedtls_ssl_free(&connections[i]);
    mbedtls_ssl_config_free(&config);
    mbedtls_psa_crypto_free();
    tls_fixer_crypto_platform_free();
    TlsFixerMemoryStats after=tls_fixer_memory_tracker_snapshot();
    assert(!after.overflow && !after.current_bytes && !after.live_allocations);
}
