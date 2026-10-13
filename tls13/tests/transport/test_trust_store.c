#define _POSIX_C_SOURCE 200809L
#include <vita_mock.h>
#include "provider.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

TlsFixerProviderGlobal g_tls_fixer_http;

static void require_clean(void) {
    assert(!g_tls_fixer_http.ca_chain_initialized);
    assert(!g_tls_fixer_http.crypto_initialized);
}

int main(int argc, char **argv) {
    char temporary[] = "/tmp/tls_fixer-ca-XXXXXX";
    int descriptor;
    size_t count = 0;
    assert(argc == 2);
    mock_ca_file = argv[1];
    mock_ca_namespace_error = 1;
    assert(tls_fixer_trust_store_init() != 0);
    require_clean();
    mock_ca_namespace_error = 0;
    mock_ca_namespace_unterminated = 1;
    assert(tls_fixer_trust_store_init() != 0);
    require_clean();
    mock_ca_namespace_unterminated = 0;
    assert(tls_fixer_trust_store_init() == 0);
    for (const mbedtls_x509_crt *certificate = &g_tls_fixer_http.ca_chain;
         certificate != NULL; certificate = certificate->next) {
        if (certificate->raw.p != NULL) ++count;
    }
    assert(count != 0);
    tls_fixer_trust_store_free();
    require_clean();

    mock_entropy_calls = 0;
    mock_entropy_fail_after = 0;
    assert(tls_fixer_trust_store_init() != 0);
    require_clean();
    mock_entropy_fail_after = -1;
    mock_clock_failure = 1;
    assert(tls_fixer_trust_store_init() != 0);
    require_clean();
    mock_clock_failure = 0;

    descriptor = mkstemp(temporary);
    assert(descriptor >= 0);
    mock_ca_file = temporary;
    assert(tls_fixer_trust_store_init() != 0);
    require_clean();
    assert(write(descriptor, "malformed", 9) == 9);
    assert(tls_fixer_trust_store_init() != 0);
    require_clean();
    assert(ftruncate(descriptor, 0) == 0 && lseek(descriptor, 0, SEEK_SET) == 0);
    assert(write(descriptor, "malformed\0certificate", 21) == 21);
    assert(tls_fixer_trust_store_init() != 0);
    require_clean();
    assert(ftruncate(descriptor, 4 * 1024 * 1024 + 1) == 0);
    assert(tls_fixer_trust_store_init() != 0);
    require_clean();
    close(descriptor);
    unlink(temporary);
    assert(tls_fixer_trust_store_init() != 0);
    require_clean();

    mock_ca_file = argv[1];
    assert(tls_fixer_trust_store_init() == 0);
    tls_fixer_trust_store_free();
    require_clean();
    printf("trust store: %zu roots; entropy/RTC/empty/NUL/oversize/missing failures and reinit PASS\n", count);
    return 0;
}
