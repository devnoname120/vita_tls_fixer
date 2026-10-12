#define _GNU_SOURCE
#include "backend.h"
#include "ca_file.h"
#include "tls_fixer/sony_abi.h"
#include <vita_mock.h>

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

static int ca_calls;
static int ca_failure;

int __wrap_tls_fixer_load_ca_file(mbedtls_x509_crt *chain, const char *path) {
    assert(chain != NULL);
    assert(strcmp(path, "wb0:/cert/CA_LIST.cer") == 0);
    ++ca_calls;
    return ca_failure ? -0x2180 : 0;
}

static int timeleft(void *easy, void *now, int connecting) {
    (void)easy;
    (void)now;
    (void)connecting;
    return 1000;
}

static int socket_wait(int read_fd, int read_fd2, int write_fd, int timeout_ms) {
    (void)read_fd;
    (void)read_fd2;
    (void)write_fd;
    (void)timeout_ms;
    return 0;
}

int main(int argc, char **argv) {
    const TlsFixerBrowserOps ops = {
        .timeleft = timeleft,
        .socket_wait = socket_wait,
        .is_default_ctx_callback = NULL,
        .default_ciphers = "known default",
        .default_ca_path = "wb0:/cert/CA_LIST.cer"
    };
    unsigned char *arena;
    unsigned char *connection;
    unsigned char *easy;
    char *hostname;
    unsigned char done = 99;
    int handled = 99;

    assert(argc == 2);
    ca_failure = 1;
    arena = mmap((void *)(uintptr_t)0x24000000, 65536, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    assert(arena != MAP_FAILED && (uintptr_t)arena <= UINT32_MAX);
    connection = arena;
    easy = arena + 4096;
    hostname = (char *)arena + 8192;
    strcpy(hostname, "localhost");
    tls_fixer_write_u32(connection, TLS_FIXER_CURL_EASY_OFFSET, (uint32_t)(uintptr_t)easy);
    tls_fixer_write_u32(connection, TLS_FIXER_CURL_HOST_OFFSET, (uint32_t)(uintptr_t)hostname);
    tls_fixer_write_u32(connection, TLS_FIXER_CURL_SOCKET_OFFSET, 99);
    tls_fixer_write_u32(easy, TLS_FIXER_CURL_VERSION_OFFSET, 1);
    easy[TLS_FIXER_CURL_VERIFY_PEER_OFFSET] = 1;
    easy[TLS_FIXER_CURL_VERIFY_HOST_OFFSET] = 1;

    assert(tls_fixer_browser_init(&ops) == 0);
    assert(ca_calls == 0);
    tls_fixer_browser_enable(1);

    if (strcmp(argv[1], "init") == 0) {
        assert(tls_fixer_browser_destroy() == 0);
    } else if (strcmp(argv[1], "legacy") == 0) {
        tls_fixer_write_u32(easy, TLS_FIXER_CURL_CTX_CALLBACK_OFFSET, 1);
        assert(tls_fixer_browser_connect(connection, 0, 1, &done, &handled) == 0);
        assert(done == 0 && handled == 0 && ca_calls == 0);
        assert(tls_fixer_browser_destroy() == 0);
    } else if (strcmp(argv[1], "failure") == 0) {
        assert(tls_fixer_browser_connect(connection, 0, 1, &done, &handled) == 0);
        assert(done == 0 && handled == 0 && ca_calls == 1);
        done = 99;
        handled = 99;
        assert(tls_fixer_browser_connect(connection, 0, 1, &done, &handled) == 0);
        assert(done == 0 && handled == 0 && ca_calls == 1);
        assert(tls_fixer_browser_destroy() == 0);
    } else {
        abort();
    }

    assert(munmap(arena, 65536) == 0);
    printf("browser lazy default CA: %s PASS\n", argv[1]);
    return 0;
}
