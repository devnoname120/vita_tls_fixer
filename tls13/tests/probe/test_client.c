#define _POSIX_C_SOURCE 200809L
#include "core.h"
#include "crypto_platform.h"
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <psa/crypto.h>
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

typedef struct { int fd, error, starts, closes, partial, timeout, wait_calls, fail_close, clock_case, clock_calls;
    int late_close; uint64_t initial_time; } Network;
static int start(void *opaque, const char *ip, unsigned int port) {
    Network *net = opaque;
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port)};
    assert(net->fd == -1 && inet_pton(AF_INET, ip, &address.sin_addr) == 1);
    ++net->starts;
    net->fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(net->fd >= 0 && fcntl(net->fd, F_SETFL, O_NONBLOCK) == 0);
    if (connect(net->fd, (struct sockaddr *)&address, sizeof(address)) == 0) return 0;
    net->error = errno;
    return errno == EINPROGRESS ? MBEDTLS_ERR_SSL_WANT_WRITE : MBEDTLS_ERR_NET_CONNECT_FAILED;
}
static int finish(void *opaque) {
    Network *net = opaque;
    int error = 0;
    socklen_t size = sizeof(error);
    if (getsockopt(net->fd, SOL_SOCKET, SO_ERROR, &error, &size) != 0) error = errno;
    if (error) net->error = error;
    return error ? MBEDTLS_ERR_NET_CONNECT_FAILED : 0;
}
static int wait_io(void *opaque, int want, unsigned int milliseconds) {
    Network *net = opaque;
    struct pollfd fd = {.fd = net->fd, .events = want == MBEDTLS_ERR_SSL_WANT_READ ? POLLIN : POLLOUT};
    assert(milliseconds > 0 && milliseconds <= TLS_FIXER_PROBE_DEADLINE_MS);
    ++net->wait_calls;
    if (net->timeout) return MBEDTLS_ERR_SSL_TIMEOUT;
    int rc = poll(&fd, 1, (int)milliseconds);
    if (rc < 0) net->error = errno;
    return rc > 0 ? 0 : rc == 0 ? MBEDTLS_ERR_SSL_TIMEOUT : MBEDTLS_ERR_NET_POLL_FAILED;
}
static int send_bytes(void *opaque, const unsigned char *data, size_t size) {
    Network *net = opaque;
    if (net->partial && size > 7) size = 7;
    ssize_t count = send(net->fd, data, size, 0);
    if (count >= 0) return (int)count;
    net->error = errno;
    return errno == EAGAIN || errno == EINTR ? MBEDTLS_ERR_SSL_WANT_WRITE : MBEDTLS_ERR_NET_SEND_FAILED;
}
static int recv_bytes(void *opaque, unsigned char *data, size_t size) {
    Network *net = opaque;
    if (net->partial && size > 13) size = 13;
    ssize_t count = recv(net->fd, data, size, 0);
    if (count >= 0) return (int)count;
    net->error = errno;
    return errno == EAGAIN || errno == EINTR ? MBEDTLS_ERR_SSL_WANT_READ : MBEDTLS_ERR_NET_RECV_FAILED;
}
static int close_socket(void *opaque) {
    Network *net = opaque;
    ++net->closes;
    int rc = net->fd >= 0 ? close(net->fd) : 0;
    net->fd = -1;
    return net->fail_close ? -77 : rc;
}
static int native_error(void *opaque) { return ((Network *)opaque)->error; }
static uint64_t now_ms(void *opaque) {
    struct timespec ts;
    Network *network = opaque;
    assert(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
    if (network->clock_case) {
        if (network->clock_calls++ == 0) return 100000;
        return network->clock_case == 1 ? 99999 : 115000;
    }
    uint64_t value = (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
    if (network->initial_time == 0) network->initial_time = value;
    if (network->late_close && network->closes) return network->initial_time + TLS_FIXER_PROBE_DEADLINE_MS;
    return value;
}

int main(int argc, char **argv) {
    assert(argc == 6);
    const char *scenario = argv[4], *nonce = argv[5];
    Network network = {.fd = -1, .partial = strcmp(scenario, "partial") == 0,
        .timeout = strcmp(scenario, "timeout") == 0, .fail_close = strcmp(scenario, "close-fail") == 0};
    if (strcmp(scenario, "clock-rewind") == 0) network.clock_case = 1;
    if (strcmp(scenario, "clock-expired") == 0) network.clock_case = 2;
    if (strcmp(scenario, "late-close") == 0) network.late_close = 1;
    TlsFixerProbeIo io = {&network, start, finish, wait_io, send_bytes, recv_bytes, close_socket, native_error, now_ms};
    TlsFixerProbeResult result;
    mbedtls_x509_crt ca;
    assert(tls_fixer_crypto_platform_init() == 0 && psa_crypto_init() == PSA_SUCCESS);
    mbedtls_x509_crt_init(&ca);
    FILE *file = fopen(argv[1], "rb");
    assert(file != NULL);
    unsigned char pem[8192];
    size_t size = fread(pem, 1, sizeof(pem) - 1, file);
    assert(size > 0 && size < sizeof(pem) - 1 && !ferror(file) && fclose(file) == 0);
    pem[size] = 0;
    assert(mbedtls_x509_crt_parse(&ca, pem, size + 1) == 0);
    unsigned int version = strcmp(argv[3], "1.3") == 0 ? MBEDTLS_SSL_VERSION_TLS1_3 : MBEDTLS_SSL_VERSION_TLS1_2;
    int rc = tls_fixer_probe_run(&io, &ca, "127.0.0.1", strcmp(scenario, "wrong-host") == 0 ? "wrong.invalid" : "localhost",
        (unsigned int)strtoul(argv[2], NULL, 10), version, nonce, &result);
    int success = strcmp(scenario, "valid") == 0 || strcmp(scenario, "partial") == 0;
    if ((rc == 0) != success)
        fprintf(stderr, "unexpected result scenario=%s rc=%d stage=%s version=%s verify=%08x native=%d\n",
            scenario, rc, result.stage, result.negotiated, result.verify_flags, result.native_error);
    assert((rc == 0) == success);
    assert(network.starts == !network.clock_case && network.closes == !network.clock_case && network.fd == -1);
    if (network.clock_case)
        assert(result.error == (network.clock_case == 1 ? TLS_FIXER_PROBE_CLOCK : MBEDTLS_ERR_SSL_TIMEOUT));
    if (success) {
        assert(result.handshake_complete && result.peer_verified && result.exchange_complete);
        assert(result.verify_flags == 0 && result.error == 0 && result.cleanup_error == 0);
        assert(strcmp(result.negotiated, version == MBEDTLS_SSL_VERSION_TLS1_3 ? "TLSv1.3" : "TLSv1.2") == 0);
    }
    if (strcmp(scenario, "wrong-host") == 0 || strcmp(scenario, "untrusted") == 0)
        assert(!result.peer_verified && !result.exchange_complete && result.verify_flags != 0);
    if (strcmp(scenario, "timeout") == 0) assert(result.error == MBEDTLS_ERR_SSL_TIMEOUT && network.wait_calls > 0);
    if (strcmp(scenario, "eof") == 0 || strcmp(scenario, "bad-echo") == 0 || strcmp(scenario, "oversize") == 0)
        assert(result.handshake_complete && result.peer_verified && !result.exchange_complete);
    if (strcmp(scenario, "close-fail") == 0)
        assert(result.handshake_complete && result.peer_verified && result.exchange_complete && result.cleanup_error == -77);
    if (strcmp(scenario, "ticket-limit") == 0)
        assert(result.handshake_complete && result.peer_verified && !result.exchange_complete);
    if (network.late_close)
        assert(result.handshake_complete && result.peer_verified && result.exchange_complete &&
            result.cleanup_error == 0 && result.error == MBEDTLS_ERR_SSL_TIMEOUT);
    printf("%s TLS=%s negotiated=%s stage=%s error=%d verify=%08x exchange=%d cleanup=%d\n",
        scenario, argv[3], result.negotiated, result.stage, result.error, result.verify_flags,
        result.exchange_complete, result.cleanup_error);
    mbedtls_x509_crt_free(&ca);
    mbedtls_psa_crypto_free();
    tls_fixer_crypto_platform_free();
    return 0;
}
