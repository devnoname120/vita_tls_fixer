#define _GNU_SOURCE
#include "backend.h"
#include "tls_fixer/sony_abi.h"
#include <vita_mock.h>
#ifdef TLS_FIXER_BROWSER_MEMORY_TEST
#include "memory_tracker.h"
#endif

#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

static uint64_t deadline;
static unsigned int waits, writes_waited, reads_waited;
static const void *accepted_callback, *accepted_userdata;

static int validate_default_callback(const void *callback, const void *userdata) {
    return callback == accepted_callback && userdata == accepted_userdata;
}

static int timeleft(void *easy, void *unused, int during_connect) {
    uint64_t now = sceKernelGetSystemTimeWide();
    (void)easy;
    assert(unused == NULL && during_connect == 1);
    return now >= deadline ? -1 : (int)((deadline - now + 999) / 1000);
}

static int socket_wait(int read_fd, int read_fd2, int write_fd, int timeout_ms) {
    struct pollfd fd = {.fd = read_fd >= 0 ? read_fd : write_fd,
        .events = read_fd >= 0 ? POLLIN : POLLOUT};
    int result;
    assert(read_fd2 == -1 && (read_fd < 0 || write_fd < 0));
    assert(timeout_ms >= 0 && timeout_ms <= 10000);
    __atomic_add_fetch(&waits, 1, __ATOMIC_RELAXED);
    if (read_fd >= 0) __atomic_add_fetch(&reads_waited, 1, __ATOMIC_RELEASE);
    if (write_fd >= 0) __atomic_add_fetch(&writes_waited, 1, __ATOMIC_RELAXED);
    result = poll(&fd, 1, timeout_ms);
    return result < 0 && errno == EINTR ? 0 : result;
}

static int connect_socket(unsigned short port) {
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(port)};
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    assert(inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) == 1);
    assert(connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    return fd;
}

typedef struct { void *connection; int index, result, handled; unsigned char done; } ConnectWorker;
static void *blocking_connect_worker(void *context) {
    ConnectWorker *worker = context;
    worker->result = tls_fixer_browser_connect(worker->connection, worker->index, 0,
        &worker->done, &worker->handled);
    return NULL;
}

int main(int argc, char **argv) {
    const TlsFixerBrowserOps ops = {
        .timeleft = timeleft,
        .socket_wait = socket_wait,
        .is_default_ctx_callback = validate_default_callback,
        .default_ciphers = "known browser default",
        .default_ca_path = NULL
    };
    const char query[] = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    unsigned char *arena, *connection, *easy;
    char *hostname;
    const char *scenario;
    int fd, handled, result, error;
    unsigned char done;
    size_t used = 0, sent = 0;
    unsigned char response[6000];
    unsigned int iterations = 0;
    int index, nonblocking;
    size_t ssl_offset;
#ifdef TLS_FIXER_BROWSER_MEMORY_TEST
    const int memory_case = argc == 5 && strncmp(argv[3], "memory", 6) == 0;
    TlsFixerMemoryStats memory_after_init = {0};
    TlsFixerMemoryStats memory_after_active = {0};
    TlsFixerMemoryStats memory_after_close = {0};
    TlsFixerMemoryStats memory_after_destroy = {0};
#endif

    assert(argc == 5);
    scenario = argv[3];
    mock_ca_file = argv[1];
    arena = mmap((void *)(uintptr_t)0x24000000, 65536, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    assert(arena != MAP_FAILED && (uintptr_t)arena <= UINT32_MAX);
    connection = arena;
    easy = arena + 4096;
    hostname = (char *)arena + 49152;
    strcpy(hostname, "localhost");
    if (strcmp(scenario, "wrong-host") == 0 || strcmp(scenario, "host-disabled") == 0 ||
        strcmp(scenario, "wrong-host-peer-disabled") == 0 ||
        strcmp(scenario, "default-callback-wrong-host") == 0) strcpy(hostname, "wrong.invalid");
    if (strcmp(scenario, "ipv4-host") == 0) strcpy(hostname, "127.0.0.1");
    if (strcmp(scenario, "ipv6-host") == 0) strcpy(hostname, "::1");
    index = strcmp(scenario, "second-socket") == 0 ? 1 : 0;
    nonblocking = strcmp(scenario, "blocking") != 0 && strcmp(scenario, "timeout") != 0;
    ssl_offset = TLS_FIXER_CURL_SSL_OFFSET + TLS_FIXER_CURL_SSL_STRIDE * (unsigned int)index;
    fd = connect_socket((unsigned short)strtoul(argv[2], NULL, 10));
    tls_fixer_write_u32(connection, TLS_FIXER_CURL_EASY_OFFSET, (uint32_t)(uintptr_t)easy);
    tls_fixer_write_u32(connection, TLS_FIXER_CURL_HOST_OFFSET, (uint32_t)(uintptr_t)hostname);
    tls_fixer_write_u32(connection, TLS_FIXER_CURL_SOCKET_OFFSET + 4 * (unsigned int)index, (uint32_t)fd);
    tls_fixer_write_u32(easy, TLS_FIXER_CURL_VERSION_OFFSET, 1);
    easy[TLS_FIXER_CURL_VERIFY_PEER_OFFSET] = strcmp(scenario, "peer-disabled") != 0 &&
        strcmp(scenario, "wrong-host-peer-disabled") != 0;
    easy[TLS_FIXER_CURL_VERIFY_HOST_OFFSET] = strcmp(scenario, "host-disabled") != 0;
    if (strncmp(scenario, "default-callback-", sizeof("default-callback-") - 1) == 0) {
        accepted_callback = easy + 2048;
        accepted_userdata = easy + 3072;
        tls_fixer_write_u32(easy, TLS_FIXER_CURL_CTX_CALLBACK_OFFSET,
            (uint32_t)(uintptr_t)accepted_callback);
        tls_fixer_write_u32(easy, TLS_FIXER_CURL_CTX_CALLBACK_DATA_OFFSET,
            (uint32_t)(uintptr_t)accepted_userdata);
    }
#ifdef TLS_FIXER_BROWSER_MEMORY_TEST
    if (memory_case) tls_fixer_memory_tracker_reset();
#endif
    assert(tls_fixer_browser_init(&ops) == 0);
#ifdef TLS_FIXER_BROWSER_MEMORY_TEST
    if (memory_case) {
        memory_after_init = tls_fixer_memory_tracker_snapshot();
        assert(!memory_after_init.overflow);
        assert(memory_after_init.current_bytes > 0 && memory_after_init.live_allocations > 0);
    }
#endif
    tls_fixer_browser_enable(1);
    if (strcmp(scenario, "custom-ca") == 0 || strcmp(scenario, "missing-ca") == 0 ||
        strcmp(scenario, "empty-ca") == 0) {
        char *ca = hostname + 2048;
        strcpy(ca, strcmp(scenario, "custom-ca") == 0 ? argv[1] : "/not-present/tls_fixer-test-ca.pem");
        if (strcmp(scenario, "empty-ca") == 0) ca[0] = '\0';
        tls_fixer_write_u32(easy, TLS_FIXER_CURL_CAFILE_OFFSET, (uint32_t)(uintptr_t)ca);
    }

    if (strcmp(scenario, "empty-ca") == 0) {
        done = 99;
        result = tls_fixer_browser_connect(connection, index, 1, &done, &handled);
        assert(handled && !done && result == TLS_FIXER_CURLE_SSL_CACERT_BADFILE);
        goto shutdown;
    }

    if (strcmp(scenario, "legacy-callback") == 0) {
        tls_fixer_write_u32(easy, TLS_FIXER_CURL_CTX_CALLBACK_OFFSET, 1);
        done = 0;
        assert(tls_fixer_browser_connect(connection, index, 1, &done, &handled) == 0 && !handled);
        assert(tls_fixer_browser_connection_count() == 0);
        goto cleanup;
    }
    if (strcmp(scenario, "legacy-existing") == 0) {
        tls_fixer_write_u32(connection, ssl_offset + TLS_FIXER_CURL_SSL_HANDLE_OFFSET, 1);
        done = 0;
        assert(tls_fixer_browser_connect(connection, index, 1, &done, &handled) == 0 && !handled);
        assert(tls_fixer_browser_connection_count() == 0);
        goto cleanup;
    }

    mock_send_eagain = 2;
    mock_recv_eagain = 2;
    deadline = sceKernelGetSystemTimeWide() + (strcmp(scenario, "timeout") == 0 ? 150000 : 10000000);
    if (strcmp(scenario, "cancel-handshake") == 0) {
        pthread_t thread;
        ConnectWorker worker = {.connection = connection, .index = index};
        assert(pthread_create(&thread, NULL, blocking_connect_worker, &worker) == 0);
        while (__atomic_load_n(&reads_waited, __ATOMIC_ACQUIRE) == 0) {
            assert(timeleft(easy, NULL, 1) > 0);
            usleep(1000);
        }
        assert(tls_fixer_browser_destroy() != 0);
        assert(tls_fixer_browser_close(connection, index, &handled) == 0 && handled);
        assert(pthread_join(thread, NULL) == 0);
        assert(worker.handled && !worker.done && worker.result == TLS_FIXER_CURLE_ABORTED_BY_CALLBACK);
        assert(tls_fixer_browser_connection_count() == 0);
        goto cleanup;
    }
    do {
        done = 99;
        handled = 0;
        result = tls_fixer_browser_connect(connection, index, (unsigned char)nonblocking, &done, &handled);
        assert(handled && (done == 0 || done == 1));
        if (result != 0 || done) break;
        assert(tls_fixer_read_u32(connection, ssl_offset + TLS_FIXER_CURL_SSL_CONNECTING_OFFSET) >= 1);
        assert(++iterations < 10000);
        usleep(1000);
    } while (timeleft(easy, NULL, 1) >= 0);
    if (strcmp(scenario, "timeout") == 0) {
        assert(result == TLS_FIXER_CURLE_OPERATION_TIMEDOUT && !done);
        goto shutdown;
    }
    if (strcmp(scenario, "bad-record") == 0) {
        assert(result == TLS_FIXER_CURLE_SSL_CONNECT_ERROR && !done);
        goto shutdown;
    }
    if (strcmp(scenario, "missing-ca") == 0) {
        assert(result == TLS_FIXER_CURLE_SSL_CACERT_BADFILE && !done);
        goto shutdown;
    }
    if (strcmp(scenario, "untrusted") == 0 || strcmp(scenario, "wrong-host") == 0 ||
        strcmp(scenario, "default-callback-untrusted") == 0 ||
        strcmp(scenario, "default-callback-wrong-host") == 0 ||
        strcmp(scenario, "expired") == 0 || strcmp(scenario, "wrong-host-peer-disabled") == 0) {
        assert((result == TLS_FIXER_CURLE_SSL_CACERT || result == TLS_FIXER_CURLE_PEER_FAILED_VERIFICATION) && !done);
        assert(tls_fixer_read_u32(easy, TLS_FIXER_CURL_VERIFY_RESULT_OFFSET) != 0);
        goto shutdown;
    }
    if (result != 0 || !done) {
        fprintf(stderr, "browser handshake: code=%d done=%u\n", result, done);
        abort();
    }
    assert(tls_fixer_browser_connection_count() == 1);
#ifdef TLS_FIXER_BROWSER_MEMORY_TEST
    if (memory_case) {
        memory_after_active = tls_fixer_memory_tracker_snapshot();
        assert(!memory_after_active.overflow);
        assert(memory_after_active.current_bytes > memory_after_init.current_bytes);
        assert(memory_after_active.live_allocations > memory_after_init.live_allocations);
    }
#endif
    if (index == 0) {
        int alive = tls_fixer_browser_check(connection, &handled);
        assert(handled && alive != 0);
    }
    assert(tls_fixer_browser_recv(connection, index, NULL, 0, &error) == 0 && error == 0);
    assert(tls_fixer_browser_send(connection, index, NULL, 0, &error) == 0 && error == 0);
    assert(tls_fixer_browser_recv(connection, index, NULL, 1, &error) == -1 && error == TLS_FIXER_CURLE_RECV_ERROR);
    assert(tls_fixer_browser_send(connection, index, NULL, 1, &error) == -1 && error == TLS_FIXER_CURLE_SEND_ERROR);
    assert(tls_fixer_read_u32(connection, ssl_offset + TLS_FIXER_CURL_SSL_STATE_OFFSET) == 2);
    assert(tls_fixer_read_u32(connection, ssl_offset + TLS_FIXER_CURL_SSL_HANDLE_OFFSET) == 0);
    assert(tls_fixer_read_u32(connection, ssl_offset + TLS_FIXER_CURL_SSL_CONTEXT_OFFSET) == 0);
    assert(tls_fixer_read_u32(connection, TLS_FIXER_CURL_RECV_OFFSET + 4 * (unsigned int)index) ==
        (uint32_t)(uintptr_t)tls_fixer_browser_recv);
    assert(tls_fixer_read_u32(connection, TLS_FIXER_CURL_SEND_OFFSET + 4 * (unsigned int)index) ==
        (uint32_t)(uintptr_t)tls_fixer_browser_send);
    assert(tls_fixer_browser_connect(connection, index, 1, &done, &handled) == 0 && handled && done);
    if (strcmp(scenario, "write-retry") == 0 || strcmp(scenario, "changed-write") == 0) {
        char relocated[sizeof(query)];
        strcpy(relocated, query);
        mock_send_eagain = 1;
        result = tls_fixer_browser_send(connection, index, query, sizeof(query) - 1, &error);
        assert(result == -1 && error == TLS_FIXER_CURLE_AGAIN);
        if (strcmp(scenario, "changed-write") == 0) {
            relocated[0] = 'P';
            assert(tls_fixer_browser_send(connection, index, relocated, sizeof(query) - 1, &error) == -1);
            assert(error == TLS_FIXER_CURLE_SEND_ERROR);
            goto shutdown;
        }
        result = tls_fixer_browser_send(connection, index, relocated, sizeof(query) - 1, &error);
        assert(result == (int)sizeof(query) - 1 && error == 0);
        sent = (size_t)result;
    }
    while (sent < sizeof(query) - 1) {
        result = tls_fixer_browser_send(connection, index, query + sent,
            (unsigned int)(sizeof(query) - 1 - sent), &error);
        if (result > 0) { sent += (size_t)result; continue; }
        assert(result == -1 && error == TLS_FIXER_CURLE_AGAIN);
        assert(timeleft(easy, NULL, 1) > 0);
        usleep(1000);
    }
    for (;;) {
        if (index == 0) {
            int alive = tls_fixer_browser_check(connection, &handled);
            assert(handled && alive >= -1 && alive <= 1);
        }
        result = tls_fixer_browser_recv(connection, index, response + used,
            (unsigned int)(sizeof(response) - used), &error);
        if (result > 0) {
            used += (size_t)result;
            assert(used <= 5000);
            (void)tls_fixer_browser_pending(connection, index, &handled);
            assert(handled);
            continue;
        }
        if (result == -1 && error == TLS_FIXER_CURLE_AGAIN) {
            assert(timeleft(easy, NULL, 1) > 0);
            usleep(1000);
            continue;
        }
        if (strcmp(scenario, "abrupt") == 0) assert(result == -1 && error == TLS_FIXER_CURLE_RECV_ERROR);
        else assert(result == 0 && error == 0);
        break;
    }
    assert(used == 5000);
    for (size_t i = 0; i < used; ++i) assert(response[i] == (unsigned char)(i % 251));
    assert(waits > 0 && writes_waited > 0 && reads_waited > 0);
shutdown:
    assert(tls_fixer_browser_close(connection, index, &handled) == 0 && handled);
    assert(tls_fixer_browser_connection_count() == 0);
#ifdef TLS_FIXER_BROWSER_MEMORY_TEST
    if (memory_case) {
        memory_after_close = tls_fixer_memory_tracker_snapshot();
        assert(!memory_after_close.overflow);
        assert(memory_after_close.current_bytes < memory_after_active.current_bytes);
        assert(memory_after_close.live_allocations < memory_after_active.live_allocations);
    }
#endif
    assert(tls_fixer_browser_close(connection, index, &handled) == 0);
cleanup:
    close(fd);
    assert(tls_fixer_browser_destroy() == 0);
#ifdef TLS_FIXER_BROWSER_MEMORY_TEST
    if (memory_case) {
        memory_after_destroy = tls_fixer_memory_tracker_snapshot();
        assert(!memory_after_destroy.overflow);
        assert(memory_after_destroy.current_bytes == 0);
        assert(memory_after_destroy.live_allocations == 0);
        assert(tls_fixer_browser_init(&ops) == 0);
        assert(tls_fixer_browser_destroy() == 0);
        memory_after_destroy = tls_fixer_memory_tracker_snapshot();
        assert(!memory_after_destroy.overflow);
        assert(memory_after_destroy.current_bytes == 0);
        assert(memory_after_destroy.live_allocations == 0);
        printf("browser memory: init=%zu active=%zu retained=%zu peak=%zu init_allocs=%zu active_allocs=%zu retained_allocs=%zu peak_allocs=%zu total_allocs=%zu\n",
            memory_after_init.current_bytes, memory_after_active.current_bytes,
            memory_after_close.current_bytes, memory_after_close.peak_bytes,
            memory_after_init.live_allocations, memory_after_active.live_allocations,
            memory_after_close.live_allocations, memory_after_close.peak_allocations,
            memory_after_close.total_allocations);
    }
#endif
    assert(munmap(arena, 65536) == 0);
    printf("browser backend: %s %s PASS\n", scenario, argv[4]);
    return 0;
}
