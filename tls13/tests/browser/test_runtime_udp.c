#include "runtime_udp.h"
#include <vita_mock.h>

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

static _Thread_local int net_error = 23;
static _Thread_local unsigned int libc_errno_calls;
static int no_errno, socket_fail, address_fail, send_fail, reenter;
static int no_libc_errno;
static unsigned int opens, sends;
static unsigned char packets[TLS_FIXER_RUNTIME_RECORD_LIMIT][TLS_FIXER_RUNTIME_PACKET_SIZE];
static pthread_mutex_t record_lock = PTHREAD_MUTEX_INITIALIZER;

int *_sceLibcErrnoLoc(void) {
    ++libc_errno_calls;
    return no_libc_errno ? NULL : &errno;
}

static uint32_t field(const unsigned char *data) {
    return (uint32_t)data[0] << 24 | (uint32_t)data[1] << 16 |
        (uint32_t)data[2] << 8 | data[3];
}

int *sceNetErrnoLoc(void) { return no_errno ? NULL : &net_error; }
SceUID sceKernelGetProcessId(void) { return 0xabcdef; }
SceUID sceKernelGetThreadId(void) { return 0x6789; }
uint64_t sceKernelGetSystemTimeWide(void) { return UINT64_C(0x1020304050607080); }
uint16_t sceNetHtons(uint16_t value) { return (uint16_t)((value << 8) | (value >> 8)); }

int sceNetInetPton(int family, const char *text, void *output) {
    static const unsigned char address[] = {192, 168, 1, 249};
    assert(family == SCE_NET_AF_INET && strcmp(text, "192.168.1.249") == 0);
    errno = 80;
    net_error = 81;
    if (address_fail) return 0;
    memcpy(output, address, sizeof(address));
    return 1;
}

int sceNetSocket(const char *name, int family, int type, int protocol) {
    assert(strcmp(name, "tls_fixer runtime") == 0 && family == SCE_NET_AF_INET);
    assert(type == SCE_NET_SOCK_DGRAM && protocol == 0);
    ++opens;
    errno = 82;
    net_error = 83;
    return socket_fail ? -7 : 123;
}

int sceNetSendto(int fd, const void *data, unsigned int size, int flags,
    const SceNetSockaddr *address, unsigned int address_size) {
    const SceNetSockaddrIn *target = (const SceNetSockaddrIn *)address;
    static const unsigned char ip[] = {192, 168, 1, 249};
    assert(fd == 123 && size == TLS_FIXER_RUNTIME_PACKET_SIZE && flags == SCE_NET_MSG_DONTWAIT);
    assert(address_size == 16 && target->sin_len == 16 && target->sin_family == SCE_NET_AF_INET);
    assert(target->sin_port == sceNetHtons(52154) && target->sin_vport == 0);
    assert(memcmp(&target->sin_addr, ip, sizeof(ip)) == 0);
    assert(pthread_mutex_lock(&record_lock) == 0);
    assert(sends < TLS_FIXER_RUNTIME_RECORD_LIMIT);
    memcpy(packets[sends++], data, size);
    assert(pthread_mutex_unlock(&record_lock) == 0);
    errno = 84;
    net_error = 85;
    if (reenter) {
        reenter = 0;
        tls_fixer_runtime_mark(TLS_FIXER_RT_CONNECT_RETURN, 99);
    }
    return send_fail ? -9 : (int)size;
}

static void *producer(void *unused) {
    (void)unused;
    for (unsigned int i = 0; i < 80; ++i) {
        errno = 17;
        net_error = 23;
        tls_fixer_runtime_mark(TLS_FIXER_RT_CONNECT_ENTER, -31);
        assert(errno == 17 && net_error == 23);
    }
    return NULL;
}

int main(int argc, char **argv) {
    assert(argc == 2);
    const char *scenario = argv[1];
    no_errno = strcmp(scenario, "no-errno") == 0;
    no_libc_errno = strcmp(scenario, "no-libc-errno") == 0;
    socket_fail = strcmp(scenario, "socket-fail") == 0;
    address_fail = strcmp(scenario, "address-fail") == 0;
    send_fail = strcmp(scenario, "send-fail") == 0;
    reenter = strcmp(scenario, "reentry") == 0;
    errno = 17;
    if (strcmp(scenario, "invalid-stage") == 0) {
        tls_fixer_runtime_mark(0, 0);
        tls_fixer_runtime_mark(TLS_FIXER_RT_STAGE_LIMIT, 0);
        tls_fixer_runtime_mark(UINT32_MAX, 0);
        assert(opens == 0 && sends == 0 && errno == 17 && net_error == 23);
        return 0;
    }
    if (strcmp(scenario, "concurrent") == 0) {
        pthread_t threads[8];
        for (size_t i = 0; i < 8; ++i) assert(pthread_create(&threads[i], NULL, producer, NULL) == 0);
        for (size_t i = 0; i < 8; ++i) assert(pthread_join(threads[i], NULL) == 0);
        assert(opens == 1 && sends > 0 && sends <= TLS_FIXER_RUNTIME_RECORD_LIMIT);
    } else {
        unsigned int count = strcmp(scenario, "limit") == 0 ? 1000 : 1;
        for (unsigned int i = 0; i < count; ++i) tls_fixer_runtime_mark(TLS_FIXER_RT_CONNECT_ENTER, -31);
        assert(errno == 17 && net_error == 23);
#if TLS_FIXER_RUNTIME_USE_SCE_LIBC
        assert(libc_errno_calls > 0);
        if (no_libc_errno) {
            assert(opens == 0 && sends == 0);
            return 0;
        }
#endif
        if (no_errno || socket_fail || address_fail) {
            tls_fixer_runtime_mark(TLS_FIXER_RT_CONNECT_ENTER, -31);
            assert(sends == 0 && opens == (unsigned int)(!no_errno && !address_fail));
            return 0;
        }
        assert(opens == 1);
        assert(sends == (strcmp(scenario, "limit") == 0 ? TLS_FIXER_RUNTIME_RECORD_LIMIT :
            strcmp(scenario, "reentry") == 0 ? 2u : 1u));
    }
    unsigned int seen[TLS_FIXER_RUNTIME_RECORD_LIMIT] = {0};
    for (size_t i = 0; i < sends; ++i) {
        const unsigned char *packet = packets[i];
        assert(memcmp(packet, "ITR1", 4) == 0);
        for (size_t j = 0; j < 16; ++j) assert(packet[4 + j] == j);
        unsigned int sequence = field(packet + 20);
        assert(sequence < TLS_FIXER_RUNTIME_RECORD_LIMIT && seen[sequence]++ == 0);
        assert(field(packet + 24) == 0xabcdef && field(packet + 28) == 0x6789);
        assert(field(packet + 32) == TLS_FIXER_RT_CONNECT_ENTER || field(packet + 32) == TLS_FIXER_RT_CONNECT_RETURN);
        assert((int32_t)field(packet + 36) == -31 || field(packet + 36) == 99);
        assert(field(packet + 40) == 0x10203040 && field(packet + 44) == 0x50607080);
    }
    puts("runtime UDP: bounded scalar packets, nonblocking sends and errno preservation PASS");
    return 0;
}
