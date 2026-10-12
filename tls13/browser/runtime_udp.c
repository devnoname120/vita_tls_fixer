#include "runtime_udp.h"

#include <psp2/kernel/processmgr.h>
#include <psp2/kernel/threadmgr/thread.h>
#include <psp2/net/net.h>

#include <stddef.h>
#include <string.h>

#if TLS_FIXER_RUNTIME_USE_SCE_LIBC
/* This provider links Sony libc, not newlib's __errno implementation. */
extern int *_sceLibcErrnoLoc(void);
#else
#include <errno.h>
#endif

#if !TLS_FIXER_ENABLE_RUNTIME_UDP
#error "The UDP recorder must only be compiled for an explicitly selected diagnostic"
#endif

_Static_assert(TLS_FIXER_RUNTIME_PORT > 0 && TLS_FIXER_RUNTIME_PORT < 65536, "UDP port range");
_Static_assert(sizeof(TLS_FIXER_RUNTIME_NONCE_HEX) == 33, "128-bit hexadecimal session nonce");
_Static_assert(sizeof(SceNetSockaddrIn) == 16, "Native IPv4 socket address extent");

static uint32_t initialized, records;
static int descriptor = -1;
static SceNetSockaddrIn destination;
static unsigned char nonce[16];

static int nibble(unsigned char character) {
    if (character >= '0' && character <= '9') return character - '0';
    if (character >= 'a' && character <= 'f') return character - 'a' + 10;
    if (character >= 'A' && character <= 'F') return character - 'A' + 10;
    return -1;
}

static void initialize(void) {
    static const char hex[] = TLS_FIXER_RUNTIME_NONCE_HEX;
    for (size_t i = 0; i < sizeof(nonce); ++i) {
        int high = nibble((unsigned char)hex[2 * i]);
        int low = nibble((unsigned char)hex[2 * i + 1]);
        if (high < 0 || low < 0) return;
        nonce[i] = (unsigned char)((high << 4) | low);
    }
    memset(&destination, 0, sizeof(destination));
    destination.sin_len = sizeof(destination);
    destination.sin_family = SCE_NET_AF_INET;
    destination.sin_port = sceNetHtons(TLS_FIXER_RUNTIME_PORT);
    if (sceNetInetPton(SCE_NET_AF_INET, TLS_FIXER_RUNTIME_HOST, &destination.sin_addr) != 1) return;
    descriptor = sceNetSocket("tls_fixer runtime", SCE_NET_AF_INET, SCE_NET_SOCK_DGRAM, 0);
}

static void put32(unsigned char *output, uint32_t value) {
    output[0] = (unsigned char)(value >> 24);
    output[1] = (unsigned char)(value >> 16);
    output[2] = (unsigned char)(value >> 8);
    output[3] = (unsigned char)value;
}

void tls_fixer_runtime_mark(unsigned int stage, int32_t result) {
    unsigned char packet[TLS_FIXER_RUNTIME_PACKET_SIZE];
    if (stage == 0 || stage >= TLS_FIXER_RT_STAGE_LIMIT) return;
    if (stage != TLS_FIXER_RT_CONNECT_ENTER && __atomic_load_n(&initialized, __ATOMIC_ACQUIRE) == 0) return;
    if (__atomic_load_n(&records, __ATOMIC_RELAXED) >= TLS_FIXER_RUNTIME_RECORD_LIMIT) return;
#if TLS_FIXER_RUNTIME_USE_SCE_LIBC
    int *libc_errno = _sceLibcErrnoLoc();
#else
    int *libc_errno = &errno;
#endif
    if (libc_errno == NULL) return;
    int saved_errno = *libc_errno;
    int *net_errno = sceNetErrnoLoc();
    if (net_errno == NULL) {
        *libc_errno = saved_errno;
        return;
    }
    int saved_net_errno = *net_errno;
    uint32_t expected = 0;
    if (__atomic_compare_exchange_n(&initialized, &expected, 1, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        initialize();
        __atomic_store_n(&initialized, 2, __ATOMIC_RELEASE);
    }
    if (__atomic_load_n(&initialized, __ATOMIC_ACQUIRE) != 2 || descriptor < 0) goto done;
    uint32_t sequence = __atomic_load_n(&records, __ATOMIC_RELAXED);
    do {
        if (sequence >= TLS_FIXER_RUNTIME_RECORD_LIMIT) goto done;
    } while (!__atomic_compare_exchange_n(&records, &sequence, sequence + 1, 0,
        __ATOMIC_RELAXED, __ATOMIC_RELAXED));

    memcpy(packet, "ITR1", 4);
    memcpy(packet + 4, nonce, sizeof(nonce));
    put32(packet + 20, sequence);
    put32(packet + 24, (uint32_t)sceKernelGetProcessId());
    put32(packet + 28, (uint32_t)sceKernelGetThreadId());
    put32(packet + 32, stage);
    put32(packet + 36, (uint32_t)result);
    uint64_t now = sceKernelGetSystemTimeWide();
    put32(packet + 40, (uint32_t)(now >> 32));
    put32(packet + 44, (uint32_t)now);
    (void)sceNetSendto(descriptor, packet, sizeof(packet), SCE_NET_MSG_DONTWAIT,
        (const SceNetSockaddr *)&destination, sizeof(destination));
done:
    /* Diagnostics must not change the caller's subsequent native error handling. */
    *net_errno = saved_net_errno;
    *libc_errno = saved_errno;
}
