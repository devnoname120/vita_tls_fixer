#include "platform_vita.h"
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <stdlib.h>
#include <string.h>
#if defined(TLS_FIXER_PROBE_PLATFORM_TEST)
#include "platform_fixture.h"
#else
#include <psp2/kernel/processmgr.h>
#include <psp2/kernel/threadmgr.h>
#include <psp2/net/net.h>
#include <psp2/net/netctl.h>
#include <psp2common/net.h>
#include <psp2/sysmodule.h>
#endif

static uint64_t probe_now(void *unused) {
    (void)unused;
    return sceKernelGetSystemTimeWide() / 1000;
}

static int probe_close(void *opaque) {
    TlsFixerProbeNetwork *network = opaque;
    if (network->cleanup_error != 0) return network->cleanup_error;
    if (network->epoll >= 0) {
        int rc = sceNetEpollDestroy(network->epoll);
        if (rc < 0) network->cleanup_error = rc;
        else network->epoll = -1;
    }
    if (network->socket >= 0) {
        int rc = sceNetSocketClose(network->socket);
        if (rc < 0 && network->cleanup_error == 0) network->cleanup_error = rc;
        if (rc >= 0) network->socket = -1;
    }
    return network->cleanup_error;
}

static int probe_start(void *opaque, const char *ip, unsigned int port) {
    TlsFixerProbeNetwork *network = opaque;
    SceNetSockaddrIn address;
    SceNetEpollEvent event;
    int nonblocking = 1, rc;
    if (network->socket >= 0 || network->epoll >= 0 || network->cleanup_error != 0) return TLS_FIXER_PROBE_INVALID;
    network->error = 0;
    memset(&address, 0, sizeof(address));
    address.sin_len = sizeof(address);
    address.sin_family = SCE_NET_AF_INET;
    address.sin_port = sceNetHtons((uint16_t)port);
    rc = sceNetInetPton(SCE_NET_AF_INET, ip, &address.sin_addr);
    if (rc != 1) { network->error = rc; return TLS_FIXER_PROBE_INVALID; }
    network->socket = sceNetSocket("tls_fixer probe", SCE_NET_AF_INET, SCE_NET_SOCK_STREAM, 0);
    if (network->socket < 0) { network->error = network->socket; return MBEDTLS_ERR_NET_SOCKET_FAILED; }
    rc = sceNetSetsockopt(network->socket, SCE_NET_SOL_SOCKET, SCE_NET_SO_NBIO, &nonblocking, sizeof(nonblocking));
    if (rc < 0) goto failed;
    network->epoll = sceNetEpollCreate("tls_fixer probe", 0);
    if (network->epoll < 0) { rc = network->epoll; goto failed; }
    memset(&event, 0, sizeof(event));
    event.events = SCE_NET_EPOLLIN | SCE_NET_EPOLLOUT;
    rc = sceNetEpollControl(network->epoll, SCE_NET_EPOLL_CTL_ADD, network->socket, &event);
    if (rc < 0) goto failed;
    rc = sceNetConnect(network->socket, (SceNetSockaddr *)&address, sizeof(address));
    if (rc == 0) return 0;
    if ((uint32_t)rc == (uint32_t)SCE_NET_ERROR_EINPROGRESS ||
        (uint32_t)rc == (uint32_t)SCE_NET_ERROR_EALREADY || (uint32_t)rc == (uint32_t)SCE_NET_ERROR_EINTR)
        return MBEDTLS_ERR_SSL_WANT_WRITE;
failed:
    network->error = rc;
    return MBEDTLS_ERR_NET_CONNECT_FAILED;
}

static int probe_finish_connect(void *opaque) {
    TlsFixerProbeNetwork *network = opaque;
    int error = 0;
    unsigned int length = sizeof(error);
    int rc = sceNetGetsockopt(network->socket, SCE_NET_SOL_SOCKET, SCE_NET_SO_ERROR, &error, &length);
    if (rc < 0 || length != sizeof(error) || error != 0) {
        network->error = rc < 0 ? rc : error;
        return MBEDTLS_ERR_NET_CONNECT_FAILED;
    }
    return 0;
}

static int probe_wait(void *opaque, int want, unsigned int milliseconds) {
    TlsFixerProbeNetwork *network = opaque;
    SceNetEpollEvent event;
    if (milliseconds == 0 || milliseconds > TLS_FIXER_PROBE_DEADLINE_MS ||
        (want != MBEDTLS_ERR_SSL_WANT_READ && want != MBEDTLS_ERR_SSL_WANT_WRITE)) return TLS_FIXER_PROBE_INVALID;
    memset(&event, 0, sizeof(event));
    event.events = want == MBEDTLS_ERR_SSL_WANT_READ ? SCE_NET_EPOLLIN : SCE_NET_EPOLLOUT;
    unsigned int mask = event.events | SCE_NET_EPOLLERR | SCE_NET_EPOLLHUP;
    int rc = sceNetEpollControl(network->epoll, SCE_NET_EPOLL_CTL_MOD, network->socket, &event);
    if (rc < 0) { network->error = rc; return MBEDTLS_ERR_NET_POLL_FAILED; }
    uint64_t begin = probe_now(NULL);
    for (;;) {
        uint64_t now = probe_now(NULL);
        if (now < begin) return TLS_FIXER_PROBE_CLOCK;
        if (now - begin >= milliseconds) return MBEDTLS_ERR_SSL_TIMEOUT;
        memset(&event, 0, sizeof(event));
        rc = sceNetEpollWait(network->epoll, &event, 1, 0);
        if (rc > 0 && (event.events & mask) != 0) return 0;
        if (rc < 0 && (uint32_t)rc != (uint32_t)SCE_NET_ERROR_EINTR) {
            network->error = rc;
            return MBEDTLS_ERR_NET_POLL_FAILED;
        }
        unsigned int rest = milliseconds - (unsigned int)(now - begin);
        rc = sceKernelDelayThread((rest > 10 ? 10 : rest) * 1000);
        if (rc < 0) { network->error = rc; return MBEDTLS_ERR_NET_POLL_FAILED; }
    }
}

static int net_result(TlsFixerProbeNetwork *network, int rc, int sending) {
    network->error = rc < 0 ? rc : 0;
    if (rc >= 0) return rc;
    if ((uint32_t)rc == (uint32_t)SCE_NET_ERROR_EAGAIN || (uint32_t)rc == (uint32_t)SCE_NET_ERROR_EINTR)
        return sending ? MBEDTLS_ERR_SSL_WANT_WRITE : MBEDTLS_ERR_SSL_WANT_READ;
    if ((uint32_t)rc == (uint32_t)SCE_NET_ERROR_ETIMEDOUT) return MBEDTLS_ERR_SSL_TIMEOUT;
    if ((uint32_t)rc == (uint32_t)SCE_NET_ERROR_ECONNRESET) return MBEDTLS_ERR_NET_CONN_RESET;
    return sending ? MBEDTLS_ERR_NET_SEND_FAILED : MBEDTLS_ERR_NET_RECV_FAILED;
}
static int probe_send(void *opaque, const unsigned char *data, size_t size) {
    TlsFixerProbeNetwork *network = opaque;
    if (size > UINT32_MAX) return TLS_FIXER_PROBE_INVALID;
    return net_result(network, sceNetSend(network->socket, data, (unsigned int)size, 0), 1);
}
static int probe_recv(void *opaque, unsigned char *data, size_t size) {
    TlsFixerProbeNetwork *network = opaque;
    if (size > UINT32_MAX) return TLS_FIXER_PROBE_INVALID;
    return net_result(network, sceNetRecv(network->socket, data, (unsigned int)size, 0), 0);
}
static int probe_native_error(void *opaque) { return ((TlsFixerProbeNetwork *)opaque)->error; }

int tls_fixer_probe_network_init(TlsFixerProbeNetwork *network) {
    if (network == NULL) return TLS_FIXER_PROBE_INVALID;
    memset(network, 0, sizeof(*network));
    network->socket = network->epoll = -1;
    network->io = (TlsFixerProbeIo){network, probe_start, probe_finish_connect, probe_wait,
        probe_send, probe_recv, probe_close, probe_native_error, probe_now};
    int rc = sceSysmoduleIsLoaded(SCE_SYSMODULE_NET);
    if ((uint32_t)rc == (uint32_t)SCE_SYSMODULE_ERROR_UNLOADED) {
        rc = sceSysmoduleLoadModule(SCE_SYSMODULE_NET);
        if (rc < 0) return rc;
        network->module_owned = 1;
    } else if (rc != SCE_SYSMODULE_LOADED) return rc < 0 ? rc : TLS_FIXER_PROBE_INVALID;
    network->memory = malloc(1024 * 1024);
    if (network->memory == NULL) return MBEDTLS_ERR_SSL_ALLOC_FAILED;
    SceNetInitParam init = {network->memory, 1024 * 1024, 0};
    rc = sceNetInit(&init);
    if (rc < 0) return rc;
    network->net_owned = 1;
    rc = sceNetCtlInit();
    if (rc < 0) return rc;
    network->ctl_owned = 1;
    return 0;
}

int tls_fixer_probe_network_ready(TlsFixerProbeNetwork *network) {
    if (network == NULL || !network->net_owned || !network->ctl_owned) return TLS_FIXER_PROBE_INVALID;
    uint64_t begin = probe_now(NULL);
    for (;;) {
        int state = -1;
        int rc = sceNetCtlInetGetState(&state);
        if (rc < 0) return rc;
        if (state == SCE_NETCTL_STATE_CONNECTED) return 0;
        uint64_t now = probe_now(NULL);
        if (now < begin) return TLS_FIXER_PROBE_CLOCK;
        if (now - begin >= TLS_FIXER_PROBE_DEADLINE_MS) return MBEDTLS_ERR_SSL_TIMEOUT;
        rc = sceKernelDelayThread(10000);
        if (rc < 0) return rc;
    }
}

int tls_fixer_probe_network_free(TlsFixerProbeNetwork *network) {
    if (network == NULL) return TLS_FIXER_PROBE_INVALID;
    int rc = probe_close(network);
    /* Failed native cleanup can leave references live until ordinary process exit. */
    if (rc < 0) return rc;
    if (network->ctl_owned) { sceNetCtlTerm(); network->ctl_owned = 0; }
    if (network->net_owned) {
        rc = sceNetTerm();
        if (rc < 0) { network->cleanup_error = rc; return rc; }
        network->net_owned = 0;
    }
    free(network->memory);
    network->memory = NULL;
    if (network->module_owned) {
        rc = sceSysmoduleUnloadModule(SCE_SYSMODULE_NET);
        if (rc >= 0) network->module_owned = 0;
    }
    return rc;
}
