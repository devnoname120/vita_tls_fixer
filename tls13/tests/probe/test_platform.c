#include "platform_vita.h"
#include "platform_fixture.h"
#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail, module_already, allocated, freed, unloaded, net_terms, ctl_terms, delays;
static int socket_closes, epoll_closes, send_result, recv_result, wait_result = 1;
static uint64_t clock_us;
static void *fixture_malloc(size_t size) { if (fail == 3) return NULL; ++allocated; return malloc(size); }
static void fixture_free(void *ptr) { if (ptr != NULL) ++freed; free(ptr); }
#define TLS_FIXER_PROBE_PLATFORM_TEST 1
#define malloc fixture_malloc
#define free fixture_free
#include "../../probe/platform_vita.c"
#undef malloc
#undef free

int sceSysmoduleIsLoaded(int module) { assert(module == SCE_SYSMODULE_NET); return fail == 1 ? -101 : module_already ? 0 : SCE_SYSMODULE_ERROR_UNLOADED; }
int sceSysmoduleLoadModule(int module) { assert(module == SCE_SYSMODULE_NET); return fail == 2 ? -102 : 0; }
int sceSysmoduleUnloadModule(int module) { assert(module == SCE_SYSMODULE_NET); ++unloaded; return 0; }
int sceNetInit(SceNetInitParam *init) { assert(init->memory != NULL && init->size == 1024 * 1024 && init->flags == 0); return fail == 4 ? -104 : 0; }
int sceNetTerm(void) { ++net_terms; return fail == 12 ? -112 : 0; }
int sceNetCtlInit(void) { return fail == 5 ? -105 : 0; }
void sceNetCtlTerm(void) { ++ctl_terms; }
int sceNetCtlInetGetState(int *state) { *state = SCE_NETCTL_STATE_CONNECTED; return 0; }
int sceKernelDelayThread(unsigned int us) { assert(us > 0 && us <= 10000); clock_us += us; ++delays; return 0; }
uint64_t sceKernelGetSystemTimeWide(void) { return clock_us; }
int sceNetInetPton(int family, const char *ip, void *out) { assert(family == SCE_NET_AF_INET && strcmp(ip, "192.168.1.1") == 0); memset(out, 0, 4); return 1; }
uint16_t sceNetHtons(uint16_t port) { return port; }
int sceNetSocket(const char *name, int family, int kind, int protocol) { (void)name; assert(family == SCE_NET_AF_INET && kind == SCE_NET_SOCK_STREAM && protocol == 0); return fail == 6 ? -106 : 4; }
int sceNetSetsockopt(int fd, int level, int option, const void *value, unsigned int length) { assert(fd == 4 && level == SCE_NET_SOL_SOCKET && option == SCE_NET_SO_NBIO && length == sizeof(int) && *(const int *)value == 1); return fail == 7 ? -107 : 0; }
int sceNetGetsockopt(int fd, int level, int option, void *value, unsigned int *length) { assert(fd == 4 && level == SCE_NET_SOL_SOCKET && option == SCE_NET_SO_ERROR && *length == sizeof(int)); *(int *)value = 0; return 0; }
int sceNetEpollCreate(const char *name, int flags) { (void)name; assert(flags == 0); return fail == 8 ? -108 : 5; }
int sceNetEpollControl(int eid, int op, int fd, SceNetEpollEvent *event) { assert(eid == 5 && fd == 4 && event != NULL && (op == SCE_NET_EPOLL_CTL_ADD || op == SCE_NET_EPOLL_CTL_MOD)); return fail == 9 ? -109 : 0; }
int sceNetEpollWait(int eid, SceNetEpollEvent *event, int count, int timeout) { assert(eid == 5 && count == 1 && timeout == 0); event->events = SCE_NET_EPOLLIN | SCE_NET_EPOLLOUT; return wait_result; }
int sceNetEpollDestroy(int eid) { assert(eid == 5); ++epoll_closes; return fail == 10 ? -110 : 0; }
int sceNetSocketClose(int fd) { assert(fd == 4); ++socket_closes; return fail == 11 ? -111 : 0; }
int sceNetConnect(int fd, const SceNetSockaddr *address, unsigned int length) { assert(fd == 4 && address != NULL && length == sizeof(SceNetSockaddrIn)); return SCE_NET_ERROR_EINPROGRESS; }
int sceNetSend(int fd, const void *data, unsigned int size, int flags) { assert(fd == 4 && data != NULL && size == 1 && flags == 0); return send_result; }
int sceNetRecv(int fd, void *data, unsigned int size, int flags) { assert(fd == 4 && data != NULL && size == 1 && flags == 0); return recv_result; }

int main(void) {
    for (fail = 0; fail <= 12; ++fail) {
        TlsFixerProbeNetwork network;
        allocated = freed = unloaded = net_terms = ctl_terms = socket_closes = epoll_closes = 0;
        module_already = 0;
        int rc = tls_fixer_probe_network_init(&network);
        if (fail >= 1 && fail <= 5) {
            assert(rc < 0);
            assert(tls_fixer_probe_network_free(&network) == 0);
            assert(net_terms == (fail == 5) && ctl_terms == 0);
            assert(unloaded == (fail >= 3));
            assert(allocated == freed);
            continue;
        }
        assert(rc == 0 && tls_fixer_probe_network_ready(&network) == 0);
        rc = network.io.start(&network, "192.168.1.1", 8443);
        if (fail >= 6 && fail <= 9) assert(rc < 0 && rc != MBEDTLS_ERR_SSL_WANT_WRITE);
        else {
            assert(rc == MBEDTLS_ERR_SSL_WANT_WRITE && network.io.finish_connect(&network) == 0);
            assert(network.io.wait(&network, MBEDTLS_ERR_SSL_WANT_READ, 10) == 0);
            char byte = 0;
            send_result = SCE_NET_ERROR_EAGAIN;
            recv_result = SCE_NET_ERROR_EINTR;
            assert(network.io.send(&network, (unsigned char *)&byte, 1) == MBEDTLS_ERR_SSL_WANT_WRITE);
            assert(network.io.recv(&network, (unsigned char *)&byte, 1) == MBEDTLS_ERR_SSL_WANT_READ);
            send_result = recv_result = 1;
            assert(network.io.send(&network, (unsigned char *)&byte, 1) == 1);
            assert(network.io.recv(&network, (unsigned char *)&byte, 1) == 1);
            wait_result = 0;
            assert(network.io.wait(&network, MBEDTLS_ERR_SSL_WANT_READ, 2) == MBEDTLS_ERR_SSL_TIMEOUT);
            assert(delays > 0);
            wait_result = 1;
        }
        int cleanup = tls_fixer_probe_network_free(&network);
        assert((cleanup < 0) == (fail >= 10));
        assert(net_terms == (fail < 10 || fail == 12));
        if (fail >= 10) {
            assert(freed == 0 && unloaded == 0);
            fixture_free(network.memory);
        } else assert(allocated == freed && unloaded == 1);
    }
    fail = 0; module_already = 1; unloaded = 0;
    TlsFixerProbeNetwork network;
    assert(tls_fixer_probe_network_init(&network) == 0 && tls_fixer_probe_network_free(&network) == 0 && unloaded == 0);
    puts("native platform fixtures: ownership, failures, nonblocking I/O and finite waits PASS");
    return 0;
}
