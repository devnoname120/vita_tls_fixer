/* SPDX-License-Identifier: 0BSD */
#include "cover.h"
#include "fetch.h"
#include "http.h"
#include "ca_index.h"
#include "crypto_platform.h"
#include "user_runtime.h"
#include <psp2/kernel/processmgr.h>
#include <psp2/kernel/sysmem.h>
#include <psp2/kernel/threadmgr.h>
#include <psp2/net/net.h>
#include <psp2/np/mgr.h>
#include <psp2common/net.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <psa/crypto.h>
#include <psa/crypto_extra.h>
#include <stdio.h>
#include <string.h>

#if STORE_COVER_DIAGNOSTICS
void store_cover_note(const char *phase, int value, const char *id);
#define note store_cover_note
#else
#define note(phase, value, id) ((void)0)
#endif
int _sceAppMgrConvertVs0UserDrivePath(const char *, char *, unsigned, const void *);
#define TIME_LIMIT_US INT64_C(10000000)

typedef struct { int socket; int64_t deadline; } Socket;
static int retryable(int rc) {
    return (uint32_t)rc == (uint32_t)SCE_NET_ERROR_EAGAIN || (uint32_t)rc == (uint32_t)SCE_NET_ERROR_EINTR;
}
static int send_data(void *opaque, const unsigned char *data, size_t length) {
    Socket *s = opaque;
    if (sceKernelGetSystemTimeWide() >= s->deadline) return MBEDTLS_ERR_SSL_TIMEOUT;
    int rc = sceNetSend(s->socket, data, (unsigned)length, 0);
    return rc >= 0 ? rc : retryable(rc) ? MBEDTLS_ERR_SSL_WANT_WRITE : MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}
static int recv_data(void *opaque, unsigned char *data, size_t length) {
    Socket *s = opaque;
    if (sceKernelGetSystemTimeWide() >= s->deadline) return MBEDTLS_ERR_SSL_TIMEOUT;
    int rc = sceNetRecv(s->socket, data, (unsigned)length, 0);
    return rc >= 0 ? rc : retryable(rc) ? MBEDTLS_ERR_SSL_WANT_READ : MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}
static int pause_io(Socket *socket, int rc) {
    if (rc != MBEDTLS_ERR_SSL_WANT_READ && rc != MBEDTLS_ERR_SSL_WANT_WRITE &&
        rc != MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) return 0;
    if (sceKernelGetSystemTimeWide() >= socket->deadline) return 0;
    return sceKernelDelayThread(10000) >= 0;
}

/* Runs on a dedicated Store worker stack. No Sony HTTP/SSL object, global
 * network initialization, host application heap, or account cookie is used. */
int store_cover_fetch(void *unused, const char *id, char *url) {
    (void)unused;
    static const char *const languages[] = {
        "ja", "en", "fr", "es", "de", "it", "nl", "pt", "ru", "ko",
        "zh", "zh", "fi", "sv", "da", "no", "pl", "pt", "en", "tr"
    };
    SceNpCountryCode region = {{0}}; int language = -1;
    int rc = sceNpManagerGetAccountRegion(&region, &language);
    if (rc < 0 || language < 0 || (unsigned)language >= sizeof(languages)/sizeof(languages[0])) return -1;
    char country[3] = {(char)region.data[0], (char)region.data[1], 0};
    for (unsigned i = 0; i < 2; ++i) if (country[i] >= 'A' && country[i] <= 'Z') country[i] += 'a'-'A';
    char path[160], request[384];
    if (store_cover_catalog_path(path, sizeof(path), country, languages[language], id) < 0) return -1;
    int request_length = snprintf(request, sizeof(request),
        "GET %s HTTP/1.0\r\nHost: store.playstation.com\r\nUser-Agent: tls_fixer\r\n"
        "Accept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n", path);
    if (request_length <= 0 || (size_t)request_length >= sizeof(request)) return -1;

    Socket socket = {-1, sceKernelGetSystemTimeWide() + TIME_LIMIT_US};
    int resolver = -1, epoll = -1, heap_live = 0, crypto_live = 0, result = -1;
    char incoming[4096];
    StoreCoverResponse response;
    if (store_response_init(&response, id) < 0) return -1;
    TlsFixerCaIndex ca = {0};
    mbedtls_ssl_context ssl; mbedtls_ssl_config config;
    mbedtls_ssl_init(&ssl); mbedtls_ssl_config_init(&config);
    const char *phase = "heap";
#define CHECK(call) do { phase = #call; rc = (call); if (rc < 0) goto done; } while (0)
    CHECK(tls_fixer_user_runtime_init()); heap_live = 1;
    CHECK(tls_fixer_crypto_platform_init()); crypto_live = 1;
    CHECK((int)psa_crypto_init());
    char ca_path[0x124] = {0}; const unsigned options[4] = {0};
    CHECK(_sceAppMgrConvertVs0UserDrivePath("vs0:/data/external/cert/CA_LIST.cer",ca_path,sizeof(ca_path),options));
    if (!ca_path[0] || !memchr(ca_path,0,sizeof(ca_path))) goto done;
    CHECK(tls_fixer_ca_index_build(&ca, ca_path));
    CHECK(mbedtls_ssl_config_defaults(&config,MBEDTLS_SSL_IS_CLIENT,MBEDTLS_SSL_TRANSPORT_STREAM,MBEDTLS_SSL_PRESET_DEFAULT));
    mbedtls_ssl_conf_min_tls_version(&config, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_max_tls_version(&config, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_authmode(&config, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_cb(&config, tls_fixer_ca_index_find, &ca);
    CHECK(mbedtls_ssl_setup(&ssl, &config));
    CHECK(mbedtls_ssl_set_hostname(&ssl, "store.playstation.com"));

    SceNetSockaddrIn address = {0};
    address.sin_len = sizeof(address); address.sin_family = SCE_NET_AF_INET; address.sin_port = sceNetHtons(443);
    phase = "resolver.create";
    resolver = sceNetResolverCreate("tls_fixer artwork",NULL,0); rc = resolver; if (rc < 0) goto done;
    CHECK(sceNetResolverStartNtoa(resolver,"store.playstation.com",&address.sin_addr,2000000,1,0));
    (void)sceNetResolverDestroy(resolver); resolver = -1;
    phase = "socket.create";
    socket.socket = sceNetSocket("tls_fixer artwork",SCE_NET_AF_INET,SCE_NET_SOCK_STREAM,0);
    rc = socket.socket; if (rc < 0) goto done;
    int nonblocking = 1;
    CHECK(sceNetSetsockopt(socket.socket,SCE_NET_SOL_SOCKET,SCE_NET_SO_NBIO,&nonblocking,sizeof(nonblocking)));
    epoll = sceNetEpollCreate("tls_fixer artwork",0); rc = epoll; if (rc < 0) goto done;
    SceNetEpollEvent event = {0}; event.events = SCE_NET_EPOLLOUT;
    CHECK(sceNetEpollControl(epoll,SCE_NET_EPOLL_CTL_ADD,socket.socket,&event));
    phase = "connect";
    rc = sceNetConnect(socket.socket,(SceNetSockaddr *)&address,sizeof(address));
    if (rc < 0) {
        if ((uint32_t)rc != (uint32_t)SCE_NET_ERROR_EINPROGRESS && (uint32_t)rc != (uint32_t)SCE_NET_ERROR_EALREADY) goto done;
        for (;;) {
            if (sceKernelGetSystemTimeWide() >= socket.deadline) { rc = MBEDTLS_ERR_SSL_TIMEOUT; goto done; }
            rc = sceNetEpollWait(epoll,&event,1,0);
            if (rc > 0) break;
            if (rc < 0 && !retryable(rc)) goto done;
            sceKernelDelayThread(10000);
        }
        int error = 0; unsigned length = sizeof(error);
        CHECK(sceNetGetsockopt(socket.socket,SCE_NET_SOL_SOCKET,SCE_NET_SO_ERROR,&error,&length));
        if (length != sizeof(error) || error) { rc = error ? error : -1; goto done; }
    }
    mbedtls_ssl_set_bio(&ssl,&socket,send_data,recv_data,NULL);
    phase = "handshake";
    do { rc = mbedtls_ssl_handshake(&ssl); } while (rc < 0 && pause_io(&socket,rc));
    note("verification", (int)mbedtls_ssl_get_verify_result(&ssl), id);
    if (rc < 0 || mbedtls_ssl_get_verify_result(&ssl) != 0) goto done;
    size_t sent = 0;
    phase = "send";
    while (sent < (size_t)request_length) {
        rc = mbedtls_ssl_write(&ssl,(const unsigned char *)request+sent,(size_t)request_length-sent);
        if (rc > 0) sent += (size_t)rc;
        else if (!pause_io(&socket,rc)) goto done;
    }
    phase = "read";
    for (;;) {
        rc = mbedtls_ssl_read(&ssl, (unsigned char *)incoming, sizeof(incoming));
        if (rc > 0) {
            int parsed = store_response_feed(&response, incoming, (size_t)rc);
            if (parsed < 0) { phase = "response"; rc = -1; goto done; }
            if (parsed > 0) break;
        } else if (rc == 0 || rc == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || rc == MBEDTLS_ERR_SSL_CONN_EOF) {
            /* Close-delimited HTTP/1.0 is valid only with complete JSON.
             * A declared Content-Length still requires every byte. */
            break;
        } else if (!pause_io(&socket, rc)) goto done;
    }
    phase = "parse.finish";
    result = store_response_finish(&response, url); rc = result;

done:
    note(phase,rc,id); (void)phase;
    if (resolver >= 0) (void)sceNetResolverDestroy(resolver);
    if (epoll >= 0) (void)sceNetEpollDestroy(epoll);
    if (socket.socket >= 0) (void)sceNetSocketClose(socket.socket);
    mbedtls_ssl_free(&ssl); mbedtls_ssl_config_free(&config);
    tls_fixer_ca_index_free(&ca);
    if (crypto_live) { mbedtls_psa_crypto_free(); tls_fixer_crypto_platform_free(); }
    if (heap_live) (void)tls_fixer_user_runtime_destroy();
    return result;
#undef CHECK
}
