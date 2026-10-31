#define _GNU_SOURCE
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include <vita_mock.h>
#include "provider.h"
#include "transport.h"
#include <assert.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

TlsFixerProviderGlobal g_tls_fixer_http;
int main(int argc, char **argv) {
    enum { CONNECTIONS=64 };
    assert(argc==3);
    mock_ca_file=argv[1];
    unsigned char *arena=mmap((void *)(uintptr_t)0x21000000,CONNECTIONS*4096,
        PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
    assert(arena!=MAP_FAILED);
    uint32_t *options=(uint32_t *)(arena+0x800); *options=0x3f;
    g_tls_fixer_http.global_https_options_address=(uintptr_t)options;
    assert(!tls_fixer_transport_global_init());
    g_tls_fixer_http.state=TLS_FIXER_PROVIDER_ACTIVE;
    int sockets[CONNECTIONS], handled, result;
    size_t rx_bytes=0;
    struct sockaddr_in address={.sin_family=AF_INET,.sin_port=htons((uint16_t)atoi(argv[2]))};
    assert(inet_pton(AF_INET,"127.0.0.1",&address.sin_addr)==1);
    for(unsigned i=0;i<CONNECTIONS;++i) {
        unsigned char *request=arena+i*4096, *sony=request+0x200;
        char *host=(char *)request+0x400; strcpy(host,"localhost");
        tls_fixer_write_u32(request,TLS_FIXER_REQUEST_PRIMARY_CONNECTION_OFFSET,(uint32_t)(uintptr_t)sony);
        tls_fixer_write_u32(request,0x8c,1);
        tls_fixer_write_u32(sony,TLS_FIXER_CONNECTION_HOSTNAME_OFFSET,(uint32_t)(uintptr_t)host);
        sockets[i]=socket(AF_INET,SOCK_STREAM,0); assert(sockets[i]>=0);
        assert(!connect(sockets[i],(void *)&address,sizeof(address)));
        assert(!fcntl(sockets[i],F_SETFL,O_NONBLOCK));
        assert(!tls_fixer_transport_create(request,sockets[i],&handled) && handled);
        uint64_t deadline=sceKernelGetSystemTimeWide()+10000000;
        do {
            result=tls_fixer_transport_connect(request,&handled); assert(handled);
            if(result==TLS_FIXER_SCE_HTTP_ERROR_EAGAIN)usleep(1000);
            assert(sceKernelGetSystemTimeWide()<deadline);
        }while(result==TLS_FIXER_SCE_HTTP_ERROR_EAGAIN);
        assert(!result);
        TlsFixerRegistryHandle handle;
        assert(!tls_fixer_registry_acquire(&g_tls_fixer_http.registry,(uintptr_t)sony,&handle));
        TlsFixerConnection *connection=handle.payload;
        rx_bytes+=connection->ssl.in_buf_len;
        assert(!tls_fixer_registry_release(&g_tls_fixer_http.registry,&handle));
    }
    assert(tls_fixer_registry_count(&g_tls_fixer_http.registry)==CONNECTIONS);
    for(unsigned i=0;i<CONNECTIONS;++i) {
        unsigned char *sony=arena+i*4096+0x200, byte=0;
        uint64_t deadline=sceKernelGetSystemTimeWide()+10000000;
        do {
            result=tls_fixer_transport_read(sony,&byte,1,&handled); assert(handled);
            if(result==TLS_FIXER_SCE_HTTP_ERROR_EAGAIN)usleep(1000);
            assert(sceKernelGetSystemTimeWide()<deadline);
        }while(result==TLS_FIXER_SCE_HTTP_ERROR_EAGAIN);
        assert(result==1 && byte=='x');
        assert(!tls_fixer_transport_shutdown(sony,&handled) && handled);
        close(sockets[i]);
    }
    assert(!tls_fixer_registry_count(&g_tls_fixer_http.registry));
    assert(!tls_fixer_transport_global_destroy());
    assert(!munmap(arena,CONNECTIONS*4096));
    printf("64 simultaneous modern TLS connections PASS; receive buffers=%zu bytes\n",rx_bytes);
}
