#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include <vita_mock.h>
#include "crypto_platform.h"
#include "ssl_misc.h"
#include <psa/crypto.h>
#include <psa/crypto_extra.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail_alloc;
static size_t allocations;
void *__real_calloc(size_t, size_t);
void *__wrap_calloc(size_t a, size_t b) {
    ++allocations;
    return fail_alloc ? NULL : __real_calloc(a,b);
}
typedef struct Input { const unsigned char *data; size_t size, offset, calls; } Input;
static int receive(void *p, unsigned char *out, size_t n) {
    Input *in=p;
    if (++in->calls % 5 == 0) return MBEDTLS_ERR_SSL_WANT_READ;
    if (n > 7) n=7;
    if (n > in->size-in->offset) n=in->size-in->offset;
    memcpy(out,in->data+in->offset,n); in->offset+=n;
    return (int)n;
}
static void setup(mbedtls_ssl_context *ssl, mbedtls_ssl_config *config) {
    mbedtls_ssl_init(ssl);
    assert(!mbedtls_ssl_setup(ssl,config));
    assert(ssl->in_buf_len==4096);
}
int main(void) {
    assert(!tls_fixer_crypto_platform_init());
    assert(psa_crypto_init()==PSA_SUCCESS);
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config config;
    mbedtls_ssl_config_init(&config);
    assert(!mbedtls_ssl_config_defaults(&config,MBEDTLS_SSL_IS_CLIENT,
                                      MBEDTLS_SSL_TRANSPORT_STREAM,MBEDTLS_SSL_PRESET_DEFAULT));
    setup(&ssl,&config);
    unsigned char *old=ssl.in_buf;
    ssl.in_offt=old+333;
    size_t ctr=(size_t)(ssl.in_ctr-old), hdr=(size_t)(ssl.in_hdr-old);
    size_t len=(size_t)(ssl.in_len-old), iv=(size_t)(ssl.in_iv-old), msg=(size_t)(ssl.in_msg-old);
    for (size_t i=0;i<4096;++i) old[i]=(unsigned char)(i%251);
    fail_alloc=1;
    assert(mbedtls_ssl_grow_input_buffer(&ssl,8000)==MBEDTLS_ERR_SSL_ALLOC_FAILED);
    assert(ssl.in_buf==old && ssl.in_buf_len==4096 && ssl.in_offt==old+333);
    fail_alloc=0;
    assert(!mbedtls_ssl_grow_input_buffer(&ssl,8000));
    assert(ssl.in_buf!=old && ssl.in_buf_len==8000);
    assert(ssl.in_ctr==ssl.in_buf+ctr && ssl.in_hdr==ssl.in_buf+hdr);
    assert(ssl.in_len==ssl.in_buf+len && ssl.in_iv==ssl.in_buf+iv && ssl.in_msg==ssl.in_buf+msg);
    assert(ssl.in_offt==ssl.in_buf+333);
    for (size_t i=0;i<4096;++i) assert(ssl.in_buf[i]==(unsigned char)(i%251));
    for (size_t i=4096;i<8000;++i) assert(!ssl.in_buf[i]);
    size_t count=allocations;
    fail_alloc=1;
    assert(!mbedtls_ssl_grow_input_buffer(&ssl,4096) && allocations==count);
    assert(mbedtls_ssl_grow_input_buffer(&ssl,MBEDTLS_SSL_IN_BUFFER_LEN+1)==MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
    assert(allocations==count && ssl.in_buf_len==8000);
    fail_alloc=0;
    assert(!mbedtls_ssl_session_reset(&ssl) && ssl.in_buf_len==8000);
    assert(!mbedtls_ssl_grow_input_buffer(&ssl,MBEDTLS_SSL_IN_BUFFER_LEN));
    assert(ssl.in_buf_len==MBEDTLS_SSL_IN_BUFFER_LEN);
    assert(!mbedtls_ssl_session_reset(&ssl) && ssl.in_buf_len==MBEDTLS_SSL_IN_BUFFER_LEN);
    mbedtls_ssl_free(&ssl);

    /* Individually small records form a handshake larger than 4 KiB.
     * Seven-byte network reads and WANT_READ exercise relocation on retries. */
    unsigned char message[7000], wire[7015];
    memset(message,0x35,sizeof(message));
    message[0]=MBEDTLS_SSL_HS_CERTIFICATE;
    message[1]=0; message[2]=(unsigned char)((sizeof(message)-4)>>8); message[3]=(unsigned char)(sizeof(message)-4);
    for (size_t fragment=2500;fragment<=4083;fragment+=1583) {
    size_t used=0;
    for (size_t off=0;off<sizeof(message);) {
        size_t n=sizeof(message)-off; if(n>fragment)n=fragment;
        unsigned char header[]={MBEDTLS_SSL_MSG_HANDSHAKE,3,3,(unsigned char)(n>>8),(unsigned char)n};
        memcpy(wire+used,header,5); used+=5; memcpy(wire+used,message+off,n); used+=n; off+=n;
    }
    setup(&ssl,&config);
    Input in={wire,used,0,0};
    mbedtls_ssl_set_bio(&ssl,&in,NULL,receive,NULL);
    int ret;
    do { ret=mbedtls_ssl_read_record(&ssl,0); } while(ret==MBEDTLS_ERR_SSL_WANT_READ);
    assert(!ret && ssl.in_msglen==sizeof(message));
    assert(!memcmp(ssl.in_msg,message,sizeof(message)) && ssl.in_buf_len>4096);
    mbedtls_ssl_free(&ssl);
    }

    setup(&ssl,&config);
    const unsigned char bad[]={MBEDTLS_SSL_MSG_HANDSHAKE,3,3,255,255};
    Input in={bad,sizeof(bad),0,0};
    mbedtls_ssl_set_bio(&ssl,&in,NULL,receive,NULL);
    count=allocations;
    int ret=mbedtls_ssl_read_record(&ssl,0);
    assert(ret==MBEDTLS_ERR_SSL_BAD_INPUT_DATA && ssl.in_buf_len==4096 && allocations==count);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&config);
    mbedtls_psa_crypto_free();
    tls_fixer_crypto_platform_free();
    puts("small RX: 4096 start, safe growth, pointers, failure, reset, fragmented handshake and limits PASS");
}
