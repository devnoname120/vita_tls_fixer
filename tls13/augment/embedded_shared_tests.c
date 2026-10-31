#include "embedded.h"
#include "provider.h"
#include "transport.h"
#include "user_runtime.h"
#include "sony_ssl_pool.h"
#include <psp2/kernel/modulemgr.h>
#include <assert.h>
#include <stdio.h>

int module_start(SceSize,const void *);
int module_stop(SceSize,const void *);
int tls_fixer_embedded_http_init(unsigned int);
int tls_fixer_embedded_http_term(void);
int tls_fixer_embedded_create(void *,int);
static int ready,alive=1,fail_transport,fail_native_term;
static int runtime,transports,term_calls,start_calls,stop_calls;
static int native_start(SceSize n,const void *p){(void)n;(void)p;++start_calls;return 0;}
static int native_stop(SceSize n,const void *p){(void)n;(void)p;++stop_calls;return 0;}
static int native_init(unsigned int n){assert(n==65536);return 0;}
static int native_term(void){++term_calls;return fail_native_term?-25:0;}
SceUID sceKernelCreateMutex(const char *n,unsigned a,int c,const void *o){(void)n;(void)a;(void)c;(void)o;return 99;}
int sceKernelDeleteMutex(SceUID i){assert(i==99);return 0;}
int sceKernelLockMutex(SceUID i,int c,unsigned *t){(void)c;(void)t;assert(i==99);return 0;}
int sceKernelUnlockMutex(SceUID i,int c){(void)c;assert(i==99);return 0;}
int tls_fixer_cert_policy_bind(TlsFixerCertPolicy *p,const void *t,size_t n){(void)p;assert(t&&n);return 0;}
int tls_fixer_sony_ssl_pool_prepare(const void *p){assert(p);return ready?0:-17;}
int tls_fixer_sony_ssl_pool_read(void *c,TlsFixerSslPoolView *v){(void)c;(void)v;return 0;}
int tls_fixer_user_runtime_bind_ssl(TlsFixerSslPoolRead r,void *c){(void)c;assert(r);return 0;}
int tls_fixer_user_runtime_init(void){assert(!runtime);runtime=1;return 0;}
int tls_fixer_user_runtime_destroy(void){assert(runtime&&!transports);runtime=0;return 0;}
int tls_fixer_user_runtime_pool_alive(void){return alive;}
int tls_fixer_transport_global_init(void){assert(runtime&&!transports);transports=1;return fail_transport?-20:0;}
int tls_fixer_transport_global_destroy(void){assert(runtime);transports=0;return 0;}
int tls_fixer_embedded_cert_init(void){return 0;}
void tls_fixer_embedded_cert_destroy(void){}
void tls_fixer_embedded_profile_init(void){}
void tls_fixer_embedded_profile_destroy(void){}
void tls_fixer_embedded_redirect_init(void){}
void tls_fixer_embedded_redirect_destroy(void){}
int tls_fixer_transport_create(void *p,int s,int *handled){assert(p&&s==7&&runtime&&transports);*handled=1;return 0;}
int main(void) {
    g_tls_fixer_embedded_bindings.text=(void *)1;g_tls_fixer_embedded_bindings.data=(void *)2;
    g_tls_fixer_embedded_bindings.start=native_start;g_tls_fixer_embedded_bindings.stop=native_stop;
    g_tls_fixer_embedded_bindings.http_init=native_init;g_tls_fixer_embedded_bindings.http_term=native_term;
    g_tls_fixer_embedded_bindings.certificates.get_crypto_context=(void *)3;
    assert(!module_start(0,NULL)&&start_calls==1);
    /* HTTP-before-SSL must still succeed without reserving anything. */
    assert(!tls_fixer_embedded_http_init(65536)&&!runtime);
    assert(tls_fixer_embedded_enter()&&!runtime);
    /* One native operation was already admitted. A failed lazy initialization
     * must roll back its private state without closing admission underneath it. */
    ready=1;fail_transport=1;
    assert(tls_fixer_embedded_enter()&&!runtime&&!transports);
    tls_fixer_embedded_leave();tls_fixer_embedded_leave();
    fail_transport=0;assert(!tls_fixer_embedded_create((void *)1,7)&&runtime&&transports);
    assert(module_stop(0,NULL)==SCE_KERNEL_STOP_FAIL);
    fail_native_term=1;assert(tls_fixer_embedded_http_term()==-25&&runtime&&transports);
    fail_native_term=0;
    assert(tls_fixer_embedded_enter());
    int calls_before=term_calls;
    assert(tls_fixer_embedded_http_term()<0 && term_calls==calls_before); /* Active entry prevents cleanup. */
    tls_fixer_embedded_leave();
    assert(!tls_fixer_embedded_http_term()&&!runtime&&!transports);
    assert(!module_stop(0,NULL)&&stop_calls==1);
    /* Pool-loss detection fails before any stale modern pointers are touched. */
    assert(!module_start(0,NULL));assert(!tls_fixer_embedded_http_init(65536));
    alive=0;int before=term_calls;assert(!tls_fixer_embedded_enter());
    assert(tls_fixer_embedded_http_term()==TLS_FIXER_SCE_HTTP_ERROR_SSL&&term_calls==before);
    alive=1;assert(!tls_fixer_embedded_http_term());assert(!module_stop(0,NULL));
    puts("embedded shared pool: HTTP-before-SSL, retry/rollback, active operations and lifetime PASS");
}
