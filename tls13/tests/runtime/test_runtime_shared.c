#define _POSIX_C_SOURCE 200809L
#include "user_runtime.h"
#include "shared_ssl_pool.h"
#include "user_runtime_mock.h"
#include <assert.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static unsigned capacity, used, peak, native_live, destroyed, kernel_allocations;
static int ready, block=1, mutex_live;
static pthread_mutex_t mutex=PTHREAD_MUTEX_INITIALIZER;
typedef union Header { size_t bytes; max_align_t align; } Header;
static int view(void *unused,TlsFixerSslPoolView *v) {
    (void)unused;if(!ready)return -17;
    *v=(TlsFixerSslPoolView){&capacity,block};return 0;
}
SceUID sceKernelAllocMemBlock(const char *n,int t,SceSize s,const void *o) {
    (void)n;(void)t;(void)s;(void)o;++kernel_allocations;abort();
}
int sceKernelFreeMemBlock(SceUID id){(void)id;abort();}
SceClibMspace sceClibMspaceCreate(void *p,SceSize s){(void)p;(void)s;abort();}
void sceClibMspaceDestroy(SceClibMspace h){(void)h;++destroyed;abort();}
SceUID sceKernelCreateMutex(const char *n,unsigned a,int c,const void *o){(void)n;(void)a;(void)c;(void)o;assert(!mutex_live);mutex_live=1;return 99;}
int sceKernelLockMutex(SceUID i,int c,unsigned *t){(void)c;(void)t;assert(i==99&&mutex_live);return pthread_mutex_lock(&mutex);}
int sceKernelUnlockMutex(SceUID i,int c){(void)c;assert(i==99&&mutex_live);return pthread_mutex_unlock(&mutex);}
int sceKernelDeleteMutex(SceUID i){assert(i==99&&mutex_live);mutex_live=0;return 0;}
void sceClibMspaceMallocStats(SceClibMspace h,SceClibMspaceStats *s){assert(h==&capacity);*s=(SceClibMspaceStats){capacity,0,peak,used};}
void *sceClibMspaceMalloc(SceClibMspace h,SceSize n) {
    assert(h==&capacity);if(n>capacity-used)return NULL;
    Header *p=malloc(sizeof(*p)+n);assert(p);p->bytes=n;used+=n;if(used>peak)peak=used;return p+1;
}
void sceClibMspaceFree(SceClibMspace h,void *p){assert(h==&capacity);Header *v=(Header*)p-1;assert(v->bytes<=used);used-=(unsigned)v->bytes;free(v);}
void *sceClibMspaceRealloc(SceClibMspace h,void *p,SceSize n) {
    assert(h==&capacity);Header *v=(Header*)p-1;size_t old=v->bytes;if(n>capacity-used+old)return NULL;
    v=realloc(v,sizeof(*v)+n);assert(v);v->bytes=n;used=used-(unsigned)old+n;if(used>peak)peak=used;return v+1;
}
void *sceClibMemset(void *p,int v,SceSize n){return memset(p,v,n);}
static void *worker(void *unused){(void)unused;for(unsigned i=0;i<500;++i){unsigned char *p=__wrap_calloc(16,16);assert(p);for(unsigned j=0;j<256;++j)assert(!p[j]);__wrap_free(p);}return NULL;}
int main(void) {
    assert(!__wrap_malloc(1));assert(!tls_fixer_user_runtime_bind_ssl(view,NULL));
    assert(tls_fixer_user_runtime_init()==-17 && !mutex_live);
    ready=1;capacity=64*1024;void *native=sceClibMspaceMalloc(&capacity,1472);assert(native);native_live=1;
    assert(!tls_fixer_user_runtime_init());assert(tls_fixer_user_runtime_init()<0);
    assert(tls_fixer_user_runtime_bind_ssl(view,NULL)<0);
    unsigned char *p=__wrap_malloc(32768);assert(p);memset(p,0x5a,32768);
    assert(tls_fixer_user_runtime_destroy()<0);
    /* Simulate the game consuming every unreserved byte. No kernel allocation
     * is available; reserved SSL allocations must still work until N is full. */
    void *q=__wrap_malloc(30000);assert(q);assert(!__wrap_malloc(2000));
    assert(!__wrap_realloc(p,40000));for(unsigned i=0;i<32768;++i)assert(p[i]==0x5a);
    __wrap_free(q);p=__wrap_realloc(p,40000);assert(p);for(unsigned i=0;i<32768;++i)assert(p[i]==0x5a);
    assert(!__wrap_malloc(SIZE_MAX)&&!__wrap_calloc(SIZE_MAX,2));
    /* Reused addresses with a different kernel UID must not be accepted. */
    ++block;assert(!tls_fixer_user_runtime_pool_alive()&&!__wrap_malloc(1));--block;
    assert(tls_fixer_user_runtime_pool_alive());__wrap_free(p);
    pthread_t threads[4];for(unsigned i=0;i<4;++i)assert(!pthread_create(&threads[i],NULL,worker,NULL));
    for(unsigned i=0;i<4;++i)assert(!pthread_join(threads[i],NULL));
    TlsFixerRuntimeStats s;assert(!tls_fixer_user_runtime_stats(&s));
    assert(s.capacity==65536&&s.used==1472&&!s.outstanding);
    assert(!tls_fixer_user_runtime_destroy()&&native_live&&used==1472&&!destroyed&&!kernel_allocations);
    /* A legal HTTP reinitialization borrows the same live pool again. A new
     * SSL initialization may also reuse its address with a fresh UID. */
    ++block;assert(!tls_fixer_user_runtime_init());
    p=__wrap_malloc(128);assert(p);__wrap_free(p);
    assert(!tls_fixer_user_runtime_destroy()&&used==1472&&!kernel_allocations);
    sceClibMspaceFree(&capacity,native);native_live=0;ready=0;
    puts("shared SSL heap: caller reservation, starvation, exhaustion, failure preservation, lifetime and concurrency PASS");
}
