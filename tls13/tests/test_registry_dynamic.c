#include "tls_fixer/registry.h"
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>

static int fail_resize;
static _Atomic unsigned cleaned;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_barrier_t barrier;
static TlsFixerRegistry *thread_registry;
void *__real_realloc(void *, size_t);
void *__wrap_realloc(void *p, size_t n) { return fail_resize ? NULL : __real_realloc(p,n); }
static void lock(void *p) { (void)p; assert(!pthread_mutex_lock(&mutex)); }
static void unlock(void *p) { (void)p; assert(!pthread_mutex_unlock(&mutex)); }
static void cleanup(void *p, void *payload) {
    TlsFixerRegistry *r = p;
    assert(payload && tls_fixer_registry_count(r));
    assert(tls_fixer_registry_begin_stop_if_empty(r) == TLS_FIXER_REGISTRY_BUSY);
    ++cleaned;
}
static void *worker(void *argument) {
    uintptr_t base=(uintptr_t)argument*1000+10000;
    TlsFixerRegistryHandle held[64];
    for(unsigned iteration=0;iteration<20;++iteration) {
        for(uintptr_t i=0;i<64;++i) {
            assert(!tls_fixer_registry_insert(thread_registry,base+i,(void *)(base+i)));
            assert(!tls_fixer_registry_acquire(thread_registry,base+i,&held[i]));
        }
        (void)pthread_barrier_wait(&barrier);
        for(uintptr_t i=0;i<64;++i) {
            assert(!tls_fixer_registry_remove(thread_registry,base+i));
            assert(!tls_fixer_registry_release(thread_registry,&held[i]));
        }
        (void)pthread_barrier_wait(&barrier);
    }
    return NULL;
}
int main(void) {
    TlsFixerRegistry registry;
    TlsFixerRegistryOps ops = {.lock=lock,.unlock=unlock,.cleanup=cleanup,.context=&registry};
    TlsFixerRegistryHandle held[256], stale;
    assert(!tls_fixer_registry_init(&registry,&ops));
    assert(!registry.capacity && !registry.slots);
    for (uintptr_t i=1;i<=256;++i) {
        if (i == 5) {
            fail_resize=1;
            assert(tls_fixer_registry_insert(&registry,i,(void *)i)==TLS_FIXER_REGISTRY_FULL);
            assert(tls_fixer_registry_count(&registry)==4);
            fail_resize=0;
        }
        assert(!tls_fixer_registry_insert(&registry,i,(void *)i));
        assert(!tls_fixer_registry_acquire(&registry,i,&held[i-1]));
    }
    assert(tls_fixer_registry_count(&registry)==256);
    stale=held[0];
    for (uintptr_t i=1;i<=256;++i) {
        assert(held[i-1].payload==(void *)i);
        assert(!tls_fixer_registry_remove(&registry,i));
    }
    assert(tls_fixer_registry_destroy(&registry)==TLS_FIXER_REGISTRY_BUSY);
    for (unsigned i=0;i<256;++i) assert(!tls_fixer_registry_release(&registry,&held[i]));
    assert(tls_fixer_registry_release(&registry,&stale)==TLS_FIXER_REGISTRY_STALE_HANDLE);
    assert(cleaned==256 && !tls_fixer_registry_count(&registry));
    assert(!tls_fixer_registry_destroy(&registry));
    assert(!registry.capacity && !registry.slots);
    assert(!tls_fixer_registry_init(&registry,&ops));
    thread_registry=&registry;
    assert(!pthread_barrier_init(&barrier,NULL,4));
    pthread_t threads[4];
    for(uintptr_t i=0;i<4;++i)assert(!pthread_create(&threads[i],NULL,worker,(void *)i));
    for(unsigned i=0;i<4;++i)assert(!pthread_join(threads[i],NULL));
    assert(!pthread_barrier_destroy(&barrier));
    assert(cleaned==256+4*64*20 && !tls_fixer_registry_count(&registry));
    assert(!tls_fixer_registry_destroy(&registry));
    puts("dynamic registry: 256 held connections, resize failure, four concurrent callers and cleanup PASS");
}
