#define _POSIX_C_SOURCE 200809L
#include <openssl/crypto.h>
#include <psp2/kernel/threadmgr/lw_mutex.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

CRYPTO_RWLOCK *__wrap_CRYPTO_THREAD_lock_new(void);
int __wrap_CRYPTO_THREAD_read_lock(CRYPTO_RWLOCK *);
int __wrap_CRYPTO_THREAD_write_lock(CRYPTO_RWLOCK *);
int __wrap_CRYPTO_THREAD_unlock(CRYPTO_RWLOCK *);
void __wrap_CRYPTO_THREAD_lock_free(CRYPTO_RWLOCK *);
int __wrap_CRYPTO_atomic_add(int *, int, int *, CRYPTO_RWLOCK *);
void *tls_fixer_test_calloc(size_t,size_t);
#define calloc tls_fixer_test_calloc
#include "../../../../installer/crypto_lock_vita.c"
#undef calloc
static int allocation_fail,create_fail,lock_fail,unlock_fail,delete_fail;
static unsigned int created,deleted;
void *tls_fixer_test_calloc(size_t count,size_t size) {
    if (allocation_fail) return NULL;
    return calloc(count,size);
}
int sceKernelCreateLwMutex(SceKernelLwMutexWork *work,const char *name,unsigned int attr,int initial,const SceKernelLwMutexOptParam *opt) {
    assert(strcmp(name,"tls_fixer crypto")==0 && attr==SCE_KERNEL_MUTEX_ATTR_RECURSIVE && initial==0 && opt==NULL);
    if (create_fail) return -1;
    pthread_mutexattr_t attributes;
    assert(pthread_mutexattr_init(&attributes)==0);
    assert(pthread_mutexattr_settype(&attributes,PTHREAD_MUTEX_RECURSIVE)==0);
    assert(pthread_mutex_init(&work->mutex,&attributes)==0);
    assert(pthread_mutexattr_destroy(&attributes)==0);
    ++created;return 0;
}
int sceKernelDeleteLwMutex(SceKernelLwMutexWork *work) {
    if (delete_fail) return -1;
    assert(pthread_mutex_destroy(&work->mutex)==0);++deleted;return 0;
}
int sceKernelLockLwMutex(SceKernelLwMutexWork *work,int count,unsigned int *timeout) {
    assert(count==1 && timeout==NULL);
    if (lock_fail) return -1;
    return pthread_mutex_lock(&work->mutex)==0 ? 0 : -1;
}
int sceKernelUnlockLwMutex(SceKernelLwMutexWork *work,int count) {
    assert(count==1);
    if (unlock_fail) return -1;
    return pthread_mutex_unlock(&work->mutex)==0 ? 0 : -1;
}
static CRYPTO_RWLOCK *shared;
static int protected_count,atomic_count,inside;
static void *worker(void *opaque) {
    int writer=(int)(size_t)opaque;
    for (int i=0;i<25000;++i) {
        assert((writer ? __wrap_CRYPTO_THREAD_write_lock(shared) : __wrap_CRYPTO_THREAD_read_lock(shared))==1);
        assert(++inside==1);++protected_count;--inside;
        assert(__wrap_CRYPTO_THREAD_unlock(shared)==1);
        int result;
        assert(__wrap_CRYPTO_atomic_add(&atomic_count,1,&result,shared)==1);
    }
    return NULL;
}
int main(void) {
    allocation_fail=1;assert(__wrap_CRYPTO_THREAD_lock_new()==NULL && created==0);allocation_fail=0;
    create_fail=1;assert(__wrap_CRYPTO_THREAD_lock_new()==NULL && created==0);create_fail=0;
    assert(__wrap_CRYPTO_THREAD_read_lock(NULL)==0 && __wrap_CRYPTO_THREAD_write_lock(NULL)==0);
    assert(__wrap_CRYPTO_THREAD_unlock(NULL)==0);__wrap_CRYPTO_THREAD_lock_free(NULL);
    shared=__wrap_CRYPTO_THREAD_lock_new();assert(shared!=NULL && created==1);
    lock_fail=1;assert(__wrap_CRYPTO_THREAD_read_lock(shared)==0);lock_fail=0;
    assert(__wrap_CRYPTO_THREAD_read_lock(shared)==1 && __wrap_CRYPTO_THREAD_write_lock(shared)==1);
    unlock_fail=1;assert(__wrap_CRYPTO_THREAD_unlock(shared)==0);unlock_fail=0;
    assert(__wrap_CRYPTO_THREAD_unlock(shared)==1 && __wrap_CRYPTO_THREAD_unlock(shared)==1);
    pthread_t threads[4];
    for (size_t i=0;i<4;++i) assert(pthread_create(&threads[i],NULL,worker,(void *)(i&1))==0);
    for (size_t i=0;i<4;++i) assert(pthread_join(threads[i],NULL)==0);
    assert(protected_count==100000 && atomic_count==100000 && inside==0);
    int result;
    assert(__wrap_CRYPTO_atomic_add(NULL,1,&result,shared)==0);
    assert(__wrap_CRYPTO_atomic_add(&atomic_count,1,NULL,shared)==0);
    assert(__wrap_CRYPTO_atomic_add(&atomic_count,-1,&result,shared)==1 && result==99999);
    delete_fail=1;__wrap_CRYPTO_THREAD_lock_free(shared);assert(deleted==0);
    delete_fail=0;
    assert(__wrap_CRYPTO_THREAD_write_lock(shared)==1 && __wrap_CRYPTO_THREAD_unlock(shared)==1);
    __wrap_CRYPTO_THREAD_lock_free(shared);assert(deleted==created);
    puts("Crypto lock: recursive native locking, failure lifetime and concurrent atomic/reference updates PASS");
}
