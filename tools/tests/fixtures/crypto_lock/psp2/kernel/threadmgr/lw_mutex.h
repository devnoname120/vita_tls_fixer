#ifndef TLS_FIXER_TEST_LW_MUTEX_H
#define TLS_FIXER_TEST_LW_MUTEX_H
#include <pthread.h>
typedef struct SceKernelLwMutexWork { pthread_mutex_t mutex; } SceKernelLwMutexWork;
typedef struct SceKernelLwMutexOptParam { unsigned int size; } SceKernelLwMutexOptParam;
#define SCE_KERNEL_MUTEX_ATTR_RECURSIVE 2
int sceKernelCreateLwMutex(SceKernelLwMutexWork *, const char *, unsigned int, int, const SceKernelLwMutexOptParam *);
int sceKernelDeleteLwMutex(SceKernelLwMutexWork *);
int sceKernelLockLwMutex(SceKernelLwMutexWork *, int, unsigned int *);
int sceKernelUnlockLwMutex(SceKernelLwMutexWork *, int);
#endif
