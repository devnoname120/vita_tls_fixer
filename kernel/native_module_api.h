#ifndef TLS_FIXER_NATIVE_MODULE_API_H
#define TLS_FIXER_NATIVE_MODULE_API_H

#include <psp2kern/kernel/modulemgr.h>

#ifndef TLS_FIXER_PRIVATE_GUI_CLIENTS
#define TLS_FIXER_PRIVATE_GUI_CLIENTS 0
#endif

int tls_fixer_native_module_api_init(void);
int tls_fixer_native_module_info(SceUID pid, SceUID module, SceKernelModuleInfo *info);
int tls_fixer_native_module_list(SceUID pid, int flags1, int flags2, SceUID *modules, SceSize *count);
int tls_fixer_native_module_unload(SceUID pid, SceUID module, int flags, const void *options);
int tls_fixer_native_module_shared(SceUID pid, void *address);
typedef struct TlsFixerNativeHttpConsumer {
    SceUID module;
    uint32_t library;
    uint16_t attributes;
    char name[28];
    uint32_t step;
    int32_t native_result;
} TlsFixerNativeHttpConsumer;
/* 0: compatible; 1: shared exports or emulator startup require Sony; <0: unknown. */
int tls_fixer_native_http_requires_sony(SceUID pid, TlsFixerNativeHttpConsumer *consumer);
/* 1: HTTP has private RX storage; 0: absent/shared; <0: lookup failed. */
int tls_fixer_native_http_is_private(SceUID pid);
/* 0: absent; 1: private; 2: shared/nonprivate; negative: lookup failure. */
int tls_fixer_native_http_mapping(SceUID pid);

/* Host fixtures retain their native-service mocks. ARM uses resolved exports. */
#if defined(__arm__)
#define ksceKernelGetModuleInfo tls_fixer_native_module_info
#define ksceKernelGetModuleList tls_fixer_native_module_list
#define ksceKernelUnloadModuleForPid tls_fixer_native_module_unload
#define ksceKernelGetModuleIsSharedByAddr tls_fixer_native_module_shared
#endif

#endif
