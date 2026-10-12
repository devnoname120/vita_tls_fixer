#ifndef TLS_FIXER_NATIVE_MODULE_API_H
#define TLS_FIXER_NATIVE_MODULE_API_H

#include <psp2kern/kernel/modulemgr.h>

int tls_fixer_native_module_api_init(void);
int tls_fixer_native_module_info(SceUID pid, SceUID module, SceKernelModuleInfo *info);
int tls_fixer_native_module_list(SceUID pid, int flags1, int flags2, SceUID *modules, SceSize *count);
int tls_fixer_native_module_unload(SceUID pid, SceUID module, int flags, const void *options);
int tls_fixer_native_module_shared(SceUID pid, void *address);

/* Host fixtures retain their native-service mocks. ARM uses resolved exports. */
#if defined(__arm__)
#define ksceKernelGetModuleInfo tls_fixer_native_module_info
#define ksceKernelGetModuleList tls_fixer_native_module_list
#define ksceKernelUnloadModuleForPid tls_fixer_native_module_unload
#define ksceKernelGetModuleIsSharedByAddr tls_fixer_native_module_shared
#endif

#endif
