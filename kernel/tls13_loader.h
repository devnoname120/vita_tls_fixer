#ifndef TLS_FIXER_KERNEL_LOADER_H
#define TLS_FIXER_KERNEL_LOADER_H

#include <psp2kern/types.h>

#ifdef __cplusplus
extern "C" {
#endif

int tls_fixer_kernel_loader_init(void);
void tls_fixer_kernel_loader_destroy(void);
int tls_fixer_kernel_loader_ready(void);
int tls_fixer_kernel_http_process_allowed(SceUID pid);
int tls_fixer_kernel_inject_for_pid(SceUID pid, SceUID libhttp_modid);
int tls_fixer_kernel_browser_loader_ready(void);
int tls_fixer_kernel_inject_browser_for_pid(SceUID pid, SceUID compat_modid, const char *provider_path);

#ifdef __cplusplus
}
#endif

#endif
