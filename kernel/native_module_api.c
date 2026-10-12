#include "native_module_api.h"
#include "tls_fixer/firmware_profiles.h"
#include <psp2kern/kernel/sysclib.h>
#include <taihen.h>

/* Exported by taihenModuleUtils, although omitted from the public header. */
int module_get_export_func(SceUID pid, const char *module, uint32_t library,
    uint32_t function, uintptr_t *address);

static int (*get_info)(SceUID, SceUID, SceKernelModuleInfo *);
static int (*get_list)(SceUID, int, int, SceUID *, SceSize *);
static int (*unload_module)(SceUID, SceUID, int, const void *);
static int (*is_shared)(SceUID, void *);
static int ready;

int tls_fixer_native_module_api_init(void) {
    tai_module_info_t identity;
    const TlsFixerKernelProfile *profile = NULL;
    static const uint32_t libraries[] = {UINT32_C(0xc445fa63), UINT32_C(0x92c9ffc2)};
    static const uint32_t nids[2][4] = {
        {0xd269f915, 0x97cf7b4e, 0x5972e2cc, 0x99890202},
        {0xdaa90093, 0xb72c75a4, 0xfca9fdb1, 0xf1de6949}
    };
    uintptr_t addresses[4] = {0};
    __atomic_store_n(&ready, 0, __ATOMIC_RELEASE);
    memset(&identity, 0, sizeof(identity));
    identity.size = sizeof(identity);
    if (taiGetModuleInfoForKernel(KERNEL_PID, "SceKernelModulemgr", &identity) < 0 ||
        memcmp(identity.name, "SceKernelModulemgr", sizeof("SceKernelModulemgr")) != 0) return -1;
    for (size_t i = 0; i < sizeof(tls_fixer_kernel_profiles) / sizeof(tls_fixer_kernel_profiles[0]); ++i) {
        if (identity.module_nid == tls_fixer_kernel_profiles[i].module_nid) {
            profile = &tls_fixer_kernel_profiles[i];
            break;
        }
    }
    if (profile == NULL) return -1;
    for (size_t i = 0; i < 4; ++i) {
        if (module_get_export_func(KERNEL_PID, "SceKernelModulemgr", libraries[profile->family],
                nids[profile->family][i], &addresses[i]) < 0 || addresses[i] == 0) return -1;
    }
    get_info = (int (*)(SceUID, SceUID, SceKernelModuleInfo *))addresses[0];
    get_list = (int (*)(SceUID, int, int, SceUID *, SceSize *))addresses[1];
    unload_module = (int (*)(SceUID, SceUID, int, const void *))addresses[2];
    is_shared = (int (*)(SceUID, void *))addresses[3];
    __atomic_store_n(&ready, 1, __ATOMIC_RELEASE);
    return 0;
}

int tls_fixer_native_module_info(SceUID pid, SceUID module, SceKernelModuleInfo *info) {
    return __atomic_load_n(&ready, __ATOMIC_ACQUIRE) ? get_info(pid, module, info) : -1;
}
int tls_fixer_native_module_list(SceUID pid, int flags1, int flags2, SceUID *modules, SceSize *count) {
    return __atomic_load_n(&ready, __ATOMIC_ACQUIRE) ? get_list(pid, flags1, flags2, modules, count) : -1;
}
int tls_fixer_native_module_unload(SceUID pid, SceUID module, int flags, const void *options) {
    return __atomic_load_n(&ready, __ATOMIC_ACQUIRE) ? unload_module(pid, module, flags, options) : -1;
}
int tls_fixer_native_module_shared(SceUID pid, void *address) {
    return __atomic_load_n(&ready, __ATOMIC_ACQUIRE) ? is_shared(pid, address) : -1;
}
