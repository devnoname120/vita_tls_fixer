#include "native_module_api.h"
#include <taihen.h>
#include <assert.h>
#include <stdio.h>

static uint32_t identity_nid;
static int family, fail_index, lookup_count, bad_identity;

static int fake_info(SceUID pid, SceUID module, SceKernelModuleInfo *info) {
    assert(pid == 21 && module == 22 && info != NULL);
    return 31;
}
static int fake_list(SceUID pid, int a, int b, SceUID *modules, SceSize *count) {
    assert(pid == 21 && a == 0xff && b == 1 && modules != NULL && *count == 256);
    return 32;
}
static int fake_unload(SceUID pid, SceUID module, int flags, const void *options) {
    assert(pid == 21 && module == 22 && flags == 0 && options == NULL);
    return 33;
}
static int fake_shared(SceUID pid, void *address) {
    assert(pid == 21 && address == (void *)(uintptr_t)0x81000000);
    return 34;
}
int taiGetModuleInfoForKernel(SceUID pid, const char *name, tai_module_info_t *info) {
    assert(pid == KERNEL_PID && strcmp(name, "SceKernelModulemgr") == 0);
    assert(info->size == sizeof(*info));
    info->module_nid = identity_nid;
    strcpy(info->name, bad_identity ? "unknown" : name);
    return 0;
}
int module_get_export_func(SceUID pid, const char *name, uint32_t library, uint32_t function, uintptr_t *address) {
    static const uint32_t nids[][4] = {
        {0xd269f915,0x97cf7b4e,0x5972e2cc,0x99890202},
        {0xdaa90093,0xb72c75a4,0xfca9fdb1,0xf1de6949}
    };
    uintptr_t targets[] = {(uintptr_t)fake_info,(uintptr_t)fake_list,(uintptr_t)fake_unload,(uintptr_t)fake_shared};
    assert(pid == KERNEL_PID && strcmp(name, "SceKernelModulemgr") == 0);
    assert(library == (family ? UINT32_C(0x92c9ffc2) : UINT32_C(0xc445fa63)));
    int i = lookup_count++;
    assert(i < 4 && function == nids[family][i]);
    if (i == fail_index) return -123;
    *address = targets[i];
    return 0;
}
static void forwarding(void) {
    SceKernelModuleInfo info;
    SceUID modules[256]; SceSize count = 256;
    assert(tls_fixer_native_module_info(21,22,&info) == 31);
    assert(tls_fixer_native_module_list(21,0xff,1,modules,&count) == 32);
    assert(tls_fixer_native_module_unload(21,22,0,NULL) == 33);
    assert(tls_fixer_native_module_shared(21,(void *)(uintptr_t)0x81000000) == 34);
}
int main(void) {
    assert(tls_fixer_native_module_info(0,0,NULL) < 0);
    const uint32_t identities[] = {0x726c6635,0xa5a80af8,0xb87084f7,0x781c6f50,0x8f483354};
    for (size_t i = 0; i < sizeof(identities)/sizeof(identities[0]); ++i) {
        identity_nid = identities[i]; family = i < 2 ? 0 : 1; bad_identity = 0;
        lookup_count = 0; fail_index = -1;
        assert(tls_fixer_native_module_api_init() == 0 && lookup_count == 4);
        forwarding();
        for (fail_index = 0; fail_index < 4; ++fail_index) {
            lookup_count = 0;
            assert(tls_fixer_native_module_api_init() < 0);
            assert(tls_fixer_native_module_info(0,0,NULL) < 0);
            assert(tls_fixer_native_module_list(0,0,0,NULL,NULL) < 0);
            assert(tls_fixer_native_module_unload(0,0,0,NULL) < 0);
            assert(tls_fixer_native_module_shared(0,NULL) < 0);
        }
    }
    identity_nid = 0; lookup_count = 0;
    assert(tls_fixer_native_module_api_init() < 0 && lookup_count == 0);
    identity_nid = 0x726c6635; bad_identity = 1;
    assert(tls_fixer_native_module_api_init() < 0 && lookup_count == 0);
    puts("native module APIs: identity-selected export families, forwarding and failed publication PASS");
    return 0;
}
