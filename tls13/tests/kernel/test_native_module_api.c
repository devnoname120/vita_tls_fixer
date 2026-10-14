#include "native_module_api.h"
#include <taihen.h>
#include <assert.h>
#include <stdio.h>

static uint32_t identity_nid;
static int family, fail_index, lookup_count, bad_identity;
static int consumer_query, list_result, info_result, imports_result, copy_result, wrong_import_uid;
static SceSize consumer_count = 1;
static uint16_t consumer_attributes = 0x200;
static int consumer_sharing = 1;
static const char *consumer_name = "shared_http_user";
static uint8_t import_header[0x34];
static uintptr_t import_begin = 0x81010000, import_end = 0x81010034;

static int fake_info(SceUID pid, SceUID module, SceKernelModuleInfo *info) {
    assert(pid == 21 && module == 22 && info != NULL);
    if (consumer_query) {
        assert(info->size == sizeof(*info));
        info->modid = 22;
        info->modattr = consumer_attributes;
        strcpy(info->module_name, consumer_name);
        info->segments[0].vaddr = (void *)(uintptr_t)0x81000000;
        return info_result;
    }
    return 31;
}
static int fake_list(SceUID pid, int a, int b, SceUID *modules, SceSize *count) {
    assert(pid == 21 && a == 0xff && b == 1 && modules != NULL && *count == 256);
    if (consumer_query) { modules[0] = 22; *count = consumer_count; return list_result; }
    return 32;
}
static int fake_unload(SceUID pid, SceUID module, int flags, const void *options) {
    assert(pid == 21 && module == 22 && flags == 0 && options == NULL);
    return 33;
}
static int fake_shared(SceUID pid, void *address) {
    assert(pid == 21 && address == (void *)(uintptr_t)0x81000000);
    if (consumer_query) return consumer_sharing;
    return 34;
}
int taiGetModuleInfoForKernel(SceUID pid, const char *name, tai_module_info_t *info) {
    if (consumer_query && pid == 21) {
        assert(strcmp(name, "shared_http_user") == 0 && info->size == sizeof(*info));
        info->modid = wrong_import_uid ? 23 : 22;
        info->imports_start = import_begin; info->imports_end = import_end;
        return imports_result;
    }
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
    uintptr_t targets[] = {(uintptr_t)fake_info,(uintptr_t)fake_list,(uintptr_t)fake_unload,
        (uintptr_t)fake_shared};
    assert(pid == KERNEL_PID && strcmp(name, "SceKernelModulemgr") == 0);
    assert(library == (family ? UINT32_C(0x92c9ffc2) : UINT32_C(0xc445fa63)));
    int i = lookup_count++;
    assert(i < 4 && function == nids[family][i]);
    if (i == fail_index) return -123;
    *address = targets[i];
    return 0;
}
static void forwarding(void) {
    consumer_query = 0;
    SceKernelModuleInfo info;
    SceUID modules[256]; SceSize count = 256;
    assert(tls_fixer_native_module_info(21,22,&info) == 31);
    assert(tls_fixer_native_module_list(21,0xff,1,modules,&count) == 32);
    assert(tls_fixer_native_module_unload(21,22,0,NULL) == 33);
    assert(tls_fixer_native_module_shared(21,(void *)(uintptr_t)0x81000000) == 34);
}
int ksceKernelCopyFromUserProc(SceUID pid, void *destination, const void *source, SceSize size) {
    assert(pid == 21 && consumer_query && size == 20 && (uintptr_t)source == import_begin);
    if (copy_result < 0) return copy_result;
    memcpy(destination, import_header, size);
    return 0;
}
static void consumer_checks(void) {
    TlsFixerNativeHttpConsumer consumer;
    consumer_query = 1;
    memset(import_header, 0, sizeof(import_header));
    import_header[0] = 0x34;
    uint32_t library = UINT32_C(0xe8f15cde);
    memcpy(import_header + 16, &library, 4);
    assert(tls_fixer_native_http_shared_consumer(21, &consumer) == 1);
    assert(consumer.module == 22 && consumer.library == library && consumer.attributes == 0x200);
    assert(strcmp(consumer.name, "shared_http_user") == 0);
    library = UINT32_C(0xcaf5f2e9); memcpy(import_header + 16, &library, 4);
    assert(tls_fixer_native_http_shared_consumer(21, NULL) == 1);
    import_header[0] = 0x24; import_end = import_begin + 0x24;
    memcpy(import_header + 12, &library, 4);
    assert(tls_fixer_native_http_shared_consumer(21, NULL) == 1);
    library = 0x12345678; memcpy(import_header + 12, &library, 4);
    assert(tls_fixer_native_http_shared_consumer(21, NULL) == 0);
    consumer_attributes = 0x1000; consumer_sharing = 0;
    library = UINT32_C(0xe8f15cde); memcpy(import_header + 12, &library, 4);
    assert(tls_fixer_native_http_shared_consumer(21, NULL) == 0);
    consumer_attributes = 0x200; consumer_sharing = -9;
    assert(tls_fixer_native_http_shared_consumer(21, NULL) < 0);
    consumer_sharing = 2;
    assert(tls_fixer_native_http_shared_consumer(21, NULL) < 0);
    consumer_sharing = 1;
    consumer_name = "SceLibHttp";
    assert(tls_fixer_native_http_shared_consumer(21, NULL) == 0);
    consumer_name = "shared_http_user";
    import_header[0] = 0;
    assert(tls_fixer_native_http_shared_consumer(21, NULL) < 0);
    import_header[0] = 0x24;
    import_end = import_begin + 19;
    assert(tls_fixer_native_http_shared_consumer(21, NULL) < 0);
    import_end = import_begin - 1;
    assert(tls_fixer_native_http_shared_consumer(21, NULL) < 0);
    import_end = import_begin + 65537;
    assert(tls_fixer_native_http_shared_consumer(21, NULL) < 0);
    import_end = import_begin + 0x34; import_header[0] = 0x34;
    library = UINT32_C(0xe8f15cde); memcpy(import_header + 16, &library, 4);
    wrong_import_uid = 1;
    assert(tls_fixer_native_http_shared_consumer(21, NULL) < 0);
    wrong_import_uid = 0; copy_result = -9;
    assert(tls_fixer_native_http_shared_consumer(21, NULL) < 0);
    copy_result = 0; imports_result = -9;
    assert(tls_fixer_native_http_shared_consumer(21, NULL) < 0);
    imports_result = 0; info_result = -9;
    assert(tls_fixer_native_http_shared_consumer(21, NULL) < 0);
    info_result = 0; list_result = -9;
    assert(tls_fixer_native_http_shared_consumer(21, NULL) < 0);
    list_result = 0; consumer_count = 256;
    assert(tls_fixer_native_http_shared_consumer(21, NULL) < 0);
    consumer_count = 0;
    assert(tls_fixer_native_http_shared_consumer(21, NULL) < 0);
    consumer_count = 1; consumer_query = 0;
}
int main(void) {
    assert(tls_fixer_native_module_info(0,0,NULL) < 0);
    const uint32_t identities[] = {0x726c6635,0xa5a80af8,0xb87084f7,0x781c6f50,0x8f483354};
    for (size_t i = 0; i < sizeof(identities)/sizeof(identities[0]); ++i) {
        identity_nid = identities[i]; family = i < 2 ? 0 : 1; bad_identity = 0;
        lookup_count = 0; fail_index = -1;
        assert(tls_fixer_native_module_api_init() == 0 && lookup_count == 4);
        forwarding();
        consumer_checks();
        for (fail_index = 0; fail_index < 4; ++fail_index) {
            lookup_count = 0;
            assert(tls_fixer_native_module_api_init() < 0);
            assert(tls_fixer_native_module_info(0,0,NULL) < 0);
            assert(tls_fixer_native_module_list(0,0,0,NULL,NULL) < 0);
            assert(tls_fixer_native_module_unload(0,0,0,NULL) < 0);
            assert(tls_fixer_native_module_shared(0,NULL) < 0);
            assert(tls_fixer_native_http_shared_consumer(21, NULL) < 0);
        }
    }
    identity_nid = 0; lookup_count = 0;
    assert(tls_fixer_native_module_api_init() < 0 && lookup_count == 0);
    identity_nid = 0x726c6635; bad_identity = 1;
    assert(tls_fixer_native_module_api_init() < 0 && lookup_count == 0);
    puts("native module APIs: identity-selected export families, forwarding and failed publication PASS");
    return 0;
}
