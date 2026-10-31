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
static int consumer_import_queries;
static int consumer_private, consumer_bad_span, consumer_bad_type;
static int consumer_missing_block, consumer_block_error, consumer_type_error, consumer_shared_queries;
static int consumer_data_shared, consumer_no_text, consumer_extra_segment;
static uintptr_t consumer_text_start = 0x81000000;
static uint32_t consumer_text_size = 0x2000, consumer_text_perms = 5;
static const char *consumer_name = "shared_http_user";
static uint8_t import_header[0x34];
static uintptr_t import_begin = 0x81010000, import_end = 0x81010034;
static int provider_query, provider_lookup_result, provider_uid = 22, provider_bad_name;
static uintptr_t http_exports = 0x81010000;
static int http_block = 77, http_type_result, http_block_queries;
static unsigned int http_block_type = 0x0C20D050;

SceUID ksceKernelFindMemBlockByAddrForPid(SceUID pid, const void *address, SceSize size) {
    if (consumer_query) {
        assert(pid == 21 && size == 0);
        if (consumer_missing_block) return 0;
        if (consumer_block_error) return consumer_block_error;
        uintptr_t a = (uintptr_t)address;
        uintptr_t last = consumer_text_start + consumer_text_size - 1;
        if (consumer_bad_span && a == last) return 91;
        if (a == consumer_text_start || a == last) return 77;
        if (a == 0x81002000 || a == 0x81002fff) return 78;
        assert(0);
    }
    assert(provider_query && pid == 21 && (uintptr_t)address == http_exports && size == 0);
    ++http_block_queries;
    return http_block;
}
int ksceKernelGetMemBlockType(SceUID block, unsigned int *type) {
    if (consumer_query) {
        assert((block == 77 || block == 78) && type != NULL);
        if (consumer_type_error) return consumer_type_error;
        *type = !consumer_private || consumer_bad_type ? 0x0320d050 : block == 77 ? 0x0c20d050 : 0x0c20d060;
        if (block == 78 && consumer_data_shared) *type = 0x0320d060;
        return 0;
    }
    assert(provider_query && block == 77 && type != NULL);
    *type = http_block_type;
    return http_type_result;
}

static int fake_info(SceUID pid, SceUID module, SceKernelModuleInfo *info) {
    assert(pid == 21 && module == 22 && info != NULL);
    if (consumer_query) {
        assert(info->size == sizeof(*info));
        info->modid = 22;
        info->modattr = consumer_attributes;
        strcpy(info->module_name, consumer_name);
        info->segments[0].vaddr = (void *)consumer_text_start;
        {
            info->segments[0].memsz = consumer_no_text ? 0 : consumer_text_size;
            info->segments[0].perms = consumer_text_perms;
            info->segments[1].vaddr=(void *)(uintptr_t)0x81002000;
            info->segments[1].memsz=0x1000; info->segments[1].perms=6;
            if (consumer_extra_segment) {
                info->segments[2].vaddr = (void *)(uintptr_t)0x81004000;
                info->segments[2].memsz = 0x1000;
                info->segments[2].perms = 4; /* Unrecognized allocation permission. */
            }
        }
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
    if (consumer_query) { ++consumer_shared_queries; return consumer_sharing; }
    return 34;
}
int taiGetModuleInfoForKernel(SceUID pid, const char *name, tai_module_info_t *info) {
    if (provider_query) {
        assert(pid == 21 && strcmp(name, "SceLibHttp") == 0 && info->size == sizeof(*info));
        info->modid = provider_uid;
        info->exports_start = http_exports;
        strcpy(info->name, provider_bad_name ? "SceOther" : "SceLibHttp");
        return provider_lookup_result;
    }
    if (consumer_query && pid == 21) {
        assert(strcmp(name, consumer_name) == 0 && info->size == sizeof(*info));
        ++consumer_import_queries;
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
        (uintptr_t)fake_shared, (uintptr_t)ksceKernelGetMemBlockType};
    assert(pid == KERNEL_PID);
    int i = lookup_count++;
    assert(i < 5);
    if (i < 4) {
        assert(strcmp(name, "SceKernelModulemgr") == 0);
        assert(library == (family ? UINT32_C(0x92c9ffc2) : UINT32_C(0xc445fa63)));
        assert(function == nids[family][i]);
    } else {
        assert(strcmp(name, "SceSysmem") == 0);
        assert(library == (family ? UINT32_C(0x02451f0f) : UINT32_C(0x63a519e5)));
        assert(function == (family ? UINT32_C(0xd44fe44b) : UINT32_C(0x289be3ec)));
    }
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
    assert(tls_fixer_native_http_requires_sony(21, &consumer) == 1);
    assert(consumer.module == 22 && consumer.library == library && consumer.attributes == 0x200);
    assert(strcmp(consumer.name, "shared_http_user") == 0);
    library = UINT32_C(0xcaf5f2e9); memcpy(import_header + 16, &library, 4);
    assert(tls_fixer_native_http_requires_sony(21, NULL) == 1);
    import_header[0] = 0x24; import_end = import_begin + 0x24;
    memcpy(import_header + 12, &library, 4);
    assert(tls_fixer_native_http_requires_sony(21, NULL) == 1);
    library = 0x12345678; memcpy(import_header + 12, &library, 4);
    assert(tls_fixer_native_http_requires_sony(21, NULL) == 0);
    consumer_attributes = 0x1000; consumer_sharing = 0;
    library = UINT32_C(0xe8f15cde); memcpy(import_header + 12, &library, 4);
    assert(tls_fixer_native_http_requires_sony(21, NULL) == 0);
    consumer_name = "ScePspemu";
    consumer_import_queries = 0;
    assert(tls_fixer_native_http_requires_sony(21, &consumer) == 1);
    assert(consumer.module == 22 && consumer.attributes == 0x1000);
    assert(strcmp(consumer.name, "ScePspemu") == 0 && consumer.library == 0);
    assert(consumer_import_queries == 0);
    assert(tls_fixer_native_http_requires_sony(21, NULL) == 1);
    consumer_name = "ScePspemuHelper";
    assert(tls_fixer_native_http_requires_sony(21, NULL) == 0);
    consumer_name = "Adrenaline";
    assert(tls_fixer_native_http_requires_sony(21, NULL) == 0);
    assert(consumer_import_queries == 2);
    consumer_name = "shared_http_user";
    consumer_attributes = 0x200; consumer_sharing = -9;
    assert(tls_fixer_native_http_requires_sony(21, NULL) < 0);
    consumer_sharing = 2;
    assert(tls_fixer_native_http_requires_sony(21, NULL) < 0);
    consumer_sharing = 1;
    consumer_name = "SceLibHttp";
    assert(tls_fixer_native_http_requires_sony(21, NULL) == 0);
    consumer_name = "shared_http_user";
    import_header[0] = 0;
    assert(tls_fixer_native_http_requires_sony(21, NULL) < 0);
    import_header[0] = 0x24;
    import_end = import_begin + 19;
    assert(tls_fixer_native_http_requires_sony(21, NULL) < 0);
    import_end = import_begin - 1;
    assert(tls_fixer_native_http_requires_sony(21, NULL) < 0);
    import_end = import_begin + 65537;
    assert(tls_fixer_native_http_requires_sony(21, NULL) < 0);
    import_end = import_begin + 0x34; import_header[0] = 0x34;
    library = UINT32_C(0xe8f15cde); memcpy(import_header + 16, &library, 4);
    wrong_import_uid = 1;
    assert(tls_fixer_native_http_requires_sony(21, NULL) < 0);
    wrong_import_uid = 0; copy_result = -9;
    assert(tls_fixer_native_http_requires_sony(21, NULL) < 0);
    copy_result = 0; imports_result = -9;
    assert(tls_fixer_native_http_requires_sony(21, NULL) < 0);
    imports_result = 0; info_result = -9;
    assert(tls_fixer_native_http_requires_sony(21, NULL) < 0);
    info_result = 0; list_result = -9;
    assert(tls_fixer_native_http_requires_sony(21, NULL) < 0);
    list_result = 0; consumer_count = 256;
    assert(tls_fixer_native_http_requires_sony(21, NULL) < 0);
    consumer_count = 0;
    assert(tls_fixer_native_http_requires_sony(21, NULL) < 0);
    consumer_count = 1;
#if TLS_FIXER_PRIVATE_GUI_CLIENTS
    /* CommonDialog has no direct HTTP import, but its shared PAF dependency
     * blocks a later private PAF. Catch it before privatizing HTTP. */
    library = UINT32_C(0x3d643ce8); memcpy(import_header + 16, &library, 4);
    consumer_sharing = 1;
    assert(tls_fixer_native_http_requires_sony(21, NULL) == 1);
    consumer_private = 1;
    assert(tls_fixer_native_http_requires_sony(21, NULL) == 0);
    consumer_private = 0;
    library = UINT32_C(0x68d6c3ff); memcpy(import_header + 16, &library, 4);
    assert(tls_fixer_native_http_requires_sony(21, NULL) == 1);
    library = UINT32_C(0xe8f15cde); memcpy(import_header + 16, &library, 4);
    consumer_private = 1; consumer_sharing = 1;
    assert(tls_fixer_native_http_requires_sony(21, NULL) == 0);
    consumer_bad_span = 1;
    assert(tls_fixer_native_http_requires_sony(21, NULL) == 1);
    consumer_bad_span = 0; consumer_bad_type = 1;
    assert(tls_fixer_native_http_requires_sony(21, NULL) == 1);
    consumer_bad_type = 0; consumer_private = 0;
#endif
    consumer_query = 0;
}
static void provider_checks(void) {
    provider_query = 1;
    provider_lookup_result = 0; provider_uid = 22; provider_bad_name = 0;
    assert(tls_fixer_native_http_is_private(21) == 1);
    assert(tls_fixer_native_http_mapping(21) == 1);
    http_exports = 0xE0100000; http_block_queries = 0;
    assert(tls_fixer_native_http_mapping(21) == 2);
    assert(tls_fixer_native_http_is_private(21) == 0 && http_block_queries == 0);
    http_exports = 0;
    assert(tls_fixer_native_http_is_private(21) < 0);
    http_exports = 0x81010000; http_block_type = 0x0320D050;
    assert(tls_fixer_native_http_is_private(21) == 0);
    http_block_type = 0x0C20D060;
    assert(tls_fixer_native_http_is_private(21) == 0);
    http_block_type = 0x0C20D050; http_block = -19;
    assert(tls_fixer_native_http_is_private(21) == -19);
    http_block = 0;
    assert(tls_fixer_native_http_is_private(21) < 0);
    http_block = 77; http_type_result = -20;
    assert(tls_fixer_native_http_is_private(21) == -20);
    http_type_result = 1;
    assert(tls_fixer_native_http_is_private(21) < 0);
    http_type_result = 0;
    assert(tls_fixer_native_http_is_private(0) < 0);
    provider_lookup_result = (int32_t)UINT32_C(0x90010002);
    assert(tls_fixer_native_http_mapping(21) == 0);
    assert(tls_fixer_native_http_is_private(21) == 0);
    provider_lookup_result = -42;
    assert(tls_fixer_native_http_is_private(21) == -42);
    provider_lookup_result = 1;
    assert(tls_fixer_native_http_is_private(21) < 0);
    provider_lookup_result = 0; provider_uid = 0;
    assert(tls_fixer_native_http_is_private(21) < 0);
    provider_uid = 22; provider_bad_name = 1;
    assert(tls_fixer_native_http_is_private(21) < 0);
    provider_query = 0;
}
int main(void) {
    assert(tls_fixer_native_module_info(0,0,NULL) < 0);
    const uint32_t identities[] = {0x726c6635,0xa5a80af8,0xb87084f7,0x781c6f50,0x8f483354};
    for (size_t i = 0; i < sizeof(identities)/sizeof(identities[0]); ++i) {
        identity_nid = identities[i]; family = i < 2 ? 0 : 1; bad_identity = 0;
        lookup_count = 0; fail_index = -1;
        assert(tls_fixer_native_module_api_init() == 0 && lookup_count == 5);
        forwarding();
        consumer_checks();
        provider_checks();
        for (fail_index = 0; fail_index < 5; ++fail_index) {
            lookup_count = 0;
            assert(tls_fixer_native_module_api_init() < 0);
            assert(tls_fixer_native_module_info(0,0,NULL) < 0);
            assert(tls_fixer_native_module_list(0,0,0,NULL,NULL) < 0);
            assert(tls_fixer_native_module_unload(0,0,0,NULL) < 0);
            assert(tls_fixer_native_module_shared(0,NULL) < 0);
            assert(tls_fixer_native_http_requires_sony(21, NULL) < 0);
            assert(tls_fixer_native_http_is_private(21) < 0);
        }
    }
    identity_nid = 0; lookup_count = 0;
    assert(tls_fixer_native_module_api_init() < 0 && lookup_count == 0);
    identity_nid = 0x726c6635; bad_identity = 1;
    assert(tls_fixer_native_module_api_init() < 0 && lookup_count == 0);
    puts("native module APIs: identity-selected export families, forwarding and failed publication PASS");
    return 0;
}
