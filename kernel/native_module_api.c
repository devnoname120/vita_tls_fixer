#include "native_module_api.h"
#include "tls_fixer/firmware_profiles.h"
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/threadmgr/misc.h>
#include <taihen.h>

/* Exported by taihenModuleUtils, although omitted from the public header. */
int module_get_export_func(SceUID pid, const char *module, uint32_t library,
    uint32_t function, uintptr_t *address);

static int (*get_info)(SceUID, SceUID, SceKernelModuleInfo *);
static int (*get_list)(SceUID, int, int, SceUID *, SceSize *);
static int (*unload_module)(SceUID, SceUID, int, const void *);
static int (*is_shared)(SceUID, void *);
static int (*get_memblock_type)(SceUID, unsigned int *);
static int ready;

int tls_fixer_native_module_api_init(void) {
    tai_module_info_t identity;
    const TlsFixerKernelProfile *profile = NULL;
    static const uint32_t libraries[] = {UINT32_C(0xc445fa63), UINT32_C(0x92c9ffc2)};
    static const uint32_t nids[2][4] = {
        {0xd269f915, 0x97cf7b4e, 0x5972e2cc, 0x99890202},
        {0xdaa90093, 0xb72c75a4, 0xfca9fdb1, 0xf1de6949}
    };
    static const uint32_t sysmem_libraries[] = {UINT32_C(0x63a519e5), UINT32_C(0x02451f0f)};
    static const uint32_t sysmem_type_nids[] = {UINT32_C(0x289be3ec), UINT32_C(0xd44fe44b)};
    uintptr_t addresses[5] = {0};
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
    if (module_get_export_func(KERNEL_PID, "SceSysmem", sysmem_libraries[profile->family],
            sysmem_type_nids[profile->family], &addresses[4]) < 0 || addresses[4] == 0) return -1;
    get_info = (int (*)(SceUID, SceUID, SceKernelModuleInfo *))addresses[0];
    get_list = (int (*)(SceUID, int, int, SceUID *, SceSize *))addresses[1];
    unload_module = (int (*)(SceUID, SceUID, int, const void *))addresses[2];
    is_shared = (int (*)(SceUID, void *))addresses[3];
    get_memblock_type = (int (*)(SceUID, unsigned int *))addresses[4];
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

typedef struct ConsumerQuery {
    SceUID pid;
    int called;
    int result;
    TlsFixerNativeHttpConsumer *consumer;
} ConsumerQuery;

static int query_native_http_consumers(void *argument) {
    ConsumerQuery *query = argument;
    SceUID modules[256];
    SceSize count = sizeof(modules) / sizeof(modules[0]);
    query->called = 1;
    if (query->consumer != NULL) query->consumer->step = 1;
    int result = get_list(query->pid, 0xff, 1, modules, &count);
    if (query->consumer != NULL) query->consumer->native_result = result;
    if (result != 0 || count == 0 || count >= 256) return 0;
    for (SceSize i = 0; i < count; ++i) {
        SceKernelModuleInfo info;
        memset(&info, 0, sizeof(info));
        info.size = sizeof(info);
        if (query->consumer != NULL) {
            query->consumer->step = 2;
            query->consumer->module = modules[i];
        }
        result = get_info(query->pid, modules[i], &info);
        if (query->consumer != NULL) query->consumer->native_result = result;
        if (result != 0 || info.modid <= 0 ||
            info.module_name[sizeof(info.module_name) - 1] != '\0') return 0;
        /* Adrenaline replaces the PSP emulator's title-info initializer without
         * its native join. Its main thread can then call ScreenShot while the
         * title thread is still loading HTTP, before ScreenShot is loaded.
         * Starting our provider here exposes that race. Match the actual
         * emulator, not its title ID: the separate downloader can still use TLS. */
        if (strcmp(info.module_name, "ScePspemu") == 0) {
            if (query->consumer != NULL) {
                query->consumer->module = info.modid;
                query->consumer->attributes = info.modattr;
                memcpy(query->consumer->name, info.module_name, sizeof(info.module_name));
                query->consumer->step = 6;
            }
            query->result = 1;
            return 0;
        }
        /* modattr is the declared SELF attribute, not the native loader's
         * internal mode word. Inspect all importers. The paired transports
         * and our own provider have independent exact/private mapping gates. */
        if (strcmp(info.module_name, "SceLibHttp") == 0 ||
            strcmp(info.module_name, "SceLibSsl") == 0 ||
            strcmp(info.module_name, "tls_fixer_http") == 0) continue;
        tai_module_info_t imports;
        memset(&imports, 0, sizeof(imports));
        imports.size = sizeof(imports);
        if (query->consumer != NULL) query->consumer->step = 3;
        result = taiGetModuleInfoForKernel(query->pid, info.module_name, &imports);
        if (query->consumer != NULL) query->consumer->native_result = result;
        if (result < 0 ||
            imports.modid != info.modid || imports.imports_end < imports.imports_start ||
            imports.imports_end - imports.imports_start > 65536) return 0;
        uintptr_t cursor = imports.imports_start;
        while (cursor < imports.imports_end) {
            uint8_t header[20];
            uint16_t size;
            uint32_t library;
            if (query->consumer != NULL) query->consumer->step = 4;
            if (imports.imports_end - cursor < sizeof(header)) return 0;
            result = ksceKernelCopyFromUserProc(query->pid, header, (void *)cursor, sizeof(header));
            if (query->consumer != NULL) query->consumer->native_result = result;
            if (result < 0) return 0;
            memcpy(&size, header, sizeof(size));
            if ((size != 0x24 && size != 0x34) || size > imports.imports_end - cursor) return 0;
            memcpy(&library, header + (size == 0x34 ? 16 : 12), sizeof(library));
            if (library == UINT32_C(0xe8f15cde) || library == UINT32_C(0xcaf5f2e9)) {
                if (query->consumer != NULL) query->consumer->step = 5;
                if (info.segments[0].vaddr == NULL) return 0;
                result = is_shared(query->pid, info.segments[0].vaddr);
                if (query->consumer != NULL) query->consumer->native_result = result;
                if (result != 0 && result != 1) return 0;
                if (result == 0) { cursor += size; continue; }
                if (query->consumer != NULL) {
                    query->consumer->module = info.modid;
                    query->consumer->attributes = info.modattr;
                    query->consumer->library = library;
                    memcpy(query->consumer->name, info.module_name, sizeof(info.module_name));
                    query->consumer->step = 6;
                }
                query->result = 1;
                return 0;
            }
            cursor += size;
        }
    }
    query->result = 0;
    if (query->consumer != NULL) query->consumer->step = 7;
    return 0;
}

int tls_fixer_native_http_requires_sony(SceUID pid, TlsFixerNativeHttpConsumer *consumer) {
    if (consumer != NULL) memset(consumer, 0, sizeof(*consumer));
    if (!__atomic_load_n(&ready, __ATOMIC_ACQUIRE) || pid <= 0) return -1;
    ConsumerQuery query = {pid, 0, -1, consumer};
#if defined(__arm__)
    /* Library-load hooks run before the native load routine takes its process
     * module lock. Keep bounded metadata inspection off the caller's stack. */
    int result = ksceKernelRunWithStack(16384, query_native_http_consumers, &query);
    if (result < 0) {
        if (consumer != NULL) consumer->native_result = result;
        return result;
    }
#else
    (void)query_native_http_consumers(&query);
#endif
    return query.called ? query.result : -1;
}

typedef struct HttpMappingQuery {
    SceUID pid;
    int called;
    int result;
} HttpMappingQuery;

static int query_http_mapping(void *argument) {
    HttpMappingQuery *query = argument;
    tai_module_info_t info;
    memset(&info, 0, sizeof(info)); info.size = sizeof(info);
    query->called = 1;
    int result = taiGetModuleInfoForKernel(query->pid, "SceLibHttp", &info);
    if (result == (int32_t)UINT32_C(0x90010002)) { query->result = 0; return 0; }
    if (result != 0) { query->result = result < 0 ? result : -1; return 0; }
    if (info.modid <= 0 || info.exports_start == 0 ||
        memcmp(info.name, "SceLibHttp", sizeof("SceLibHttp")) != 0) return 0;
    if (info.exports_start < UINT32_C(0x80000000) || info.exports_start >= UINT32_C(0xE0000000)) {
        query->result = 0;
        return 0;
    }
    SceUID block = ksceKernelFindMemBlockByAddrForPid(query->pid, (void *)info.exports_start, 0);
    if (block <= 0) { query->result = block < 0 ? block : -1; return 0; }
    unsigned int type = 0;
    result = get_memblock_type(block, &type);
    if (result != 0) { query->result = result < 0 ? result : -1; return 0; }
    /* Same allocator-confirmed RX type used by the user provider's gate.
     * This also preserves bindings if provider startup fell back to Sony. */
    query->result = type == UINT32_C(0x0C20D050);
    return 0;
}

int tls_fixer_native_http_is_private(SceUID pid) {
    if (!__atomic_load_n(&ready, __ATOMIC_ACQUIRE) || pid <= 0) return -1;
    HttpMappingQuery query = {pid, 0, -1};
#if defined(__arm__)
    int result = ksceKernelRunWithStack(16384, query_http_mapping, &query);
    if (result < 0) return result;
#else
    (void)query_http_mapping(&query);
#endif
    return query.called ? query.result : -1;
}
