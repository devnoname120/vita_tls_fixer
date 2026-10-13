#include "tls13_loader.h"
#include "tls_fixer/browser_abi.h"
#include "tls_fixer/sony_abi.h"
#include "boot_trace.h"
#include <kernel_mock.h>
#include "tls_fixer/browser_start_diagnostics.h"
#include <assert.h>
#include <stdio.h>

#ifndef TLS_FIXER_PREPARE_ONLY
#define TLS_FIXER_PREPARE_ONLY 0
#endif
#ifndef TLS_FIXER_PREPARE_EXTENDED_STACK
#define TLS_FIXER_PREPARE_EXTENDED_STACK 0
#endif
#ifndef TLS_FIXER_PREPARE_NO_MODULE_QUERIES
#define TLS_FIXER_PREPARE_NO_MODULE_QUERIES 0
#endif
#ifndef TLS_FIXER_PREPARE_TARGET_QUERY_ONLY
#define TLS_FIXER_PREPARE_TARGET_QUERY_ONLY 0
#endif
#ifndef TLS_FIXER_PREPARE_LIST_TARGET_ONLY
#define TLS_FIXER_PREPARE_LIST_TARGET_ONLY 0
#endif
#ifndef TLS_FIXER_PREPARE_NAME_QUERY
#define TLS_FIXER_PREPARE_NAME_QUERY 0
#endif
#if TLS_FIXER_PREPARE_NAME_QUERY
#include <taihen.h>
#endif

static const uint8_t http_hash[32] = {
    0x42,0xbc,0x7e,0x34,0x07,0x79,0x64,0xac,0x7e,0xdc,0x43,0x65,0xab,0xad,0x8a,0xf9,
    0xbf,0x41,0x79,0x3a,0x34,0xd2,0xc7,0xef,0xd6,0x31,0x97,0x6f,0x7d,0x27,0x39,0xc1};
static const uint8_t compat_hash[32] = {
    0x73,0x88,0x62,0x13,0x38,0x19,0xfc,0x37,0xbc,0x21,0xf7,0x14,0xda,0x7c,0xa7,0x6c,
    0x72,0xd7,0x3a,0x62,0x0a,0xfa,0xfb,0xe6,0xa9,0x40,0xd8,0x7d,0xd4,0xe6,0xdc,0x58};
static int browser_file = 1, http_file = 1, corrupt_browser, corrupt_http;
static int read_once[2], locked, mutex_live, loads, unloads, scan_error, saturated, module_info_error;
static int load_error, start_error, reenter, close_error;
static int target_info_error, target_user_id = 188;
static int target_wrong_name;
static unsigned int target_queries;
static unsigned int list_queries;
static int list_count_override = -1;
static const char *loaded_name = "";
static const char *expected_path;
static const char *expected_module_path;
static int runtime_namespace_required, namespace_provider_error, namespace_hash_error;
static int namespace_stat_error, namespace_close_error;
static unsigned int namespace_provider_opens, namespace_hash_opens;
static unsigned int global_provider_stats;
static unsigned int stream_blocks = 1;
static int open_descriptors;
static _Alignas(16) unsigned char hash_memory[4096];
static int workspace_live, alloc_fail, base_fail, null_base, free_fail;
static unsigned int allocations, frees;
static _Alignas(16) unsigned char query_memory[4096];
static int query_live, query_alloc_fail, query_base_fail, query_null_base, query_free_fail;
static unsigned int query_allocations, query_frees;
static unsigned int stack_calls;
static int stack_error, stack_skip, stack_error_after;
static _Alignas(16) unsigned char argument_memory[4096];
static int argument_live, argument_alloc_fail, argument_base_fail, argument_null_base;
static int argument_copy_fail, argument_readback_fail, argument_corrupt, argument_free_fail;
static unsigned int argument_allocations, argument_frees, argument_copies;
static SceUID argument_current_pid = 99;
static const char *process_title = "TLSFIXAPP";
static int process_title_error;
static unsigned int process_title_queries;

#if TLS_FIXER_ENABLE_BOOT_TRACE
static const char *last_stage = "";
static const char *trace_fail;
static unsigned int trace_events;
static int checking_hash_trace;
int tls_fixer_boot_trace_open(void) { return 0; }
int tls_fixer_boot_trace_close(void) { return 0; }
int tls_fixer_boot_trace_event(const char *stage, int32_t pid, int32_t object, int32_t result) {
    (void)object; (void)result;
    assert(!locked && pid == 99);
    last_stage = stage;
    ++trace_events;
    return trace_fail != NULL && strcmp(stage, trace_fail) == 0 ? -1 : 0;
}
static void expect_hash_stage(const char *stage) {
    if (checking_hash_trace) assert(strcmp(last_stage, stage) == 0);
}
#else
static void expect_hash_stage(const char *stage) { (void)stage; }
#endif

static void require_workspace(const void *data, size_t size) {
    uintptr_t address = (uintptr_t)data, base = (uintptr_t)hash_memory;
    assert(workspace_live && address >= base && size <= sizeof(hash_memory));
    assert(address - base <= sizeof(hash_memory) - size);
}

static void require_query_workspace(const void *data, size_t size) {
    uintptr_t address = (uintptr_t)data, base = (uintptr_t)query_memory;
    assert(query_live && address >= base && size <= sizeof(query_memory));
    assert(address - base <= sizeof(query_memory) - size);
}

int ksceKernelRunWithStack(SceSize size, int (*callback)(void *), void *argument) {
    assert(TLS_FIXER_PREPARE_EXTENDED_STACK && size == 16384 && !locked);
    assert(callback != NULL && argument != NULL);
    ++stack_calls;
    if (stack_error) return -141;
    if (stack_skip) return 0;
    assert(callback(argument) == 0);
    return stack_error_after ? -142 : 0;
}

SceUID ksceKernelAllocMemBlock(const char *name, int type, SceSize size, const void *options) {
    assert(!locked);
    if (strcmp(name, "tls_fixer start arguments") == 0) {
        const SceKernelAllocMemBlockKernelOpt *opt = options;
        SceKernelAllocMemBlockKernelOpt expected = {.size = sizeof(expected),
            .attr = SCE_KERNEL_ALLOC_MEMBLOCK_ATTR_HAS_PID, .pid = 99};
        assert(type == SCE_KERNEL_MEMBLOCK_TYPE_USER_RW && size == sizeof(argument_memory));
        assert(opt != NULL && memcmp(opt, &expected, sizeof(expected)) == 0);
        assert(!argument_live && query_live);
        expect_hash_stage("args.alloc.enter");
        if (argument_alloc_fail) return -161;
        memset(argument_memory, 0, sizeof(argument_memory));
        argument_live = 1;
        ++argument_allocations;
        return 44;
    }
    if (strcmp(name, "tls_fixer query workspace") == 0) {
        assert(type == SCE_KERNEL_MEMBLOCK_TYPE_KERNEL_RW);
        assert(size == sizeof(query_memory) && options == NULL && !query_live);
        expect_hash_stage("query.alloc.enter");
        if (query_alloc_fail) return -133;
        ++query_allocations;
        query_live = 1;
        memset(query_memory, 0xa5, sizeof(query_memory));
        return 43;
    }
    assert(strcmp(name, "tls_fixer hash workspace") == 0 && type == SCE_KERNEL_MEMBLOCK_TYPE_KERNEL_RW);
    assert(size == sizeof(hash_memory) && options == NULL && !workspace_live);
    expect_hash_stage("hash.alloc.enter");
    if (alloc_fail) return -123;
    ++allocations;
    workspace_live = 1;
    memset(hash_memory, 0xa5, sizeof(hash_memory));
    return 42;
}

int ksceKernelGetMemBlockBase(SceUID uid, void **base) {
    assert(!locked);
    if (uid == 44) {
        assert(argument_live && base != NULL);
        expect_hash_stage("args.base.enter");
        if (argument_base_fail) return -162;
        *base = argument_null_base ? NULL : argument_memory;
        return 0;
    }
    if (uid == 43) {
        assert(query_live && base != NULL);
        expect_hash_stage("query.base.enter");
        if (query_base_fail) return -134;
        *base = query_null_base ? NULL : query_memory;
        return 0;
    }
    assert(uid == 42 && workspace_live && base != NULL);
    expect_hash_stage("hash.base.enter");
    if (base_fail) return -124;
    *base = null_base ? NULL : hash_memory;
    return 0;
}

int ksceKernelFreeMemBlock(SceUID uid) {
    assert(!locked);
    if (uid == 44) {
        assert(argument_live);
        expect_hash_stage("args.free.enter");
        ++argument_frees;
        argument_live = 0;
        return argument_free_fail ? -165 : 0;
    }
    if (uid == 43) {
        assert(query_live);
        expect_hash_stage("query.free.enter");
        ++query_frees;
        query_live = 0;
        return query_free_fail ? -135 : 0;
    }
    assert(uid == 42 && workspace_live);
    expect_hash_stage("hash.free.enter");
    ++frees;
    workspace_live = 0;
    return free_fail ? -125 : 0;
}

int ksceIoGetstat(const char *path, SceIoStat *status) {
    (void)status;
    expect_hash_stage("hash.stat.enter");
    if (strcmp(path, TLS_FIXER_BROWSER_PROVIDER_BOOT_PATH) == 0) {
        if (query_live) ++global_provider_stats;
        return namespace_provider_error || !browser_file ? -151 : 0;
    }
    if (runtime_namespace_required && query_live && strstr(path, "/" TLS_FIXER_BROWSER_PROVIDER_FILENAME))
        return (int32_t)UINT32_C(0x80010002);
    return (strstr(path, "/" TLS_FIXER_BROWSER_PROVIDER_FILENAME) ? browser_file : http_file) ? 0 : -1;
}
int ksceIoOpen(const char *path, int flags, int mode) {
    int index = strstr(path, "ScePsp2Compat") != NULL;
    (void)flags; (void)mode;
    expect_hash_stage("hash.open.enter");
    if (runtime_namespace_required && query_live && index)
        return (int32_t)UINT32_C(0x80010002);
    read_once[index] = 0;
    ++open_descriptors;
    return index + 10;
}
SceUID ksceIoOpenForPid(SceUID pid, const char *path, int flags, unsigned int mode) {
    assert(pid == 99 && flags == SCE_O_RDONLY && mode == 0 && query_live && !locked);
    if (strcmp(path, TLS_FIXER_BROWSER_PROVIDER_BOOT_PATH) == 0)
        return (int32_t)UINT32_C(0x80010013);
    if (strcmp(path, expected_path) == 0) {
        expect_hash_stage("hash.stat.enter");
        ++namespace_provider_opens;
        if (namespace_provider_error || !browser_file) return -151;
        ++open_descriptors;
        return 12;
    }
    assert(strcmp(path, expected_module_path) == 0);
    expect_hash_stage("hash.open.enter");
    ++namespace_hash_opens;
    if (namespace_hash_error) return -152;
    read_once[1] = 0;
    ++open_descriptors;
    return 11;
}
int ksceIoGetstatByFd(SceUID fd, SceIoStat *status) {
    assert(fd == 12 && open_descriptors > 0 && status != NULL && !locked);
    expect_hash_stage("hash.stat.enter");
    return namespace_stat_error ? -153 : 0;
}
int ksceIoRead(int fd, void *data, unsigned int size) {
    assert(fd >= 10 && fd <= 11 && size >= 1);
    require_workspace(data, size);
    if (read_once[fd-10] == 0) expect_hash_stage("hash.read.enter");
    if ((unsigned int)read_once[fd-10]++ >= stream_blocks) return 0;
    *(uint8_t *)data = (uint8_t)(fd - 10);
    return 1;
}
int ksceIoClose(int fd) {
    assert(fd >= 10 && fd <= 12 && open_descriptors > 0);
    if (fd == 12) {
        expect_hash_stage("hash.stat.enter");
        --open_descriptors;
        return namespace_close_error ? -154 : 0;
    }
    expect_hash_stage("hash.close.enter");
    --open_descriptors;
    return close_error ? -1 : 0;
}
int ksceSha256BlockInit(SceSha256Context *context) {
    expect_hash_stage("hash.init.enter");
    require_workspace(context, sizeof(*context));
    context->kind = 0;
    return 0;
}
int ksceSha256BlockUpdate(SceSha256Context *context, const void *data, SceSize size) {
    assert(size == 1);
    require_workspace(context, sizeof(*context));
    require_workspace(data, size);
    if (read_once[*(const uint8_t *)data] == 1) expect_hash_stage("hash.update.enter");
    context->kind = *(const uint8_t *)data;
    return 0;
}
int ksceSha256BlockResult(SceSha256Context *context, uint8_t *digest) {
    expect_hash_stage("hash.finish.enter");
    require_workspace(context, sizeof(*context));
    memcpy(digest, context->kind ? compat_hash : http_hash, 32);
    if (context->kind ? corrupt_browser : corrupt_http) digest[0] ^= 1;
    return 0;
}
int timingsafe_memcmp(const void *left, const void *right, size_t size) {
    expect_hash_stage("hash.compare.enter");
    return memcmp(left, right, size);
}
SceUID ksceKernelGetProcessId(void) { return argument_current_pid; }
int ksceKernelSysrootGetProcessTitleId(SceUID pid, char *title, SceSize size) {
    assert(pid == 99 && size == 16 && !locked);
    ++process_title_queries;
    if (process_title_error < 0) return process_title_error;
    memcpy(title, process_title, strlen(process_title) + 1);
    return 0;
}
int ksceKernelCopyToUserProc(SceUID pid, void *destination, const void *source, SceSize size) {
    assert(pid == 99 && argument_live && destination == argument_memory && source != destination);
    assert(size == sizeof(TlsFixerStartArgs) && !locked && query_live);
    expect_hash_stage("args.copy.enter");
    ++argument_copies;
    memcpy(destination, source, size);
    return argument_copy_fail ? -163 : 0;
}
int ksceKernelCopyFromUserProc(SceUID pid, void *destination, const void *source, SceSize size) {
    assert(pid == 99 && argument_live && source == argument_memory);
    assert(size == sizeof(TlsFixerStartArgs) && !locked);
    require_query_workspace(destination, size);
    expect_hash_stage("args.verify.enter");
    memcpy(destination, source, size);
    if (argument_corrupt) *(unsigned char *)destination ^= 1;
    return argument_readback_fail ? -164 : 0;
}
SceUID ksceKernelCreateMutex(const char *name, unsigned int attr, int count, const void *options) {
    (void)name; (void)attr; (void)options;
    assert(!mutex_live && count == 0);
    mutex_live = 1;
    return 1;
}
int ksceKernelDeleteMutex(SceUID id) { assert(id == 1 && mutex_live && !locked); mutex_live = 0; return 0; }
int ksceKernelLockMutex(SceUID id, int count, unsigned int *timeout) {
    assert(id == 1 && count == 1 && timeout == NULL && mutex_live && !locked);
    locked = 1;
    return 0;
}
int ksceKernelUnlockMutex(SceUID id, int count) { assert(id == 1 && count == 1 && locked); locked = 0; return 0; }
int ksceKernelGetModuleList(SceUID pid, unsigned int a, unsigned int b, SceUID *ids, SceSize *count) {
    assert(!TLS_FIXER_PREPARE_NO_MODULE_QUERIES);
    assert(!TLS_FIXER_PREPARE_TARGET_QUERY_ONLY);
    assert(!TLS_FIXER_PREPARE_NAME_QUERY);
    assert(pid == 99 && a == 0xff && b == 1 && *count == 256 && !locked);
    require_query_workspace(ids, *count * sizeof(*ids));
#if TLS_FIXER_ENABLE_BOOT_TRACE
    assert(strcmp(last_stage, "module.list.enter") == 0);
#endif
    ++list_queries;
    if (scan_error) return -1;
    SceSize returned = list_count_override >= 0 ? (SceSize)list_count_override : saturated ? 256u : 1u;
    for (SceSize i = 0; i < returned && i < *count; ++i) ids[i] = 7 + (SceUID)i;
    *count = returned;
    return 0;
}
int ksceKernelGetModuleInfo(SceUID pid, SceUID id, SceKernelModuleInfo *info) {
    assert(!TLS_FIXER_PREPARE_NO_MODULE_QUERIES);
    if (TLS_FIXER_PREPARE_TARGET_QUERY_ONLY || TLS_FIXER_PREPARE_LIST_TARGET_ONLY || TLS_FIXER_PREPARE_NAME_QUERY) assert(id == 88);
    assert(pid == 99 && (id == 7 || id == 88) && info->size == sizeof(*info));
    require_query_workspace(info, sizeof(*info));
    assert(info->module_name[sizeof(info->module_name) - 1] == 0);
#if TLS_FIXER_ENABLE_BOOT_TRACE
    assert(strcmp(last_stage, id == 88 ? "target.info.enter" : "module.info.enter") == 0);
#endif
    if (id == 88) {
        ++target_queries;
        if (target_info_error) return -1;
        info->modid = target_user_id;
        strcpy(info->module_name, target_wrong_name ? "unexpected" :
            (strstr(expected_path, "/" TLS_FIXER_BROWSER_PROVIDER_FILENAME) ? "ScePsp2Compat" : "SceLibHttp"));
        return 0;
    }
    if (module_info_error) return -1;
    strcpy(info->module_name, loaded_name);
    return 0;
}
SceUID ksceKernelLoadStartModuleForPid(SceUID pid, const char *path, SceSize size, const void *data,
    int flags, const void *options, int *status) {
    const TlsFixerBrowserStartArgs *args = data;
    assert(pid == 99 && size == sizeof(*args) && options == NULL && !locked);
    assert(argument_live && data == argument_memory);
    int browser_provider = strstr(path, "/" TLS_FIXER_BROWSER_PROVIDER_FILENAME) != NULL;
    const char *expected_file = browser_provider
        ? TLS_FIXER_BROWSER_PROVIDER_BOOT_PATH : expected_path;
    assert(flags == 0);
    assert(args->compat_modid == 188 && args->reserved == 0);
    assert(args->version == 1 && strcmp(path, expected_file) == 0);
    if (browser_provider) assert(args->magic == TLS_FIXER_BROWSER_START_MAGIC);
    else assert(args->magic == TLS_FIXER_START_MAGIC);
    ++loads;
    if (reenter) {
        assert(tls_fixer_kernel_inject_browser_for_pid(pid, 88, expected_path) == 1);
    }
    if (load_error) return load_error == 2 ? 0 : -456;
    *status = start_error ? SCE_KERNEL_START_FAILED : SCE_KERNEL_START_SUCCESS;
    return 777;
}
int ksceKernelUnloadModuleForPid(SceUID pid, SceUID id, int flags, const void *options) {
    assert(pid == 99 && id == 777 && flags == 0 && options == NULL && !locked);
    ++unloads;
    return 0;
}

static void reset(void) {
    tls_fixer_kernel_loader_destroy();
    assert(!argument_live && argument_allocations == argument_frees);
    assert(open_descriptors == 0 && !workspace_live && allocations == frees);
    assert(!query_live && query_allocations == query_frees);
    stream_blocks = 1;
#if TLS_FIXER_ENABLE_BOOT_TRACE
    checking_hash_trace = 0;
#endif
    loads = unloads = scan_error = saturated = module_info_error = 0;
    process_title = "TLSFIXAPP";
    process_title_error = 0;
    process_title_queries = 0;
    load_error = start_error = reenter = corrupt_browser = corrupt_http = close_error = 0;
    target_info_error = 0;
    target_wrong_name = 0;
    list_count_override = -1;
    target_user_id = 188;
    browser_file = http_file = 1;
    loaded_name = "";
    expected_path = "wb0:/tls_fixer/" TLS_FIXER_BROWSER_PROVIDER_FILENAME;
    expected_module_path = "wb0:/tls_fixer/ScePsp2Compat.suprx";
    runtime_namespace_required = namespace_provider_error = namespace_hash_error = 0;
    namespace_stat_error = namespace_close_error = 0;
    namespace_provider_opens = namespace_hash_opens = global_provider_stats = 0;
}

static void test_workspace_failures(void) {
    int *const failures[] = {&alloc_fail, &base_fail, &null_base, &free_fail};
    reset();
    assert(tls_fixer_kernel_loader_init() == 0);
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        *failures[i] = 1;
        unsigned int before = (unsigned int)loads;
        assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0);
        assert(!workspace_live && allocations == frees && open_descriptors == 0 && (unsigned int)loads == before);
        *failures[i] = 0;
        assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) == 0);
    }
    reset();
}

static void test_query_workspace_failures(void) {
    int *const failures[] = {&query_alloc_fail, &query_base_fail, &query_null_base, &query_free_fail};
    reset();
    assert(tls_fixer_kernel_loader_init() == 0);
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        *failures[i] = 1;
        unsigned int before = (unsigned int)loads;
        assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0);
        assert(!query_live && query_allocations == query_frees);
        assert(!workspace_live && allocations == frees && open_descriptors == 0 && !locked);
        if (i < 3 || TLS_FIXER_PREPARE_ONLY) assert((unsigned int)loads == before);
        *failures[i] = 0;
        assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) == 0);
    }
    reset();
}

static void test_extended_stack_contract(void) {
#if TLS_FIXER_PREPARE_EXTENDED_STACK
    int *const failures[] = {&stack_error, &stack_skip, &stack_error_after};
    reset();
    assert(tls_fixer_kernel_loader_init() == 0);
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        unsigned int before = stack_calls, before_alloc = query_allocations;
        *failures[i] = 1;
        assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0);
        assert(stack_calls == before + 1 && loads == 0 && unloads == 0);
        assert(!query_live && query_allocations == query_frees);
        assert(!workspace_live && allocations == frees && !locked);
        if (i < 2) assert(query_allocations == before_alloc);
        *failures[i] = 0;
        assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) == 0);
    }
    if (!TLS_FIXER_PREPARE_NO_MODULE_QUERIES && !TLS_FIXER_PREPARE_TARGET_QUERY_ONLY && !TLS_FIXER_PREPARE_NAME_QUERY) {
        scan_error = 1;
        assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0);
        scan_error = 0;
    }
    reset();
#else
    assert(stack_calls == 0);
#endif
}

int main(void) {
    test_extended_stack_contract();
    test_query_workspace_failures();
    test_workspace_failures();
#if TLS_FIXER_PREPARE_NO_MODULE_QUERIES || TLS_FIXER_PREPARE_TARGET_QUERY_ONLY
    static const char *const omitted_query_failures[] = {
        "reserve.enter", "reserve.return", "query.alloc.enter", "query.alloc.return",
        "query.base.enter", "query.base.return", "scan.skipped",
#if TLS_FIXER_PREPARE_TARGET_QUERY_ONLY
        "target.info.enter", "target.info.return",
#else
        "target.skipped",
#endif
        "hash.enter", "hash.return", "hash.stat.enter", "hash.stat.return",
        "hash.alloc.enter", "hash.alloc.return", "hash.base.enter", "hash.base.return",
        "hash.open.enter", "hash.open.return", "hash.init.enter", "hash.init.return",
        "hash.stream.enter", "hash.stream.return", "hash.read.enter", "hash.read.return",
        "hash.update.enter", "hash.update.return", "hash.finish.enter", "hash.finish.return",
        "hash.close.enter", "hash.close.return", "hash.free.enter", "hash.free.return",
        "hash.compare.enter", "hash.compare.return", "query.free.enter", "query.free.return",
        "stack.extend.enter", "stack.extend.return", "stack.callback.enter", "stack.callback.return"
    };
    reset();
    assert(tls_fixer_kernel_loader_init() == 0);
    checking_hash_trace = 1;
    scan_error = module_info_error = 1;
    target_info_error = TLS_FIXER_PREPARE_NO_MODULE_QUERIES;
    target_user_id = TLS_FIXER_PREPARE_NO_MODULE_QUERIES ? 0 : 188;
    for (unsigned int i = 0; i < 80; ++i) {
        unsigned int before = allocations, before_query = query_allocations;
        unsigned int before_target = target_queries;
        expected_path = "vs0:/data/external/tls_fixer/tls_fixer_http.suprx";
        assert(tls_fixer_kernel_inject_for_pid(99, 88) == 0);
        expected_path = "wb0:/tls_fixer/tls_fixer.suprx";
        assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) == 0);
        assert(allocations == before + 2 && query_allocations == before_query + 2);
        assert(target_queries == before_target + (TLS_FIXER_PREPARE_TARGET_QUERY_ONLY ? 2 : 0));
        assert(allocations == frees && query_allocations == query_frees);
        assert(!locked && open_descriptors == 0 && loads == 0 && unloads == 0);
    }
#if TLS_FIXER_PREPARE_TARGET_QUERY_ONLY
    target_info_error = 1;
    assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0);
    target_info_error = 0;
    target_wrong_name = 1;
    assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0);
    target_wrong_name = 0;
    target_user_id = 0;
    assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0);
    target_user_id = -1;
    assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0);
    target_user_id = 188;
    assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) == 0);
    assert(!query_live && query_allocations == query_frees && !workspace_live && allocations == frees);
    assert(!locked && open_descriptors == 0 && loads == 0 && unloads == 0);
#endif
    corrupt_browser = 1;
    assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0);
    corrupt_browser = 0;
    corrupt_http = 1;
    assert(tls_fixer_kernel_inject_for_pid(99, 88) < 0);
    corrupt_http = 0;
    browser_file = 0;
    assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0);
    browser_file = 1;
    for (size_t i = 0; i < sizeof(omitted_query_failures)/sizeof(omitted_query_failures[0]); ++i) {
        trace_fail = omitted_query_failures[i];
        assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0);
        assert(!query_live && query_allocations == query_frees && !workspace_live && allocations == frees);
        assert(!locked && open_descriptors == 0 && loads == 0 && unloads == 0);
        trace_fail = NULL;
        assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) == 0);
    }
    reset();
    puts(TLS_FIXER_PREPARE_TARGET_QUERY_ONLY
        ? "target-query-only diagnostic: one target-info call, no enumeration or provider starts PASS"
        : "no-module-query diagnostic: real hash path, private workspaces and cleanup, no module queries or starts PASS");
    return 0;
#endif
#if TLS_FIXER_ENABLE_BOOT_TRACE
    static const char *const failures[] = {"reserve.enter", "reserve.return", "scan.enter",
        "module.list.enter", "module.list.return", "module.info.enter", "module.info.return",
        "scan.return", "hash.enter", "hash.return", "target.info.enter", "target.info.return",
        "hash.stat.enter", "hash.stat.return", "hash.open.enter", "hash.open.return",
        "hash.init.enter", "hash.init.return", "hash.stream.enter", "hash.stream.return",
        "hash.read.enter", "hash.read.return", "hash.update.enter", "hash.update.return",
        "hash.finish.enter", "hash.finish.return", "hash.close.enter", "hash.close.return",
        "hash.compare.enter", "hash.compare.return", "hash.alloc.enter", "hash.alloc.return",
        "hash.base.enter", "hash.base.return", "hash.free.enter", "hash.free.return",
        "query.alloc.enter", "query.alloc.return", "query.base.enter", "query.base.return",
        "query.free.enter", "query.free.return"
#if TLS_FIXER_PREPARE_EXTENDED_STACK
        , "stack.extend.enter", "stack.extend.return", "stack.callback.enter", "stack.callback.return"
#endif
    };
    reset();
    assert(tls_fixer_kernel_loader_init() == 0);
    checking_hash_trace = 1;
    assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) == 0);
    assert(trace_events >= 14 && strcmp(last_stage,
        TLS_FIXER_PREPARE_EXTENDED_STACK ? "stack.extend.return" : "cleanup.return") == 0);
    for (unsigned int i = 0; i < sizeof(failures)/sizeof(failures[0]); ++i) {
        trace_fail = failures[i];
        assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0);
        assert(open_descriptors == 0 && !workspace_live && allocations == frees);
        assert(!query_live && query_allocations == query_frees);
        trace_fail = NULL;
        assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) == 0);
        assert(!locked && loads == 0 && unloads == 0);
    }
    unsigned int before = trace_events;
    stream_blocks = 4096;
    assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) == 0);
    assert(trace_events - before < 70 && open_descriptors == 0 && !workspace_live && allocations == frees);
    assert(!query_live && query_allocations == query_frees);
    reset();
    puts("kernel traced preparation: operation brackets, no lock-held I/O and failure cleanup PASS");
    return 0;
#endif
#if defined(TLS_FIXER_PREPARE_ONLY) && TLS_FIXER_PREPARE_ONLY
    reset();
    assert(tls_fixer_kernel_loader_init() == 0);
    for (unsigned int i = 0; i < 70; ++i) {
        assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) == 0);
        assert(loads == 0 && unloads == 0 && !locked);
    }
    target_info_error = 1;
    assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0 && loads == 0);
    target_info_error = 0;
    target_user_id = 0;
    assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0 && loads == 0);
    target_user_id = 188;
    corrupt_browser = 1;
    assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0 && loads == 0);
    reset();
    assert(tls_fixer_kernel_loader_init() == 0);
    expected_path = "vs0:/data/external/tls_fixer/tls_fixer_http.suprx";
    assert(tls_fixer_kernel_inject_for_pid(99, 88) == 0 && loads == 0);
    reset();
    assert(!mutex_live && !locked);
    puts("kernel preparation-only: gates, module IDs and repeated reservation cleanup without provider load PASS");
    return 0;
#endif
    reset();
    http_file = 0;
    assert(tls_fixer_kernel_loader_init() == 0);
    assert(!tls_fixer_kernel_loader_ready() && tls_fixer_kernel_browser_loader_ready());
    reenter = 1;
    assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) == 0 && loads == 1);
    reenter = 0;
    loaded_name = "tls_fixer";
    assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) == 0 && loads == 1);
    loaded_name = "";
    corrupt_browser = 1;
    assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0 && loads == 1);
    corrupt_browser = 0;
    assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) == 0 && loads == 2);
    saturated = 1;
    assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0 && loads == 2);
    saturated = 0; scan_error = 1;
    assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0 && loads == 2);
    scan_error = 0; module_info_error = 1;
    assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0 && loads == 2);
    module_info_error = 0; start_error = 1;
    assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0 && loads == 3 && unloads == 1);
    start_error = 0; load_error = 1;
    assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) == -456 && loads == 4);
    load_error = 2;
    assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0 && loads == 5 && unloads == 1);
    load_error = 0; target_info_error = 1;
    assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0 && loads == 5);
    target_info_error = 0; target_user_id = 0;
    assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0 && loads == 5);
    target_user_id = -1;
    assert(tls_fixer_kernel_inject_browser_for_pid(99, 88, expected_path) < 0 && loads == 5);
    reset();
    corrupt_browser = 1;
    assert(tls_fixer_kernel_loader_init() == 0);
    assert(tls_fixer_kernel_loader_ready() && !tls_fixer_kernel_browser_loader_ready());
    expected_path = "vs0:/data/external/tls_fixer/tls_fixer_http.suprx";
    assert(tls_fixer_kernel_inject_for_pid(99, 88) == 0 && loads == 1);
    reset();
    browser_file = http_file = 0;
    assert(tls_fixer_kernel_loader_init() < 0 && !tls_fixer_kernel_browser_loader_ready());
    reset();
    close_error = 1;
    assert(tls_fixer_kernel_loader_init() < 0 && !tls_fixer_kernel_loader_ready());
    reset();
    assert(!mutex_live && !locked);
    puts("kernel TLS loaders: exact gates, browser-only install, recursive load, duplicate and failure paths PASS");
    return 0;
}
