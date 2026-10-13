#include <kernel_mock.h>
#include <taihen.h>
#include <assert.h>
#include <stdio.h>
#undef TAI_CONTINUE
#define TAI_CONTINUE(type, reference, ...) \
    ((type (*)(PhysicalExtent *, void *, void *, void **))(reference))(__VA_ARGS__)
#include "../../../kernel/allocation_probe.c"

_Alignas(4) static uint8_t module_text[0x14000], partition_bytes[0xc0];
static SceKernelModuleInfo fixture;
static int identity_error, info_error, hook_result, native_result, native_returned;
static uint32_t identity_nid;
static unsigned int hook_calls, native_calls, counter_calls, trace_calls;
static int trace_failure;
static PhysicalExtent *expected_extent;
static void *expected_pool, *expected_partition, **expected_last;

static uint32_t free_bytes(void *partition) {
    assert(native_returned && partition == expected_partition);
    ++counter_calls;
    return 0x178000;
}
static int native_backing(PhysicalExtent *extent, void *pool, void *partition, void **last) {
    assert(extent == expected_extent && pool == expected_pool && partition == expected_partition && last == expected_last);
    ++native_calls;
    extent->bytes = 4096; /* The diagnostic must retain the original request. */
    *last = extent;
    native_returned = 1;
    return native_result;
}
SceUID ksceKernelGetProcessId(void) { assert(native_returned); return 77; }
int taiGetModuleInfoForKernel(SceUID pid, const char *name, tai_module_info_t *info) {
    assert(pid == KERNEL_PID && strcmp(name, "SceSysmem") == 0 && info->size == sizeof(*info));
    if (identity_error) return identity_error;
    info->modid = 11; info->module_nid = identity_nid; strcpy(info->name, name); return 0;
}
int ksceKernelGetModuleInfo(SceUID pid, SceUID module, SceKernelModuleInfo *info) {
    assert(pid == KERNEL_PID && module == 11 && info->size == sizeof(*info));
    if (info_error) return info_error;
    *info = fixture; return 0;
}
int taiHookFunctionOffsetForKernel(SceUID pid, tai_hook_ref_t *reference, SceUID module,
    int segment, size_t offset, int thumb, const void *callback) {
    assert(pid == KERNEL_PID && module == 11 && segment == 0 && offset == 0x3674 && thumb == 1);
    assert(callback == backing_patched);
    ++hook_calls; *reference = (uintptr_t)native_backing; return hook_result;
}
int tls_fixer_boot_trace_event(const char *stage, int32_t pid, int32_t object, int32_t result) {
    if (strcmp(stage, "alloc.hook.return") == 0) return 0;
    assert(g_capture_state == 2 && pid == 77); /* Publication occurs only in drain, never in the hook. */
    if (trace_failure) return -1;
    if (trace_calls == 0) assert(strcmp(stage, "alloc.request") == 0 && object == 0x200000 && result == NO_FREE_PHYSICAL_PAGE);
    if (trace_calls == 1) assert(strcmp(stage, "alloc.flags") == 0 && object == 0x20004 && result == 0x10040);
    if (trace_calls == 2) assert(strcmp(stage, "alloc.free") == 0 && object == 0x178000 && result == 0);
    ++trace_calls; return 0;
}
int tls_fixer_boot_trace_path(const char *stage, int32_t pid, int32_t object, int32_t result, const char *path) {
    assert(trace_calls == 3 && strcmp(stage, "alloc.partition") == 0 && pid == 77 && object == 1 && result == 0);
    assert(strcmp(path, "fixture pool") == 0); ++trace_calls; return 0;
}
static void hex_bytes(uint8_t *out, const char *hex) {
    for (size_t i = 0; i < strlen(hex) / 2; ++i) { unsigned int b; assert(sscanf(hex + 2*i, "%2x", &b) == 1); out[i] = (uint8_t)b; }
}
static void reset(void) {
    memset(&fixture, 0, sizeof(fixture)); memset(module_text, 0, sizeof(module_text));
    fixture.size = sizeof(fixture); fixture.modid = 11; strcpy(fixture.module_name, "SceSysmem");
    fixture.segments[0].size = sizeof(SceKernelSegmentInfo); fixture.segments[0].perms = 5;
    fixture.segments[0].vaddr = module_text; fixture.segments[0].filesz = fixture.segments[0].memsz = sizeof(module_text);
    /* Independent 32-byte native readbacks from retail 3.60. */
    hex_bytes(module_text + 0x3674, "2de9f04f4af2040a1f46c0f2ae0a04468bb0daf8003090463860406903910993");
    hex_bytes(module_text + 0x13cc8, "2de9f0434af20404c0f2ae0483b0064600f10808d4f800e000236ff000420121");
    identity_nid = 0x3380b323; identity_error = info_error = 0; hook_result = 55;
    g_sysmem_module = g_allocation_hook_id = -1; g_get_free_bytes = NULL;
    g_capture_state = g_published_fields = 0; hook_calls = native_calls = counter_calls = trace_calls = 0;
    native_returned = trace_failure = 0;
}
int main(void) {
    reset(); assert(tls_fixer_allocation_probe_install() < 0 && hook_calls == 0);
    identity_nid ^= 1; assert(tls_fixer_allocation_probe_prepare() < 0);
    reset(); identity_error = -3; assert(tls_fixer_allocation_probe_prepare() < 0);
    reset(); info_error = -4; assert(tls_fixer_allocation_probe_prepare() < 0);
    reset(); fixture.segments[0].filesz = 0x13cc8; assert(tls_fixer_allocation_probe_prepare() < 0);
    reset(); fixture.segments[0].perms = 3; assert(tls_fixer_allocation_probe_prepare() < 0);
    reset(); module_text[0x3674] ^= 1; assert(tls_fixer_allocation_probe_prepare() < 0);
    reset(); module_text[0x13cd4] ^= 1; assert(tls_fixer_allocation_probe_prepare() < 0);
    reset(); module_text[0x367a] ^= 0xff; module_text[0x13cd2] ^= 0xff; /* Relocated cookie immediates. */
    assert(tls_fixer_allocation_probe_prepare() == 0);
    hook_result = -5; assert(tls_fixer_allocation_probe_install() == -5 && !tls_fixer_allocation_probe_resident());
    hook_result = 55; assert(tls_fixer_allocation_probe_install() == 0 && tls_fixer_allocation_probe_resident());
    assert(tls_fixer_allocation_probe_prepare() < 0 && tls_fixer_allocation_probe_install() < 0);
    g_get_free_bytes = free_bytes;
    PhysicalExtent extent = {0}; void *last = NULL; int pool;
    expected_extent = &extent; expected_pool = &pool; expected_partition = partition_bytes; expected_last = &last;
    *(uint32_t *)(partition_bytes + 0x14) = 0x10040; strcpy((char *)partition_bytes + 0x8c, "fixture pool");
    native_result = 0; assert(backing_patched(&extent, &pool, partition_bytes, &last) == 0 && last == &extent);
    native_result = -123; assert(backing_patched(&extent, &pool, partition_bytes, &last) == -123);
    assert(counter_calls == 0 && trace_calls == 0 && g_capture_state == 0);
    native_result = NO_FREE_PHYSICAL_PAGE; extent.bytes = 0x200000; extent.flags = 0x20004;
    assert(backing_patched(&extent, &pool, partition_bytes, &last) == native_result);
    assert(counter_calls == 1 && trace_calls == 0 && g_capture_state == 2 && g_failure.bytes == 0x200000);
    extent.bytes = 0x400000;
    assert(backing_patched(&extent, &pool, partition_bytes, &last) == native_result && counter_calls == 1);
    trace_failure = 1; tls_fixer_allocation_probe_drain(); assert(trace_calls == 0 && g_published_fields == 0);
    trace_failure = 0; tls_fixer_allocation_probe_drain(); assert(trace_calls == 4 && g_published_fields == 4);
    tls_fixer_allocation_probe_drain(); assert(trace_calls == 4 && native_calls == 4);
    puts("allocation failure: native forwarding, identity/code gates, first-failure capture and deferred publication PASS");
}
