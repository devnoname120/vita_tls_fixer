#include "allocation_probe.h"
#include "boot_trace.h"
#include "native_module_api.h"
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/kernel/threadmgr/misc.h>
#include <taihen.h>
#include <stddef.h>
#include <stdint.h>

#if !TLS_FIXER_ALLOCATION_PROBE || !TLS_FIXER_TRACE_ACTIVATION_ONLY
#error "Allocation failure capture requires the sparse asynchronous recorder"
#endif

/* Private offsets and four-argument ABI: exact retail 3.60 SceSysmem only. */
#define BACK_EXTENT_OFFSET UINT32_C(0x3674)
#define FREE_BYTES_OFFSET UINT32_C(0x13cc8)
#define NO_FREE_PHYSICAL_PAGE ((int32_t)UINT32_C(0x80024302))
typedef struct PhysicalExtent {
    uint32_t next, reserved, flags, virtual_base, bytes, page_unit, physical_base;
} PhysicalExtent;
_Static_assert(offsetof(PhysicalExtent, flags) == 8, "native extent flags");
_Static_assert(offsetof(PhysicalExtent, bytes) == 16, "native extent byte length");

static SceUID g_sysmem_module = -1, g_allocation_hook_id = -1;
static tai_hook_ref_t g_allocation_hook_ref;
static uint32_t (*g_get_free_bytes)(void *);
static uint32_t g_capture_state;
static unsigned int g_published_fields;
static struct {
    SceUID pid;
    uint32_t bytes, extent_flags, partition_flags, free_bytes;
    char name[17];
} g_failure;

static const uint8_t backing_entry[] = {
    0x2d,0xe9,0xf0,0x4f,0x4a,0xf2,0x04,0x0a,0x1f,0x46,0xc0,0xf2,0xae,0x0a,0x04,0x46,
    0x8b,0xb0,0xda,0xf8,0x00,0x30,0x90,0x46,0x38,0x60,0x40,0x69,0x03,0x91,0x09,0x93
};
static const uint8_t backing_mask[] = {
    0xff,0xff,0xff,0xff,0xf0,0xfb,0x00,0x8f,0xff,0xff,0xf0,0xfb,0x00,0x8f,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
};
static const uint8_t free_entry[] = {
    0x2d,0xe9,0xf0,0x43,0x4a,0xf2,0x04,0x04,0xc0,0xf2,0xae,0x04,0x83,0xb0,0x06,0x46,
    0x00,0xf1,0x08,0x08,0xd4,0xf8,0x00,0xe0,0x00,0x23,0x6f,0xf0,0x00,0x42,0x01,0x21
};
static const uint8_t free_mask[] = {
    0xff,0xff,0xff,0xff,0xf0,0xfb,0x00,0x8f,0xf0,0xfb,0x00,0x8f,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
};

static int matches(const uint8_t *code, const uint8_t *expected, const uint8_t *mask, size_t size) {
    for (size_t i = 0; i < size; ++i)
        if (((code[i] ^ expected[i]) & mask[i]) != 0) return 0;
    return 1;
}

static int backing_patched(PhysicalExtent *extent, void *pool, void *partition, void **last) {
    const uint32_t bytes = extent->bytes, flags = extent->flags;
    int result = TAI_CONTINUE(int, g_allocation_hook_ref, extent, pool, partition, last);
    uint32_t expected = 0;
    if (result != NO_FREE_PHYSICAL_PAGE ||
        !__atomic_compare_exchange_n(&g_capture_state, &expected, 1, 0,
            __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) return result;
    /* The caller still owns partition lifetime. No allocation, trace calls or file I/O here. */
    g_failure.pid = ksceKernelGetProcessId();
    g_failure.bytes = bytes;
    g_failure.extent_flags = flags;
    g_failure.partition_flags = *(const uint32_t *)((const uint8_t *)partition + 0x14);
    /* Native recomputation, without refreshing the cached free-count field at +0x84. */
    g_failure.free_bytes = g_get_free_bytes(partition);
    const char *name = (const char *)partition + 0x8c;
    for (size_t i = 0; i < sizeof(g_failure.name) - 1; ++i) g_failure.name[i] = name[i];
    g_failure.name[sizeof(g_failure.name) - 1] = '\0';
    __atomic_store_n(&g_capture_state, 2, __ATOMIC_RELEASE);
    return result;
}

int tls_fixer_allocation_probe_prepare(void) {
    tai_module_info_t identity;
    SceKernelModuleInfo info;
    if (g_allocation_hook_id >= 0) return -1;
    g_sysmem_module = -1; g_get_free_bytes = NULL;
    memset(&identity, 0, sizeof(identity)); identity.size = sizeof(identity);
    if (taiGetModuleInfoForKernel(KERNEL_PID, "SceSysmem", &identity) != 0 ||
        identity.modid <= 0 || identity.module_nid != UINT32_C(0x3380b323) ||
        memcmp(identity.name, "SceSysmem", sizeof("SceSysmem")) != 0) return -1;
    memset(&info, 0, sizeof(info)); info.size = sizeof(info);
    if (ksceKernelGetModuleInfo(KERNEL_PID, identity.modid, &info) != 0 ||
        info.modid != identity.modid || memcmp(info.module_name, "SceSysmem", sizeof("SceSysmem")) != 0)
        return -1;
    const SceKernelSegmentInfo *segment = &info.segments[0];
    uintptr_t base = (uintptr_t)segment->vaddr;
    if (base == 0 || (base & 3u) != 0 || segment->size != sizeof(*segment) ||
        (segment->perms & 7u) != 5u || segment->memsz < segment->filesz ||
        segment->filesz < FREE_BYTES_OFFSET + sizeof(free_entry) ||
        base > UINTPTR_MAX - segment->memsz) return -1;
    if (!matches((const uint8_t *)base + BACK_EXTENT_OFFSET, backing_entry, backing_mask, sizeof(backing_entry)) ||
        !matches((const uint8_t *)base + FREE_BYTES_OFFSET, free_entry, free_mask, sizeof(free_entry))) return -1;
    g_get_free_bytes = (uint32_t (*)(void *))(base + FREE_BYTES_OFFSET + 1);
    g_sysmem_module = identity.modid;
    return 0;
}

int tls_fixer_allocation_probe_install(void) {
    if (g_sysmem_module < 0 || g_get_free_bytes == NULL || g_allocation_hook_id >= 0) return -1;
    g_allocation_hook_id = taiHookFunctionOffsetForKernel(KERNEL_PID, &g_allocation_hook_ref,
        g_sysmem_module, 0, BACK_EXTENT_OFFSET, 1, backing_patched);
    (void)tls_fixer_boot_trace_event("alloc.hook.return", 0, g_sysmem_module, g_allocation_hook_id);
    return g_allocation_hook_id < 0 ? g_allocation_hook_id : 0;
}
int tls_fixer_allocation_probe_resident(void) { return g_allocation_hook_id >= 0; }

void tls_fixer_allocation_probe_drain(void) {
    if (__atomic_load_n(&g_capture_state, __ATOMIC_ACQUIRE) != 2) return;
    while (g_published_fields < 4) {
        int result;
        switch (g_published_fields) {
        case 0: result = tls_fixer_boot_trace_event("alloc.request", g_failure.pid,
            (int32_t)g_failure.bytes, NO_FREE_PHYSICAL_PAGE); break;
        case 1: result = tls_fixer_boot_trace_event("alloc.flags", g_failure.pid,
            (int32_t)g_failure.extent_flags, (int32_t)g_failure.partition_flags); break;
        case 2: result = tls_fixer_boot_trace_event("alloc.free", g_failure.pid,
            (int32_t)g_failure.free_bytes, 0); break;
        default: result = tls_fixer_boot_trace_path("alloc.partition", g_failure.pid, 1, 0, g_failure.name); break;
        }
        if (result < 0) return;
        ++g_published_fields;
    }
}
