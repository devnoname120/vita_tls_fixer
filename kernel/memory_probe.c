#include "memory_probe.h"
#include "boot_trace.h"
#include <psp2kern/kernel/sysclib.h>
#include <taihen.h>
#include <stddef.h>

#if !TLS_FIXER_MEMORY_PROBE || !TLS_FIXER_TRACE_ACTIVATION_ONLY
#error "Memory snapshots require the sparse asynchronous diagnostic"
#endif

/* Retail 3.60 SceSysmem 3380b323 snapshot ABI; the native reader refreshes its cached free count. */
_Static_assert(sizeof(PhysicalPartitionInfo) == 16, "native partition snapshot extent");

int module_get_export_func(SceUID pid, const char *module, uint32_t library,
    uint32_t function, uintptr_t *address);
static void *(*g_primary_partition)(void);
static int (*g_partition_info)(void *, PhysicalPartitionInfo *);
static uint32_t g_ready;

int tls_fixer_memory_probe_init(void) {
    tai_module_info_t identity;
    uintptr_t getter = 0, reader = 0;
    __atomic_store_n(&g_ready, 0, __ATOMIC_RELEASE);
    memset(&identity, 0, sizeof(identity));
    identity.size = sizeof(identity);
    if (taiGetModuleInfoForKernel(KERNEL_PID, "SceSysmem", &identity) < 0 ||
        memcmp(identity.name, "SceSysmem", sizeof("SceSysmem")) != 0 ||
        identity.module_nid != UINT32_C(0x3380b323)) return -1;
    if (module_get_export_func(KERNEL_PID, "SceSysmem", UINT32_C(0x63a519e5),
            UINT32_C(0x4d38f861), &getter) < 0 || getter == 0 ||
        module_get_export_func(KERNEL_PID, "SceSysmem", UINT32_C(0x63a519e5),
            UINT32_C(0x3650963f), &reader) < 0 || reader == 0) return -1;
#if defined(__arm__)
    if ((getter & 1) == 0 || (reader & 1) == 0) return -1;
#endif
    g_primary_partition = (void *(*)(void))getter;
    g_partition_info = (int (*)(void *, PhysicalPartitionInfo *))reader;
    __atomic_store_n(&g_ready, 1, __ATOMIC_RELEASE);
    return 0;
}

void tls_fixer_memory_probe_record(const char *stage, int32_t pid) {
    PhysicalPartitionInfo info = {0};
    if (!__atomic_load_n(&g_ready, __ATOMIC_ACQUIRE)) return;
    void *partition = g_primary_partition();
    int result = partition == NULL ? -1 : g_partition_info(partition, &info);
    if (result != 0 || info.total_bytes == 0 || info.free_bytes > info.total_bytes) {
        (void)tls_fixer_boot_trace_event("mem.query.failed", pid, 0, result ? result : -1);
        return;
    }
    /* Log byte counts only, not partition pointers or physical addresses. */
    (void)tls_fixer_boot_trace_event(stage, pid, (int32_t)info.total_bytes, (int32_t)info.free_bytes);
}
