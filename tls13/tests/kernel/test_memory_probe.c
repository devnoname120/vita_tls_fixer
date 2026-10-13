#include "memory_probe.h"
#include "boot_trace.h"
#include <taihen.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>

static uint32_t module_nid = UINT32_C(0x3380b323);
static int query_error, resolve_error, null_export, null_partition, read_error;
static int partition_token;
static unsigned int resolutions, native_reads, records;
static uint32_t total_bytes = 512u * 1024u * 1024u, free_bytes = 128u * 1024u * 1024u;
static int32_t last_pid, last_total, last_free;
static char last_stage[32];

static void *get_partition(void) { return null_partition ? NULL : &partition_token; }
static int read_partition(void *partition, PhysicalPartitionInfo *info) {
    assert(partition == &partition_token);
    ++native_reads;
    if (read_error) return read_error;
    info->physical_base = UINT32_C(0x40000000);
    info->total_bytes = total_bytes;
    info->free_bytes = free_bytes;
    info->internal_statistic = 7;
    return 0;
}

int taiGetModuleInfoForKernel(SceUID pid, const char *name, tai_module_info_t *info) {
    assert(pid == KERNEL_PID && strcmp(name, "SceSysmem") == 0);
    assert(info->size == sizeof(*info) && info->module_nid == 0);
    if (query_error) return query_error;
    strcpy(info->name, name);
    info->module_nid = module_nid;
    return 0;
}

int module_get_export_func(SceUID pid, const char *module, uint32_t library,
    uint32_t function, uintptr_t *address) {
    assert(pid == KERNEL_PID && strcmp(module, "SceSysmem") == 0 && library == UINT32_C(0x63a519e5));
    ++resolutions;
    if (resolve_error) return resolve_error;
    assert(function == UINT32_C(0x4d38f861) || function == UINT32_C(0x3650963f));
    *address = null_export ? 0 : function == UINT32_C(0x4d38f861)
        ? (uintptr_t)get_partition : (uintptr_t)read_partition;
    return 0;
}

int tls_fixer_boot_trace_event(const char *stage, int32_t pid, int32_t object, int32_t result) {
    assert(strlen(stage) < sizeof(last_stage));
    strcpy(last_stage, stage);
    last_pid = pid; last_total = object; last_free = result;
    ++records;
    return 0;
}

int main(void) {
    tls_fixer_memory_probe_record("mem.start", 0);
    assert(records == 0 && native_reads == 0);
    query_error = -11;
    assert(tls_fixer_memory_probe_init() < 0 && resolutions == 0);
    query_error = 0; module_nid ^= 1;
    assert(tls_fixer_memory_probe_init() < 0 && resolutions == 0);
    module_nid ^= 1; resolve_error = -12;
    assert(tls_fixer_memory_probe_init() < 0);
    resolve_error = 0; null_export = 1;
    assert(tls_fixer_memory_probe_init() < 0);
    null_export = 0;
    assert(tls_fixer_memory_probe_init() == 0);
    tls_fixer_memory_probe_record("mem.stack.before", 99);
    assert(records == 1 && native_reads == 1 && last_pid == 99);
    assert(last_total == (int32_t)total_bytes && last_free == (int32_t)free_bytes);
    free_bytes = 0;
    tls_fixer_memory_probe_record("mem.stack.after", 99);
    assert(strcmp(last_stage, "mem.stack.after") == 0 && last_free == 0);
    free_bytes = total_bytes + 1;
    tls_fixer_memory_probe_record("mem.start", 0);
    assert(strcmp(last_stage, "mem.query.failed") == 0 && last_free < 0);
    read_error = -23;
    tls_fixer_memory_probe_record("mem.start", 0);
    assert(strcmp(last_stage, "mem.query.failed") == 0 && last_free == -23);
    null_partition = 1;
    unsigned int previous_reads = native_reads;
    tls_fixer_memory_probe_record("mem.start", 0);
    assert(native_reads == previous_reads && last_free < 0);
    module_nid ^= 1;
    assert(tls_fixer_memory_probe_init() < 0);
    unsigned int previous_records = records;
    tls_fixer_memory_probe_record("mem.start", 0);
    assert(records == previous_records && native_reads == previous_reads);
    puts("physical-memory snapshot identity gate, native ABI and failure reporting PASS");
    return 0;
}
