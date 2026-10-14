#include "browser_inventory.h"
#include <kernel_mock.h>
#include <psp2/io/fcntl.h>
#include <assert.h>
#include <stdio.h>

static char disk[32768];
static size_t used;
static unsigned int list_calls, info_calls, opens;
static int list_error, info_error, write_error, sync_error, close_error, partial;
static SceSize wanted_count = 1;
static SceUID wanted_id = 23;
int64_t ksceKernelGetSystemTimeWide(void) { return 123456; }
int ksceKernelGetModuleList(SceUID pid, unsigned int a, unsigned int b, SceUID *ids, SceSize *count) {
    assert(pid > 0 && a == 0xff && b == 1 && *count == 256);
    ++list_calls; ids[0] = wanted_id; *count = wanted_count; return list_error;
}
int ksceKernelGetModuleInfo(SceUID pid, SceUID id, SceKernelModuleInfo *info) {
    assert(pid > 0 && id == wanted_id && info->size == sizeof(*info));
    ++info_calls;
    strcpy(info->module_name, "ScePsp2Compat");
    strcpy(info->path, "wb0:/webcore/ScePsp2Compat.suprx");
    info->segments[0].vaddr = (void *)(uintptr_t)0x81012300;
    info->segments[0].filesz = info->segments[0].memsz = 0x4000;
    return info_error;
}
int ksceIoOpen(const char *path, int flags, int mode) {
    assert(strcmp(path, TLS_FIXER_BROWSER_INVENTORY_PATH) == 0 && mode == 0006);
    assert((flags & (SCE_O_WRONLY | SCE_O_CREAT)) == (SCE_O_WRONLY | SCE_O_CREAT));
    ++opens;
    if (flags & SCE_O_TRUNC) used = 0;
    return 9;
}
int ksceIoPwrite(SceUID fd, const void *data, SceSize size, SceOff offset) {
    assert(fd == 9 && offset == (SceOff)used && size > 0);
    if (write_error) return -71;
    if (partial && size > 7) size = 7;
    assert(used + size < sizeof(disk)); memcpy(disk + used, data, size); used += size; disk[used] = '\0';
    return (int)size;
}
int ksceIoSync(const char *path, unsigned int mode) {
    assert(strcmp(path, TLS_FIXER_BROWSER_INVENTORY_PATH) == 0 && mode == 0); return sync_error ? -72 : 0;
}
int ksceIoClose(SceUID fd) { assert(fd == 9); return close_error ? -73 : 0; }
static int tick(void) {
    int result = 0;
    for (unsigned int i = 0; i < 20; ++i) { result = tls_fixer_browser_inventory_tick(); if (result < 0) break; }
    return result;
}
static void reset(void) {
    tls_fixer_browser_inventory_reset(); used = 0; disk[0] = '\0';
    list_calls = info_calls = opens = 0;
    list_error = info_error = write_error = sync_error = close_error = partial = 0;
    wanted_count = 1; wanted_id = 23;
}
int main(void) {
    reset(); assert(tick() == 0 && list_calls == 0);
    tls_fixer_browser_inventory_request(-1); assert(tick() == 0 && list_calls == 0);
    tls_fixer_browser_inventory_request(99); tls_fixer_browser_inventory_request(99);
    partial = 1;
    assert(tick() == 0 && list_calls == 1 && info_calls == 1);
    assert(strstr(disk, "kind=snapshot pid=00000063") != NULL);
    assert(strstr(disk, "text=81012300 filesz=00004000 memsz=00004000") != NULL);
    assert(strstr(disk, "namehex=53636550737032436f6d706174") != NULL);
    size_t before = used;
    assert(tick() == 0 && list_calls == 2 && info_calls == 1 && used == before);
    wanted_id = 24; assert(tick() == 0 && info_calls == 2 && used > before);
    list_error = -8; before = list_calls;
    assert(tick() == 0 && strstr(disk, "kind=list_error") != NULL);
    assert(tick() == 0 && list_calls == before + 1);
    reset(); wanted_count = 256; tls_fixer_browser_inventory_request(99);
    assert(tick() == 0 && info_calls == 0 && strstr(disk, "count=00000100") != NULL);
    reset(); info_error = -9; tls_fixer_browser_inventory_request(99);
    assert(tick() == 0 && strstr(disk, "rc=fffffff7") != NULL);
    for (int failure = 0; failure < 3; ++failure) {
        reset(); tls_fixer_browser_inventory_request(99);
        write_error = failure == 0; sync_error = failure == 1; close_error = failure == 2;
        assert(tick() < 0);
        before = list_calls; assert(tick() < 0 && list_calls == before);
    }
    puts("Browser inventory: delayed read-only snapshots, changes, bounds and I/O failures PASS");
    return 0;
}
