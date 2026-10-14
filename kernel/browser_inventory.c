#include "browser_inventory.h"
#include "native_module_api.h"
#include <psp2/io/fcntl.h>
#include <psp2kern/io/fcntl.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/kernel/threadmgr/misc.h>
#include <stdint.h>
#include <stddef.h>

#if !TLS_FIXER_BROWSER_INVENTORY
#error "Browser inventory is a diagnostic only"
#endif

#define MAX_PIDS 8u
#define MAX_MODULES 256u
#define BYTE_BUDGET (2u * 1024u * 1024u)

static struct {
    uint32_t pid;
    SceUID previous[MAX_MODULES];
    SceSize count;
    int captured, retired;
} slots[MAX_PIDS];
static char record[1024];
static size_t length, written_total;
static unsigned int ticks;
static int failed;

static void text(const char *value) {
    while (*value != '\0' && length < sizeof(record)) record[length++] = *value++;
}
static void hex32(uint32_t value) {
    static const char digits[] = "0123456789abcdef";
    for (unsigned int i = 0; i < 8 && length < sizeof(record); ++i)
        record[length++] = digits[(value >> (28 - 4*i)) & 15];
}
static void bytes(const char *value, size_t capacity) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < capacity && value[i] != '\0' && length + 2 <= sizeof(record); ++i) {
        unsigned char byte = (unsigned char)value[i];
        record[length++] = digits[byte >> 4]; record[length++] = digits[byte & 15];
    }
}
static int write_record(void) {
    if (length == sizeof(record) || length > BYTE_BUDGET - written_total) return -1;
    SceUID fd = ksceIoOpen(TLS_FIXER_BROWSER_INVENTORY_PATH,
        SCE_O_WRONLY | SCE_O_CREAT | (written_total == 0 ? SCE_O_TRUNC : 0), 0006);
    if (fd < 0) return fd;
    int result = 0;
    size_t sent = 0;
    while (sent < length) {
        int count = ksceIoPwrite(fd, record + sent, (SceSize)(length - sent), (SceOff)written_total + (SceOff)sent);
        if (count <= 0 || (size_t)count > length - sent) { result = count < 0 ? count : -1; break; }
        sent += (size_t)count;
    }
    if (result == 0) result = ksceIoSync(TLS_FIXER_BROWSER_INVENTORY_PATH, 0);
    if (ksceIoClose(fd) < 0) result = -1;
    if (result == 0) written_total += length;
    return result;
}
static void begin(const char *kind, SceUID pid) {
    length = 0; text("tls_fixer-inventory1 kind="); text(kind); text(" pid="); hex32((uint32_t)pid);
    uint64_t now = (uint64_t)ksceKernelGetSystemTimeWide();
    text(" us="); hex32((uint32_t)(now >> 32)); hex32((uint32_t)now);
}

void tls_fixer_browser_inventory_reset(void) {
    memset(slots, 0, sizeof(slots)); ticks = 0; failed = 0; written_total = 0;
}
void tls_fixer_browser_inventory_request(SceUID pid) {
    if (pid <= 0) return;
    for (size_t i = 0; i < MAX_PIDS; ++i) {
        uint32_t current = __atomic_load_n(&slots[i].pid, __ATOMIC_ACQUIRE);
        if (current == (uint32_t)pid) return;
        if (current == 0) {
            if (__atomic_compare_exchange_n(&slots[i].pid, &current, (uint32_t)pid,
                    0, __ATOMIC_RELEASE, __ATOMIC_RELAXED) || current == (uint32_t)pid) return;
        }
    }
}

int tls_fixer_browser_inventory_tick(void) {
    if (failed) return failed;
    if (++ticks % 20 != 0) return 0; /* Existing 100ms worker; inventory runs every two seconds. */
    for (size_t slot = 0; slot < MAX_PIDS; ++slot) {
        SceUID pid = (SceUID)__atomic_load_n(&slots[slot].pid, __ATOMIC_ACQUIRE);
        if (pid <= 0 || slots[slot].retired) continue;
        SceUID modules[MAX_MODULES];
        SceSize count = MAX_MODULES;
        int result = ksceKernelGetModuleList(pid, 0xff, 1, modules, &count);
        if (result != 0 || count >= MAX_MODULES) {
            begin("list_error", pid); text(" rc="); hex32((uint32_t)result);
            text(" count="); hex32(count); text("\n");
            failed = write_record(); slots[slot].retired = 1;
            if (failed < 0) return failed;
            continue;
        }
        if (slots[slot].captured && slots[slot].count == count &&
            memcmp(slots[slot].previous, modules, count * sizeof(*modules)) == 0) continue;
        begin("snapshot", pid); text(" count="); hex32(count); text("\n");
        if ((failed = write_record()) < 0) return failed;
        for (SceSize i = 0; i < count; ++i) {
            SceKernelModuleInfo info;
            memset(&info, 0, sizeof(info)); info.size = sizeof(info);
            result = ksceKernelGetModuleInfo(pid, modules[i], &info);
            begin("module", pid); text(" uid="); hex32((uint32_t)modules[i]);
            text(" rc="); hex32((uint32_t)result);
            if (result == 0) {
                text(" namehex="); bytes(info.module_name, sizeof(info.module_name));
                text(" pathhex="); bytes(info.path, sizeof(info.path));
                text(" text="); hex32((uint32_t)(uintptr_t)info.segments[0].vaddr);
                text(" filesz="); hex32(info.segments[0].filesz);
                text(" memsz="); hex32(info.segments[0].memsz);
#if defined(__arm__)
                text(" state="); hex32(info.state);
#endif
            }
            text("\n");
            if ((failed = write_record()) < 0) return failed;
        }
        memcpy(slots[slot].previous, modules, count * sizeof(*modules));
        slots[slot].count = count; slots[slot].captured = 1;
    }
    return 0;
}
