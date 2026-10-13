#include "diagnostics.h"
#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#include <psp2/kernel/modulemgr.h>
#include <psp2/kernel/processmgr.h>
#include <psp2/kernel/threadmgr.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static SceUID g_descriptor = -1, g_mutex = -1;
static unsigned g_sequence;
static char g_path[160];

uint64_t check_diag_time(void) { return sceKernelGetSystemTimeWide(); }

void check_diag(const char *format, ...) {
    char line[768];
    if (g_mutex < 0)
        return;
    if (sceKernelLockMutex(g_mutex, 1, NULL) < 0)
        return;
    if (g_descriptor < 0 || g_sequence >= 8192)
        goto done;
    int n = snprintf(line, sizeof(line), "tls-check-v2 seq=%u us=%llu pid=%08X tid=%08X ",
                     g_sequence++, (unsigned long long)check_diag_time(),
                     (unsigned)sceKernelGetProcessId(), (unsigned)sceKernelGetThreadId());
    if (n < 0 || (size_t)n >= sizeof(line) - 2)
        goto done;
    int formatted;
    if (g_sequence == 8192) {
        formatted = snprintf(line + n, sizeof(line) - (size_t)n - 1,
                             "event=log.limit budget=8192 further_records_suppressed=1");
    } else {
        va_list args;
        va_start(args, format);
        formatted = vsnprintf(line + n, sizeof(line) - (size_t)n - 1, format, args);
        va_end(args);
    }
    if (formatted < 0)
        goto done;
    size_t size = strlen(line);
    line[size++] = '\n';
    size_t sent = 0;
    while (sent < size) {
        int written = sceIoWrite(g_descriptor, line + sent, (unsigned)(size - sent));
        if (written <= 0 || (size_t)written > size - sent) {
            (void)sceIoClose(g_descriptor);
            g_descriptor = -1;
            break;
        }
        sent += (unsigned)written;
    }
done:
    (void)sceKernelUnlockMutex(g_mutex, 1);
}

void check_diag_sync(void) {
    if (g_mutex < 0 || sceKernelLockMutex(g_mutex, 1, NULL) < 0)
        return;
    if (g_descriptor >= 0)
        (void)sceIoSync(g_path, 0);
    (void)sceKernelUnlockMutex(g_mutex, 1);
}

void check_diag_init(void) {
    (void)sceIoMkdir("ux0:/data/vita-tls-check", 0777);
    g_mutex = sceKernelCreateMutex("TLS check diagnostics", 0, 0, NULL);
    if (g_mutex < 0)
        return;
    snprintf(g_path, sizeof(g_path), "ux0:/data/vita-tls-check/api-%08X-%llu.log",
             (unsigned)sceKernelGetProcessId(), (unsigned long long)check_diag_time());
    g_descriptor = sceIoOpen(g_path, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_EXCL, 0666);
    check_diag("event=session.begin build=api-diagnostics-20261013 "
               "verification=enabled");
    check_diag_sync();
}

void check_diag_close(void) {
    check_diag("event=session.end");
    check_diag_sync();
    if (g_descriptor >= 0)
        (void)sceIoClose(g_descriptor);
    g_descriptor = -1;
    if (g_mutex >= 0)
        (void)sceKernelDeleteMutex(g_mutex);
    g_mutex = -1;
}

void check_diag_modules(const char *stage) {
    /* Query every module generically; the checker has no provider-specific
     * dependency. */
    SceUID ids[128];
    SceSize count = sizeof(ids) / sizeof(ids[0]);
    int rc = sceKernelGetModuleList(0xff, ids, &count);
    check_diag("event=modules.begin stage=%s rc=%08X count=%u capacity=128", stage, (unsigned)rc,
               (unsigned)count);
    if (rc >= 0) {
        for (unsigned i = 0; i < count && i < 128; ++i) {
            SceKernelModuleInfo info = {0};
            info.size = sizeof(info);
            rc = sceKernelGetModuleInfo(ids[i], &info);
            check_diag(
                "event=module stage=%s uid=%08X rc=%08X name=%.28s state=%08X "
                "text=%08X text_file=%u text_mem=%u data=%08X data_file=%u "
                "data_mem=%u "
                "path=%.256s",
                stage, (unsigned)ids[i], (unsigned)rc, rc < 0 ? "unavailable" : info.module_name,
                (unsigned)info.state, (unsigned)(uintptr_t)info.segments[0].vaddr,
                (unsigned)info.segments[0].filesz, (unsigned)info.segments[0].memsz,
                (unsigned)(uintptr_t)info.segments[1].vaddr, (unsigned)info.segments[1].filesz,
                (unsigned)info.segments[1].memsz, rc < 0 ? "" : info.path);
        }
    }
    check_diag("event=modules.end stage=%s", stage);
    check_diag_sync();
}
