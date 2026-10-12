#include "trace.h"

#include <psp2/io/fcntl.h>
#include <psp2/kernel/clib.h>
#include <psp2/kernel/processmgr.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static uint32_t records;

void tls_fixer_trace(const char *format, ...) {
    char line[TLS_FIXER_TRACE_LINE_LIMIT];
    char path[96];
    uint32_t observed = __atomic_load_n(&records, __ATOMIC_RELAXED);
    SceUID pid, fd;
    int prefix, formatted;
    size_t length;
    va_list args;

    do {
        if (observed >= TLS_FIXER_TRACE_RECORD_LIMIT) return;
    } while (!__atomic_compare_exchange_n(&records, &observed, observed + 1, 0,
        __ATOMIC_RELAXED, __ATOMIC_RELAXED));
    if (format == NULL) return;
    pid = sceKernelGetProcessId();
    prefix = snprintf(line, sizeof(line), "tls_fixer: pid=%08X t=%llu ", (unsigned int)pid,
        (unsigned long long)sceKernelGetSystemTimeWide());
    if (prefix < 0 || (size_t)prefix >= sizeof(line) - 2) return;
    va_start(args, format);
    formatted = vsnprintf(line + prefix, sizeof(line) - (size_t)prefix - 1, format, args);
    va_end(args);
    if (formatted < 0) return;
    length = strlen(line);
    line[length++] = '\n';
    line[length] = '\0';
    (void)sceClibPrintf("%s", line);
    formatted = snprintf(path, sizeof(path), "ux0:/data/tls_fixer-browser-%08X.log", (unsigned int)pid);
    if (formatted < 0 || (size_t)formatted >= sizeof(path)) return;
    fd = sceIoOpen(path, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_APPEND, 0600);
    if (fd < 0) {
        formatted = snprintf(path, sizeof(path),
            "savedata0:/temp/tls_fixer-browser-%08X.log", (unsigned int)pid);
        if (formatted < 0 || (size_t)formatted >= sizeof(path)) return;
        fd = sceIoOpen(path, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_APPEND, 0600);
        if (fd < 0) return;
    }
    (void)sceIoWrite(fd, line, (SceSize)length);
    (void)sceIoClose(fd);
}
