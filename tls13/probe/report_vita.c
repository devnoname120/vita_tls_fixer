#include "report.h"
#if defined(TLS_FIXER_PROBE_REPORT_NATIVE_TEST)
#include "report_native_fixture.h"
#else
#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#endif
#include <string.h>

static int directory(void *unused) {
    (void)unused;
    int rc = sceIoMkdir("ux0:/data/tls_fixer-probe", 0777);
    if (rc >= 0) return 0;
    SceIoStat info;
    memset(&info, 0, sizeof(info));
    int found = sceIoGetstat("ux0:/data/tls_fixer-probe", &info);
    return found >= 0 && SCE_S_ISDIR(info.st_mode) ? 0 : rc;
}
static int open_exclusive(void *unused, const char *path) {
    (void)unused;
    return sceIoOpen(path, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_EXCL, 0600);
}
static int write_data(void *unused, int fd, const void *data, size_t size) {
    (void)unused;
    if (size > TLS_FIXER_PROBE_REPORT_LIMIT) return TLS_FIXER_PROBE_INVALID;
    return sceIoWrite(fd, data, (SceSize)size);
}
static int sync_data(void *unused, int fd) {
    (void)unused; (void)fd;
    return sceIoSync("ux0:", 0);
}
static int close_data(void *unused, int fd) { (void)unused; return sceIoClose(fd); }

TlsFixerProbeReportOps tls_fixer_probe_report_vita_ops(void) {
    return (TlsFixerProbeReportOps){NULL, directory, open_exclusive, write_data, sync_data, close_data};
}
