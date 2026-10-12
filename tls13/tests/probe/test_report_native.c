#include "report.h"
#include "report_native_fixture.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static int mkdir_error, stat_error, not_directory, open_error, write_error, sync_error, close_error;
static unsigned int opens, stats;
int sceIoMkdir(const char *path, unsigned int mode) {
    assert(strcmp(path, "ux0:/data/tls_fixer-probe") == 0 && mode == 0777); return mkdir_error;
}
int sceIoGetstat(const char *path, SceIoStat *info) {
    assert(strcmp(path, "ux0:/data/tls_fixer-probe") == 0); ++stats;
    info->st_mode = not_directory ? 0x2000 : 0x1000; return stat_error;
}
int sceIoOpen(const char *path, int flags, unsigned int mode) {
    assert(strncmp(path, "ux0:/data/tls_fixer-probe/run-", 25) == 0);
    assert(flags == (SCE_O_WRONLY | SCE_O_CREAT | SCE_O_EXCL) && mode == 0600);
    ++opens; return open_error ? open_error : 19;
}
int sceIoWrite(int fd, const void *data, SceSize size) {
    assert(fd == 19 && data && size > 0 && size <= TLS_FIXER_PROBE_REPORT_LIMIT);
    return write_error ? write_error : (int)size;
}
int sceIoSync(const char *path, unsigned int flags) {
    assert(strcmp(path, "ux0:") == 0 && flags == 0); return sync_error;
}
int sceIoClose(int fd) { assert(fd == 19); return close_error; }
int main(void) {
    TlsFixerProbeReportOps ops = tls_fixer_probe_report_vita_ops();
    assert(ops.directory && ops.open_exclusive && ops.write && ops.sync && ops.close);
    assert(ops.directory(ops.context) == 0 && stats == 0);
    mkdir_error = -1;
    assert(ops.directory(ops.context) == 0 && stats == 1);
    not_directory = 1; assert(ops.directory(ops.context) < 0); not_directory = 0;
    stat_error = -42; assert(ops.directory(ops.context) < 0); stat_error = 0;
    const char *path = "ux0:/data/tls_fixer-probe/run-0123456789abcdef0123456789abcdef.log";
    assert(ops.open_exclusive(ops.context, path) == 19 && opens == 1);
    open_error = -11; assert(ops.open_exclusive(ops.context, path) == -11);
    assert(ops.write(ops.context, 19, "abc", 3) == 3);
    write_error = -12; assert(ops.write(ops.context, 19, "abc", 3) == -12);
    assert(ops.sync(ops.context, 19) == 0); sync_error = -13; assert(ops.sync(ops.context, 19) == -13);
    assert(ops.close(ops.context, 19) == 0); close_error = -14; assert(ops.close(ops.context, 19) == -14);
    puts("probe native report: directory type, exclusive create and error forwarding PASS");
    return 0;
}
