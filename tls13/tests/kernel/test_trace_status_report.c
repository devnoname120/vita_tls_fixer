#include "disarm_result.h"
#include <kernel_mock.h>
#include <assert.h>
#include <stdio.h>

static unsigned char disk[257];
static int open_error, short_write, write_error, sync_error, close_error, bad_size;
static unsigned int opens, closes, writes, syncs;

int ksceIoOpen(const char *path, int flags, int mode) {
    assert(strcmp(path, TLS_FIXER_DISARM_RESULT_PATH) == 0 && flags == SCE_O_RDWR && mode == 0);
    ++opens;
    return open_error ? -77 : 9;
}
SceOff ksceIoLseek(SceUID fd, SceOff offset, int whence) {
    assert(fd == 9 && offset == 0 && whence == SCE_SEEK_END);
    return bad_size ? 128 : 256;
}
int ksceIoPwrite(SceUID fd, const void *data, SceSize size, SceOff offset) {
    assert(fd == 9 && size != 0);
    assert((offset >= 160 && offset + size <= 192) || (offset >= 224 && offset + size <= 252));
    ++writes;
    if (write_error) return -89;
    if (short_write && size > 3) size = 3;
    memcpy(disk + offset, data, size);
    return (int)size;
}
int ksceIoSync(const char *path, unsigned int flags) {
    assert(strcmp(path, TLS_FIXER_DISARM_RESULT_PATH) == 0 && flags == 0);
    ++syncs;
    return sync_error ? -78 : 0;
}
int ksceIoClose(SceUID fd) { assert(fd == 9); ++closes; return close_error ? -79 : 0; }

int main(int argc, char **argv) {
    assert(argc == 2);
    const char *scenario = argv[1];
    TlsFixerTraceStatus status = {(int32_t)UINT32_C(0x80010009), TLS_FIXER_TRACE_ERROR_WRITE, 37, 91};
    memset(disk, 'X', 256);
    if (strcmp(scenario, "invalid") == 0) {
        assert(tls_fixer_write_trace_runtime_result(NULL, 1) < 0);
        assert(tls_fixer_write_trace_runtime_result(&status, 0) < 0);
        assert(tls_fixer_write_trace_runtime_result(&status, 3) < 0);
        assert(opens == 0);
        return 0;
    }
    open_error = strcmp(scenario, "open-fail") == 0;
    write_error = strcmp(scenario, "write-fail") == 0;
    sync_error = strcmp(scenario, "sync-fail") == 0;
    close_error = strcmp(scenario, "close-fail") == 0;
    short_write = strcmp(scenario, "partial") == 0;
    bad_size = strcmp(scenario, "bad-size") == 0;
    unsigned int mode = strcmp(scenario, "limit") == 0 ? 2u : 1u;
    int result = tls_fixer_write_trace_runtime_result(&status, mode);
    assert((result < 0) == !!(open_error || write_error || sync_error || close_error || bad_size));
    for (size_t i = 0; i < 160; ++i) assert(disk[i] == 'X');
    for (size_t i = 192; i < 224; ++i) assert(disk[i] == 'X');
    for (size_t i = 252; i < 256; ++i) assert(disk[i] == 'X');
    if (result == 0) {
        assert(memcmp(disk + 160, "err=80010009\nop=00000003\n", 25) == 0);
        assert(memcmp(disk + 224, "a=00000025\nh=0000005b\nm=", 24) == 0);
        assert(disk[248] == (mode == 1 ? '1' : '2'));
        assert(opens == closes && syncs == 2 && writes >= 2);
    }
    puts("runtime trace report: reserved spans and preserved gate/setup/footer PASS");
    return 0;
}
