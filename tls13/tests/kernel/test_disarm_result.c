#include "disarm_result.h"
#include <kernel_mock.h>
#include <assert.h>
#include <stdio.h>

static char bytes[TLS_FIXER_DISARM_RESULT_SIZE + 1];
static int open_fail, wrong_size, short_write, zero_write, sync_fail, close_fail;
static int seek_fail, oversized_write, negative_write;
static unsigned int opens, writes, closes, syncs, consumed;
static SceOff start_offset;

int ksceIoOpen(const char *path, int flags, int mode) {
    assert(strcmp(path, TLS_FIXER_DISARM_RESULT_PATH) == 0 && flags == SCE_O_RDWR && mode == 0);
    ++opens;
    return open_fail ? -77 : 9;
}
SceOff ksceIoLseek(SceUID fd, SceOff offset, int whence) {
    assert(fd == 9 && offset == 0 && whence == SCE_SEEK_END);
    if (seek_fail) return -88;
    return wrong_size ? 3 : TLS_FIXER_DISARM_RESULT_SIZE;
}
int ksceIoPwrite(SceUID fd, const void *data, SceSize size, SceOff offset) {
    assert(fd == 9 && offset == start_offset + consumed && offset + size <= TLS_FIXER_DISARM_RESULT_SIZE);
    if (zero_write) return 0;
    if (oversized_write) return (int)size + 1;
    if (negative_write) return -89;
    if (short_write && size > 7) size = 7;
    memcpy(bytes + start_offset + consumed, data, size);
    consumed += size;
    ++writes;
    return (int)size;
}
int ksceIoSync(const char *path, unsigned int flags) {
    assert(strcmp(path, TLS_FIXER_DISARM_RESULT_PATH) == 0 && flags == 0);
    ++syncs;
    return sync_fail ? -78 : 0;
}
int ksceIoClose(SceUID fd) {
    assert(fd == 9);
    ++closes;
    return close_fail ? -79 : 0;
}

int main(int argc, char **argv) {
    assert(argc == 2);
    const char *scenario = argv[1];
    TlsFixerDisarmReport report = {"gate.file_sync", -9876, 0, 1, 0, 0};
    if (strcmp(scenario, "trace-setup") == 0) {
        memset(bytes, 'X', TLS_FIXER_DISARM_RESULT_SIZE);
        start_offset = 192;
        short_write = 1;
        assert(tls_fixer_write_trace_setup_result(-77) == 0);
        assert(consumed == 32 && syncs == 1 && closes == 1 && writes > 1);
        assert(memcmp(bytes + 192, "trace_setup=ffffffb3\n", 21) == 0);
        for (size_t i = 0; i < 192; ++i) assert(bytes[i] == 'X');
        for (size_t i = 224; i < TLS_FIXER_DISARM_RESULT_SIZE; ++i) assert(bytes[i] == 'X');
        return 0;
    }
    if (strcmp(scenario, "invalid") == 0) {
        assert(tls_fixer_write_disarm_result(-1, NULL) < 0 && opens == 0);
        report.stage = NULL;
        assert(tls_fixer_write_disarm_result(-1, &report) < 0 && opens == 0);
        const char *invalid_stages[] = {"", "gate.\nforged", "UPPER", "gate=other"};
        for (size_t i = 0; i < sizeof(invalid_stages)/sizeof(invalid_stages[0]); ++i) {
            report.stage = invalid_stages[i];
            assert(tls_fixer_write_disarm_result(-1, &report) < 0 && opens == 0);
        }
        char unterminated[32];
        memset(unterminated, 'a', sizeof(unterminated));
        report.stage = unterminated;
        assert(tls_fixer_write_disarm_result(-1, &report) < 0 && opens == 0);
        return 0;
    }
    open_fail = strcmp(scenario, "open-fail") == 0;
    wrong_size = strcmp(scenario, "wrong-size") == 0;
    zero_write = strcmp(scenario, "zero-write") == 0;
    short_write = strcmp(scenario, "partial") == 0;
    sync_fail = strcmp(scenario, "sync-fail") == 0;
    close_fail = strcmp(scenario, "close-fail") == 0;
    seek_fail = strcmp(scenario, "seek-fail") == 0;
    oversized_write = strcmp(scenario, "oversized-write") == 0;
    negative_write = strcmp(scenario, "negative-write") == 0;
    int result = tls_fixer_write_disarm_result(-1, &report);
    assert((result < 0) == !!(open_fail || wrong_size || zero_write || sync_fail || close_fail ||
        seek_fail || oversized_write || negative_write));
    assert(opens == 1 && closes == (unsigned int)!open_fail);
    if (!open_fail && !wrong_size && !zero_write && !seek_fail && !oversized_write && !negative_write) {
        assert(consumed == TLS_FIXER_DISARM_RESULT_SIZE && syncs == 1);
        assert(strstr(bytes, "outcome=ffffffff") && strstr(bytes, "code=ffffd96c"));
        assert(strstr(bytes, "writes=00000001") && strstr(bytes, "stage=gate.file_sync"));
        assert(strstr(bytes, "config=00000000") && strstr(bytes, "verified=00000000"));
        assert(memcmp(bytes, "TLS_FIXER-DISARM-RESULT v1\n", sizeof("TLS_FIXER-DISARM-RESULT v1\n") - 1) == 0);
        assert(memcmp(bytes + TLS_FIXER_DISARM_RESULT_SIZE - 4, "END\n", 4) == 0);
        assert(bytes[TLS_FIXER_DISARM_RESULT_SIZE - 1] == '\n');
        assert(short_write ? writes > 1 : writes == 1);
    } else assert(writes == 0 && syncs == 0);
    puts("preallocated disarm result: no creation/truncation, exact report and I/O failure handling PASS");
    return 0;
}
