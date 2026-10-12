#include "boot_trace.h"
#include "trace_status.h"
#include <kernel_mock.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>

static char disk[TLS_FIXER_BOOT_TRACE_LIMIT * TLS_FIXER_BOOT_TRACE_RECORD_SIZE + 1];
static size_t used;
static unsigned int writes, syncs, closes;
static int open_fail, zero_write, sync_fail, close_fail, partial_write, reenter;
static int thread_fail, oversized_write;
static _Thread_local int deny_producer_write;
static unsigned int fail_write_number;
static int nested_result;
static unsigned int opens, stack_reads;
static int stack_probe_fail;
static uint32_t stack_free = 4096;

int tls_fixer_stack_probe_init(void) { return stack_probe_fail ? -91 : 0; }
uint32_t tls_fixer_stack_probe_read(void) { ++stack_reads; return stack_free; }

static int kernel_create_mode(int mode) {
    static const uint32_t accepted[] = {
        0x10186, 0x00186, 0x10106, 0x00106, 0x10104,
        0x00104, 0x10006, 0x00006, 0x10004, 0x00004
    };
    for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); ++i)
        if (((uint32_t)mode & 0x10186u) == accepted[i]) return 0;
    return (int32_t)UINT32_C(0x80010016);
}

int ksceIoOpen(const char *path, int flags, int mode) {
    ++opens;
    assert(strcmp(path, "ur0:tai/tls_fixer-startup.log") == 0);
    assert(strcmp(path, TLS_FIXER_BOOT_TRACE_PATH) == 0);
    assert(flags == (2 | 0x200 | 0x400));
    if (open_fail) return -77;
    int result = kernel_create_mode(mode);
    return result < 0 ? result : 7;
}

int ksceIoClose(SceUID fd) { assert(fd == 7); ++closes; return close_fail ? -1 : 0; }

int ksceIoPwrite(SceUID fd, const void *data, SceSize size, SceOff offset) {
    assert(fd == 7 && offset == (SceOff)used && size > 0);
    ++writes;
    if (deny_producer_write) return (int32_t)UINT32_C(0x8001000d);
    if (fail_write_number != 0 && writes == fail_write_number) return -5;
    if (oversized_write) return (int)size + 1;
    if (reenter) {
        reenter = 0;
        nested_result = tls_fixer_boot_trace_event("nested", 99, 88, 0);
    }
    if (zero_write) return 0;
    if (partial_write && size > 7) size = 7;
    assert(used + size < sizeof(disk));
    memcpy(disk + used, data, size);
    used += size;
    return (int)size;
}

int ksceIoSync(const char *path, unsigned int flags) {
    assert(strcmp(path, TLS_FIXER_BOOT_TRACE_PATH) == 0 && flags == 0);
    ++syncs;
    return sync_fail ? -78 : 0;
}

int ksceKernelGetThreadId(void) { return thread_fail ? -1 : 123; }
int64_t ksceKernelGetSystemTimeWide(void) { return INT64_C(0x100000002); }

#if TLS_FIXER_TRACE_MODULE_PATHS
static unsigned int concurrent_start, concurrent_done;
static void wait_round(const unsigned int *value, unsigned int wanted) {
    while (__atomic_load_n(value, __ATOMIC_ACQUIRE) < wanted) {
        struct timespec pause = {0, 10000};
        nanosleep(&pause, NULL);
    }
}
static void *concurrent_drain(void *unused) {
    (void)unused;
    for (unsigned int round = 1; round <= 32; ++round) {
        wait_round(&concurrent_start, round);
        assert(tls_fixer_boot_trace_drain() == 0);
        __atomic_store_n(&concurrent_done, round, __ATOMIC_RELEASE);
    }
    return NULL;
}
#endif

int main(int argc, char **argv) {
    const char *scenario;
    assert(argc == 2);
    scenario = argv[1];
    assert(kernel_create_mode(0600) == (int32_t)UINT32_C(0x80010016));
    assert(kernel_create_mode(0006) == 0);
#if defined(TLS_FIXER_STACK_HEADROOM) && TLS_FIXER_STACK_HEADROOM
    if (strcmp(scenario, "stack-probe-fail") == 0) {
        stack_probe_fail = 1;
        assert(tls_fixer_boot_trace_open() < 0 && opens == 0 && writes == 0 && stack_reads == 0);
        return 0;
    }
    if (strcmp(scenario, "no-headroom") == 0) stack_free = 0;
#endif
    if (strcmp(scenario, "before-open") == 0) {
        assert(tls_fixer_boot_trace_event("unused", 0, 0, 0) < 0);
        assert(writes == 0 && syncs == 0 && closes == 0);
    }
    if (strcmp(scenario, "open-fail") == 0) {
        open_fail = 1;
        assert(tls_fixer_boot_trace_open() == -77 && writes == 0 && syncs == 0);
        assert(tls_fixer_boot_trace_event("unused", 0, 0, 0) < 0);
        return 0;
    }
    if (strcmp(scenario, "initial-sync-fail") == 0) {
        sync_fail = 1;
        assert(tls_fixer_boot_trace_open() == -78 && writes > 0 && syncs == 1 && closes == 1);
        return 0;
    }
    if (strcmp(scenario, "partial") == 0) partial_write = 1;
    assert(tls_fixer_boot_trace_open() == 0);
    assert(strstr(disk, "stage=trace.open") != NULL && syncs == 1);
#if defined(TLS_FIXER_STACK_HEADROOM) && TLS_FIXER_STACK_HEADROOM
    assert(strstr(disk, stack_free ? " free=00001000" : " free=00000000") != NULL);
    assert(stack_reads == 1);
    if (strcmp(scenario, "unknown-headroom") == 0) {
        unsigned int before = writes;
        stack_free = UINT32_MAX;
        assert(tls_fixer_boot_trace_event("unknown", 0, 0, 0) < 0);
        assert(writes == before && syncs == 1);
        stack_free = 4096;
        assert(tls_fixer_boot_trace_event("must.not.resume", 0, 0, 0) < 0);
        assert(tls_fixer_boot_trace_close() == 0);
        return 0;
    }
#else
    assert(stack_reads == 0 && strstr(disk, " free=") == NULL);
#endif
    assert(tls_fixer_boot_trace_open() < 0);
#if TLS_FIXER_TRACE_MODULE_PATHS
    if (strcmp(scenario, "async-concurrent") == 0) {
        pthread_t consumer;
        TlsFixerTraceStatus observed;
        assert(tls_fixer_boot_trace_enable_async() == 0);
        assert(pthread_create(&consumer, NULL, concurrent_drain, NULL) == 0);
        deny_producer_write = 1;
        for (unsigned int round = 1; round <= 32; ++round) {
            __atomic_store_n(&concurrent_start, round, __ATOMIC_RELEASE);
            for (unsigned int item = 0; item < 8; ++item)
                assert(tls_fixer_boot_trace_event("parallel", 99, (int32_t)((round - 1) * 8 + item), 0) == 0);
            wait_round(&concurrent_done, round);
        }
        assert(pthread_join(consumer, NULL) == 0);
        deny_producer_write = 0;
        assert(tls_fixer_boot_trace_drain() == 0);
        tls_fixer_trace_status_snapshot(&observed);
        assert(observed.error == 0 && observed.operation == 0 && observed.attempts == 257);
        char *line = disk;
        for (unsigned int index = 0; index < 257; ++index) {
            unsigned int sequence, object;
            assert(sscanf(line, "tls_fixer-trace1 seq=%x tid=%*x pid=%*x obj=%x", &sequence, &object) == 2);
            assert(sequence == index && (index == 0 || object == index - 1));
            line = strchr(line, '\n');
            assert(line != NULL);
            ++line;
        }
        assert(*line == '\0' && syncs == 257);
        assert(tls_fixer_boot_trace_close() == 0);
        return 0;
    }
    if (strncmp(scenario, "async-", 6) == 0) {
        TlsFixerTraceStatus observed;
        unsigned int prior_writes = writes, prior_syncs = syncs;
        char owned_path[] = "mount:webcore/ScePsp2Compat.suprx";
        assert(tls_fixer_boot_trace_enable_async() == 0);
        deny_producer_write = 1;
        assert(tls_fixer_boot_trace_path("queued.first", 99, 3, 0x1000, owned_path) == 0);
        owned_path[0] = 'X';
        assert(writes == prior_writes && syncs == prior_syncs);
        if (strcmp(scenario, "async-full") == 0) {
            for (unsigned int i = 1; i < TLS_FIXER_BOOT_TRACE_QUEUE_RECORDS; ++i)
                assert(tls_fixer_boot_trace_event("queued", 99, (int32_t)i, 0) == 0);
            assert(tls_fixer_boot_trace_event("over.queue", 99, 0, 0) < 0);
            tls_fixer_trace_status_snapshot(&observed);
            assert(observed.operation == TLS_FIXER_TRACE_ERROR_QUEUE);
        }
        deny_producer_write = 0;
        if (strcmp(scenario, "async-partial") == 0) partial_write = 1;
        if (strcmp(scenario, "async-reentry") == 0) reenter = 1;
        if (strcmp(scenario, "async-write-fail") == 0) fail_write_number = writes + 1;
        if (strcmp(scenario, "async-sync-fail") == 0) sync_fail = 1;
        int failure = fail_write_number != 0 || sync_fail;
        assert((tls_fixer_boot_trace_drain() < 0) == failure);
        tls_fixer_trace_status_snapshot(&observed);
        if (failure) {
            assert(observed.operation == (sync_fail ? TLS_FIXER_TRACE_ERROR_SYNC : TLS_FIXER_TRACE_ERROR_WRITE));
            assert(observed.error == (sync_fail ? -78 : -5));
            prior_writes = writes;
            assert(tls_fixer_boot_trace_drain() < 0 && writes == prior_writes);
            assert(tls_fixer_boot_trace_event("refused", 99, 0, 0) < 0);
        } else {
            assert(strstr(disk, "stage=queued.first") != NULL);
            assert(strstr(disk, "path=6d6f756e743a") != NULL);
            assert(strstr(disk, "path=586f756e743a") == NULL);
            if (strcmp(scenario, "async-reentry") == 0)
                assert(nested_result == 0 && strstr(disk, "stage=nested") != NULL);
            prior_writes = writes;
            assert(tls_fixer_boot_trace_drain() == 0 && writes == prior_writes);
            assert(tls_fixer_boot_trace_enable_async() < 0);
        }
        assert(tls_fixer_boot_trace_close() == 0);
        puts("asynchronous trace: producer performs no I/O; owned FIFO and consumer failures PASS");
        return 0;
    }
    if (strncmp(scenario, "status-", 7) == 0) {
        TlsFixerTraceStatus observed;
        tls_fixer_trace_status_snapshot(&observed);
        assert(observed.attempts == 1 && observed.loads == 0 && observed.error == 0 && observed.operation == 0);
        tls_fixer_trace_status_note_load();
        tls_fixer_trace_status_note_load();
        int want = 0;
        uint32_t operation = TLS_FIXER_TRACE_ERROR_NONE;
        if (strcmp(scenario, "status-write-fail") == 0) {
            fail_write_number = writes + 1; want = -5; operation = TLS_FIXER_TRACE_ERROR_WRITE;
        } else if (strcmp(scenario, "status-sync-fail") == 0) {
            sync_fail = 1; want = -78; operation = TLS_FIXER_TRACE_ERROR_SYNC;
        } else if (strcmp(scenario, "status-thread-fail") == 0) {
            thread_fail = 1; want = -1; operation = TLS_FIXER_TRACE_ERROR_THREAD;
        } else if (strcmp(scenario, "status-reentry") == 0) reenter = 1;
        assert((tls_fixer_boot_trace_event("status.check", 99, 0, 0) < 0) == (want != 0));
        tls_fixer_trace_status_snapshot(&observed);
        assert(observed.attempts == (strcmp(scenario, "status-reentry") == 0 ? 3u : 2u));
        assert(observed.loads == 2 && observed.error == want && observed.operation == operation);
        if (want) {
            fail_write_number = 0; sync_fail = thread_fail = 0;
            assert(tls_fixer_boot_trace_event("refused", 99, 0, 0) < 0);
            tls_fixer_trace_status_snapshot(&observed);
            assert(observed.attempts == 3 && observed.error == want && observed.operation == operation);
        }
        assert(tls_fixer_boot_trace_close() == 0);
        return 0;
    }
    if (strncmp(scenario, "path-", 5) == 0) {
        char path[1024];
        memset(path, 'x', sizeof(path));
        const char *value = "abc:/webcore/ScePsp2Compat.suprx";
        if (strcmp(scenario, "path-encoded") == 0) value = "a:\n \xff%";
        if (strcmp(scenario, "path-null") == 0) value = NULL;
        if (strcmp(scenario, "path-empty") == 0) value = "";
        if (strcmp(scenario, "path-long") == 0) { path[200] = '\0'; value = path; }
        if (strcmp(scenario, "path-unbounded") == 0) value = path;
        if (strcmp(scenario, "path-partial") == 0) partial_write = 1;
        if (strcmp(scenario, "path-reentry") == 0) reenter = 1;
        if (strcmp(scenario, "path-sync-fail") == 0) sync_fail = 1;
        size_t before = used;
        int result = tls_fixer_boot_trace_path("load.enter", 99, 0, 0x1000, value);
        if (sync_fail) {
            assert(result < 0);
            sync_fail = 0;
            assert(tls_fixer_boot_trace_path("load.enter", 99, 0, 0, value) < 0);
        } else {
            assert(result == 0 && syncs == 2);
            const char *line = disk + before;
            assert(used - before <= TLS_FIXER_BOOT_TRACE_RECORD_SIZE);
            assert(strstr(line, "stage=load.enter pathlen=") != NULL);
            if (value == NULL) assert(strstr(line, "pathlen=ffffffff path=\n") != NULL);
            else if (*value == '\0') assert(strstr(line, "pathlen=00000000 path=\n") != NULL);
            else if (strcmp(scenario, "path-encoded") == 0)
                assert(strstr(line, "pathlen=00000006 path=613a0a20ff25\n") != NULL);
            else if (value == path) {
                assert(strstr(line, strcmp(scenario, "path-long") == 0
                    ? "pathlen=000000c8 path=" : "pathlen=00000400 path=") != NULL);
                const char *encoded = strstr(line, " path=") + 6;
                assert(strlen(encoded) == 2 * TLS_FIXER_BOOT_TRACE_PATH_BYTES + 1);
                for (size_t i = 0; i < 2 * TLS_FIXER_BOOT_TRACE_PATH_BYTES; ++i)
                    assert(encoded[i] == ((i & 1) ? '8' : '7'));
            } else assert(strstr(line, "path=6162633a2f776562636f72652f53636550737032436f6d7061742e7375707278\n") != NULL);
            if (strcmp(scenario, "path-reentry") == 0) assert(nested_result < 0);
            if (strcmp(scenario, "path-partial") == 0) assert(writes > 2);
        }
        assert(tls_fixer_boot_trace_close() == 0);
        puts("bounded hex-encoded module path trace: PASS");
        return 0;
    }
#endif
    if (strcmp(scenario, "bad-stage") == 0) {
        char longest[32], too_long[33];
        memset(longest, 'a', sizeof(longest) - 1);
        longest[sizeof(longest) - 1] = '\0';
        memset(too_long, 'a', sizeof(too_long) - 1);
        too_long[sizeof(too_long) - 1] = '\0';
        const char *invalid[] = {NULL, "", "bad\nstage", "bad stage", "BAD", too_long};
        unsigned int prior = writes;
        for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
            assert(tls_fixer_boot_trace_event(invalid[i], 0, 0, 0) < 0);
        assert(writes == prior && syncs == 1);
        size_t before = used;
        assert(tls_fixer_boot_trace_event(longest, INT32_MIN, INT32_MAX, -1) == 0);
        assert(used - before <= TLS_FIXER_BOOT_TRACE_RECORD_SIZE);
        assert(strstr(disk, "pid=80000000") && strstr(disk, "obj=7fffffff"));
    } else if (strcmp(scenario, "thread-fail") == 0) {
        thread_fail = 1;
        unsigned int prior = writes;
        assert(tls_fixer_boot_trace_event("scan.enter", 99, 88, 0) < 0);
        assert(writes == prior && syncs == 1);
        thread_fail = 0;
        assert(tls_fixer_boot_trace_event("must.not.resume", 0, 0, 0) < 0);
    } else if (strcmp(scenario, "short-write-fail") == 0 || strcmp(scenario, "oversized-write") == 0) {
        partial_write = strcmp(scenario, "short-write-fail") == 0;
        oversized_write = !partial_write;
        fail_write_number = partial_write ? writes + 2 : 0;
        size_t before = used;
        assert(tls_fixer_boot_trace_event("scan.enter", 99, 88, 0) < 0);
        assert(used == before + (partial_write ? 7 : 0) && syncs == 1);
        oversized_write = 0;
        fail_write_number = 0;
        assert(tls_fixer_boot_trace_event("must.not.resume", 0, 0, 0) < 0);
    } else if (strcmp(scenario, "zero-write") == 0) {
        zero_write = 1;
        unsigned int prior = syncs;
        assert(tls_fixer_boot_trace_event("scan.enter", 99, 88, -4) < 0 && syncs == prior);
        zero_write = 0;
        assert(tls_fixer_boot_trace_event("must.not.resume", 0, 0, 0) < 0);
    } else if (strcmp(scenario, "sync-fail") == 0) {
        sync_fail = 1;
        assert(tls_fixer_boot_trace_event("scan.enter", 99, 88, -4) < 0);
        sync_fail = 0;
        assert(tls_fixer_boot_trace_event("must.not.resume", 0, 0, 0) < 0);
    } else if (strcmp(scenario, "limit") == 0) {
        for (unsigned int i = 1; i < TLS_FIXER_BOOT_TRACE_LIMIT; ++i)
            assert(tls_fixer_boot_trace_event("bounded", 99, 88, 0) == 0);
        assert(tls_fixer_boot_trace_event("over.limit", 99, 88, 0) < 0);
        assert(syncs == TLS_FIXER_BOOT_TRACE_LIMIT);
        assert(used < TLS_FIXER_BOOT_TRACE_LIMIT * TLS_FIXER_BOOT_TRACE_RECORD_SIZE);
    } else {
        if (strcmp(scenario, "reentry") == 0) reenter = 1;
        assert(tls_fixer_boot_trace_event("scan.enter", 99, 88, -4) == 0);
        assert(strstr(disk, "tid=0000007b") && strstr(disk, "pid=00000063"));
        assert(strstr(disk, "obj=00000058") && strstr(disk, "rc=fffffffc"));
        assert(strstr(disk, "us=0000000100000002") && strstr(disk, "seq=00000001"));
        assert(syncs == 2);
        if (strcmp(scenario, "reentry") == 0) assert(nested_result < 0 && strstr(disk, "stage=nested") == NULL);
        if (strcmp(scenario, "partial") == 0) assert(writes > 2);
        if (strcmp(scenario, "close-fail") == 0) close_fail = 1;
    }
    assert((tls_fixer_boot_trace_close() < 0) == !!close_fail);
    assert(closes == 1);
    assert(tls_fixer_boot_trace_event("closed", 0, 0, 0) < 0);
    puts("bounded synchronized kernel startup trace: PASS");
    return 0;
}
