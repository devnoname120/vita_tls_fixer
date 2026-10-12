#include "trace_status.h"
#include "disarm_result.h"
#include "boot_trace.h"

#include <psp2kern/kernel/threadmgr/thread.h>
#include <stddef.h>

static SceUID worker_id = -1;
static int worker_started;
static uint32_t stop_requested;

static int status_worker(SceSize size, void *arguments) {
    TlsFixerTraceStatus previous = {0}, current;
    unsigned int published = 0;
    int have_previous = 0;
    (void)size;
    (void)arguments;
    while (!__atomic_load_n(&stop_requested, __ATOMIC_ACQUIRE)) {
        (void)tls_fixer_boot_trace_drain();
        tls_fixer_trace_status_snapshot(&current);
        if (!have_previous || current.error != previous.error || current.operation != previous.operation ||
            current.attempts != previous.attempts || current.loads != previous.loads) {
            unsigned int mode = published + 1 == TLS_FIXER_TRACE_STATUS_MAX_UPDATES ? 2u : 1u;
            int result = tls_fixer_write_trace_runtime_result(&current, mode);
            if (result < 0) return result;
            previous = current;
            have_previous = 1;
            if (++published == TLS_FIXER_TRACE_STATUS_MAX_UPDATES) return 0;
        }
        int delay = ksceKernelDelayThread(100000);
        if (delay < 0) return delay;
    }
    (void)tls_fixer_boot_trace_drain();
    return 0;
}

int tls_fixer_trace_status_start(void) {
    if (worker_id >= 0) return -1;
    __atomic_store_n(&stop_requested, 0, __ATOMIC_RELEASE);
    worker_id = ksceKernelCreateThread("tls_fixer trace status", status_worker,
        0x10000100, 0x4000, 0, 0, NULL);
    if (worker_id < 0) return worker_id;
    int result = ksceKernelStartThread(worker_id, 0, NULL);
    if (result < 0) return result;
    worker_started = 1;
    return tls_fixer_boot_trace_enable_async();
}

int tls_fixer_trace_status_stop(void) {
    if (worker_id < 0) return 0;
    __atomic_store_n(&stop_requested, 1, __ATOMIC_RELEASE);
    if (worker_started) {
        unsigned int timeout = 1000000;
        int exit_status;
        int result = ksceKernelWaitThreadEnd(worker_id, &exit_status, &timeout);
        if (result < 0) return result;
        worker_started = 0;
    }
    int result = ksceKernelDeleteThread(worker_id);
    if (result < 0) return result;
    worker_id = -1;
    return 0;
}
