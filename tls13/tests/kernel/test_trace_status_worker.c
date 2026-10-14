#include "trace_status.h"
#include "boot_trace.h"
#include "browser_inventory.h"
#include <kernel_mock.h>
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <time.h>

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed = PTHREAD_COND_INITIALIZER;
static pthread_t thread;
static SceKernelThreadEntry callback;
static TlsFixerTraceStatus input, output[TLS_FIXER_TRACE_STATUS_MAX_UPDATES];
static unsigned int modes[TLS_FIXER_TRACE_STATUS_MAX_UPDATES], reports, polls, snapshots;
static int create_error, start_error, delete_error, wait_error, report_error, delay_error;
static int automatic_changes, exited, started, joined, deleted, exit_value;
static int enable_error;
static unsigned int enable_calls, drains;
#if TLS_FIXER_BROWSER_INVENTORY
static unsigned int inventory_resets, inventory_ticks;
void tls_fixer_browser_inventory_reset(void) { ++inventory_resets; }
void tls_fixer_browser_inventory_request(SceUID pid) { (void)pid; }
int tls_fixer_browser_inventory_tick(void) { ++inventory_ticks; return 0; }
#endif

int tls_fixer_boot_trace_enable_async(void) { ++enable_calls; return enable_error ? -14 : 0; }
int tls_fixer_boot_trace_drain(void) {
    assert(pthread_mutex_lock(&lock) == 0);
    ++drains;
    assert(pthread_mutex_unlock(&lock) == 0);
    return 0;
}

static void wait_for(unsigned int minimum_reports, unsigned int minimum_polls, int want_exit) {
    struct timespec deadline;
    assert(clock_gettime(CLOCK_REALTIME, &deadline) == 0);
    deadline.tv_sec += 3;
    assert(pthread_mutex_lock(&lock) == 0);
    while (reports < minimum_reports || polls < minimum_polls || (want_exit && !exited))
        assert(pthread_cond_timedwait(&changed, &lock, &deadline) == 0);
    assert(pthread_mutex_unlock(&lock) == 0);
}

void tls_fixer_trace_status_snapshot(TlsFixerTraceStatus *status) {
    assert(pthread_mutex_lock(&lock) == 0);
    ++snapshots;
    if (automatic_changes) ++input.attempts;
    *status = input;
    assert(pthread_mutex_unlock(&lock) == 0);
}
int tls_fixer_write_trace_runtime_result(const TlsFixerTraceStatus *status, unsigned int monitor) {
    assert(pthread_mutex_lock(&lock) == 0);
    assert(reports < TLS_FIXER_TRACE_STATUS_MAX_UPDATES);
    output[reports] = *status;
    modes[reports++] = monitor;
    int result = report_error ? -19 : 0;
    assert(pthread_cond_broadcast(&changed) == 0);
    assert(pthread_mutex_unlock(&lock) == 0);
    return result;
}
int ksceKernelDelayThread(SceUInt delay) {
    assert(delay == 100000);
    assert(pthread_mutex_lock(&lock) == 0);
    ++polls;
    int result = delay_error ? -20 : 0;
    assert(pthread_cond_broadcast(&changed) == 0);
    assert(pthread_mutex_unlock(&lock) == 0);
    if (result == 0) {
        struct timespec duration = {0, 1000000};
        nanosleep(&duration, NULL);
    }
    return result;
}
static void *run(void *unused) {
    (void)unused;
    int result = callback(0, NULL);
    assert(pthread_mutex_lock(&lock) == 0);
    exit_value = result;
    exited = 1;
    assert(pthread_cond_broadcast(&changed) == 0);
    assert(pthread_mutex_unlock(&lock) == 0);
    return NULL;
}
SceUID ksceKernelCreateThread(const char *name, SceKernelThreadEntry entry, int priority,
    SceSize stack, SceUInt attr, int affinity, const SceKernelThreadOptParam *options) {
    assert(strcmp(name, "tls_fixer trace status") == 0 && priority == 0x10000100);
    assert(stack == 0x4000 && attr == 0 && affinity == 0 && options == NULL);
    callback = entry;
    return create_error ? -10 : 71;
}
int ksceKernelStartThread(SceUID id, SceSize size, void *arguments) {
    assert(id == 71 && size == 0 && arguments == NULL);
    if (start_error) return -11;
    started = 1;
    assert(pthread_create(&thread, NULL, run, NULL) == 0);
    return 0;
}
int ksceKernelWaitThreadEnd(SceUID id, int *status, SceUInt *timeout) {
    assert(id == 71 && started && !joined && timeout != NULL && *timeout == 1000000);
    if (wait_error) return -12;
    assert(pthread_join(thread, NULL) == 0);
    joined = 1;
    *status = exit_value;
    return 0;
}
int ksceKernelDeleteThread(SceUID id) {
    assert(id == 71 && (!started || joined));
    if (delete_error) return -13;
    ++deleted;
    return 0;
}

int main(int argc, char **argv) {
    assert(argc == 2);
    const char *scenario = argv[1];
    create_error = strcmp(scenario, "create-fail") == 0;
    start_error = strcmp(scenario, "start-fail") == 0;
    report_error = strcmp(scenario, "report-fail") == 0;
    delay_error = strcmp(scenario, "delay-fail") == 0;
    automatic_changes = strcmp(scenario, "limit") == 0;
    enable_error = strcmp(scenario, "enable-fail") == 0;
    assert(tls_fixer_trace_status_stop() == 0);
    int result = tls_fixer_trace_status_start();
    if (create_error || start_error) {
        assert(result == (create_error ? -10 : -11) && !started);
        assert(tls_fixer_trace_status_stop() == 0);
        assert(deleted == !create_error);
        assert(enable_calls == 0);
        return 0;
    }
    if (enable_error) {
        assert(result == -14 && started && enable_calls == 1);
        assert(tls_fixer_trace_status_stop() == 0 && deleted == 1);
        return 0;
    }
    assert(result == 0 && tls_fixer_trace_status_start() < 0);
    assert(enable_calls == 1);
    if (automatic_changes) {
#if TLS_FIXER_BROWSER_INVENTORY
        wait_for(TLS_FIXER_TRACE_STATUS_MAX_UPDATES, TLS_FIXER_TRACE_STATUS_MAX_UPDATES + 5, 0);
        assert(pthread_mutex_lock(&lock) == 0);
        assert(!exited && reports == TLS_FIXER_TRACE_STATUS_MAX_UPDATES);
        assert(pthread_mutex_unlock(&lock) == 0);
#else
        wait_for(TLS_FIXER_TRACE_STATUS_MAX_UPDATES, 0, 1);
#endif
        assert(tls_fixer_trace_status_stop() == 0 && deleted == 1);
        assert(reports == TLS_FIXER_TRACE_STATUS_MAX_UPDATES && modes[reports - 1] == 2);
#if TLS_FIXER_BROWSER_INVENTORY
        assert(inventory_resets == 1 && inventory_ticks > TLS_FIXER_TRACE_STATUS_MAX_UPDATES);
#endif
        return 0;
    }
    if (report_error || delay_error) {
        wait_for(1, 0, 1);
        assert(tls_fixer_trace_status_stop() == 0 && reports == 1 && deleted == 1);
        assert(exit_value == (report_error ? -19 : -20));
        return 0;
    }
    wait_for(1, 3, 0);
    assert(pthread_mutex_lock(&lock) == 0);
    assert(reports == 1 && modes[0] == 1);
    input.error = -5;
    input.operation = TLS_FIXER_TRACE_ERROR_WRITE;
    input.attempts = 100;
    input.loads = 500;
    assert(pthread_mutex_unlock(&lock) == 0);
    wait_for(2, 0, 0);
    wait_error = strcmp(scenario, "wait-fail") == 0;
    delete_error = strcmp(scenario, "delete-fail") == 0;
    if (wait_error || delete_error) {
        assert(tls_fixer_trace_status_stop() == (wait_error ? -12 : -13) && deleted == 0);
        wait_error = delete_error = 0;
    }
    assert(tls_fixer_trace_status_stop() == 0 && deleted == 1);
    assert(tls_fixer_trace_status_stop() == 0 && deleted == 1);
    assert(reports == 2 && output[1].error == -5 && output[1].loads == 500);
    puts("independent bounded trace status worker: publication and lifetime PASS");
    return 0;
}
