#include "boot_trace.h"
#include "stack_probe.h"
#include "trace_status.h"

#ifndef TLS_FIXER_STACK_HEADROOM
#define TLS_FIXER_STACK_HEADROOM 0
#endif

#include <psp2kern/io/fcntl.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/kernel/threadmgr/thread.h>
#include <psp2kern/kernel/threadmgr/misc.h>

#ifndef SCE_O_TRUNC
#define SCE_O_TRUNC 0x0400
#endif

static SceUID descriptor = -1;
static uint32_t started, busy;
static unsigned int records, failed;
static SceOff position;
/* The loader's kernel stack is small; formatting must not add another record-sized frame. */
static char record[TLS_FIXER_BOOT_TRACE_RECORD_SIZE];

#if TLS_FIXER_TRACE_MODULE_PATHS
static uint32_t attempted_records, observed_loads, failure_operation, failure_claimed;
static int32_t failure_result;
static uint32_t deferred, drain_busy, queue_head, queue_tail;
static int io_failure;
static struct {
    uint16_t size;
    char data[TLS_FIXER_BOOT_TRACE_RECORD_SIZE];
} queue[TLS_FIXER_BOOT_TRACE_QUEUE_RECORDS];
void tls_fixer_trace_status_note_load(void) {
    (void)__atomic_fetch_add(&observed_loads, 1, __ATOMIC_RELAXED);
}
void tls_fixer_trace_status_snapshot(TlsFixerTraceStatus *status) {
    if (status == NULL) return;
    status->operation = __atomic_load_n(&failure_operation, __ATOMIC_ACQUIRE);
    status->error = status->operation == 0 ? 0 : __atomic_load_n(&failure_result, __ATOMIC_RELAXED);
    status->attempts = __atomic_load_n(&attempted_records, __ATOMIC_RELAXED);
    status->loads = __atomic_load_n(&observed_loads, __ATOMIC_RELAXED);
}
static void record_failure(uint32_t operation, int32_t result) {
    uint32_t expected = 0;
    if (!__atomic_compare_exchange_n(&failure_claimed, &expected, 1, 0,
            __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) return;
    __atomic_store_n(&failure_result, result, __ATOMIC_RELAXED);
    __atomic_store_n(&failure_operation, operation, __ATOMIC_RELEASE);
}

int tls_fixer_boot_trace_enable_async(void) {
    uint32_t expected = 0;
    if (!__atomic_compare_exchange_n(&busy, &expected, 1, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) return -1;
    int result = -1;
    if (descriptor >= 0 && !__atomic_load_n(&failed, __ATOMIC_ACQUIRE) &&
        !__atomic_load_n(&deferred, __ATOMIC_RELAXED)) {
        __atomic_store_n(&deferred, 1, __ATOMIC_RELEASE);
        result = 0;
    }
    __atomic_store_n(&busy, 0, __ATOMIC_RELEASE);
    return result;
}

int tls_fixer_boot_trace_drain(void) {
    uint32_t expected = 0;
    int result = 0;
    if (!__atomic_load_n(&deferred, __ATOMIC_ACQUIRE)) return 0;
    if (!__atomic_compare_exchange_n(&drain_busy, &expected, 1, 0,
            __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) return -1;
    if (descriptor < 0 || io_failure) { result = io_failure ? io_failure : -1; goto done; }
    for (unsigned int i = 0; i < TLS_FIXER_BOOT_TRACE_QUEUE_RECORDS; ++i) {
        uint32_t head = __atomic_load_n(&queue_head, __ATOMIC_RELAXED);
        if (head == __atomic_load_n(&queue_tail, __ATOMIC_ACQUIRE)) break;
        size_t slot = head % TLS_FIXER_BOOT_TRACE_QUEUE_RECORDS;
        size_t size = queue[slot].size, sent = 0;
        while (sent < size) {
            int count = ksceIoPwrite(descriptor, queue[slot].data + sent,
                (SceSize)(size - sent), position + (SceOff)sent);
            if (count <= 0 || (size_t)count > size - sent) {
                result = count < 0 ? count : -1;
                record_failure(TLS_FIXER_TRACE_ERROR_WRITE, result);
                goto broken;
            }
            sent += (size_t)count;
        }
        result = ksceIoSync(TLS_FIXER_BOOT_TRACE_PATH, 0);
        if (result < 0) { record_failure(TLS_FIXER_TRACE_ERROR_SYNC, result); goto broken; }
        position += (SceOff)size;
        __atomic_store_n(&queue_head, head + 1, __ATOMIC_RELEASE);
    }
    goto done;
broken:
    io_failure = result;
    __atomic_store_n(&failed, 1, __ATOMIC_RELEASE);
done:
    __atomic_store_n(&drain_busy, 0, __ATOMIC_RELEASE);
    return result;
}
#endif

static size_t text(size_t offset, const char *value) {
    while (*value != '\0') record[offset++] = *value++;
    return offset;
}

static size_t hex32(size_t offset, uint32_t value) {
    static const char digits[] = "0123456789abcdef";
    for (unsigned int i = 0; i < 8; ++i) {
        record[offset++] = digits[(value >> (28 - 4 * i)) & 15];
    }
    return offset;
}

static int trace_event(const char *stage, int32_t pid, int32_t object, int32_t result
#if TLS_FIXER_TRACE_MODULE_PATHS
    , const char *path, uint32_t path_length, int include_path
#endif
) {
    uint32_t expected = 0, stack = 0;
    uint64_t now;
    uint32_t stack_free = 0;
    int thread, status = -1;
    size_t size = 0, sent = 0, stage_size = 0;
#if TLS_FIXER_TRACE_MODULE_PATHS
    uint32_t failure_step = TLS_FIXER_TRACE_ERROR_NONE;
    (void)__atomic_fetch_add(&attempted_records, 1, __ATOMIC_RELAXED);
#endif

    if (!__atomic_compare_exchange_n(&busy, &expected, 1, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) return -1;
#if TLS_FIXER_TRACE_MODULE_PATHS
    if (!__atomic_load_n(&failed, __ATOMIC_ACQUIRE) && records >= TLS_FIXER_BOOT_TRACE_LIMIT) {
        record_failure(TLS_FIXER_TRACE_ERROR_LIMIT, -1);
        __atomic_store_n(&failed, 1, __ATOMIC_RELEASE);
    }
#endif
    if (descriptor < 0 || __atomic_load_n(&failed, __ATOMIC_ACQUIRE) ||
        records >= TLS_FIXER_BOOT_TRACE_LIMIT || stage == NULL) goto done;
    while (stage_size < 32 && stage[stage_size] != '\0') {
        char c = stage[stage_size++];
        if (!((c >= 'a' && c <= 'z') || c == '.' || c == '_' || (c >= '0' && c <= '9'))) goto done;
    }
    if (stage_size == 0 || stage_size == 32) goto done;
#if TLS_FIXER_TRACE_MODULE_PATHS
    failure_step = TLS_FIXER_TRACE_ERROR_THREAD;
#endif
    thread = ksceKernelGetThreadId();
    if (thread < 0) { status = thread; goto broken; }
    now = (uint64_t)ksceKernelGetSystemTimeWide();
#if defined(__arm__)
    __asm__ volatile("mov %0, sp" : "=r"(stack));
#endif
    if (TLS_FIXER_STACK_HEADROOM) {
#if TLS_FIXER_TRACE_MODULE_PATHS
        failure_step = TLS_FIXER_TRACE_ERROR_STACK;
#endif
        stack_free = tls_fixer_stack_probe_read();
        if (stack_free == UINT32_MAX) goto broken;
    }
    size = text(size, "tls_fixer-trace1 seq=");
    size = hex32(size, records);
    size = text(size, " tid="); size = hex32(size, (uint32_t)thread);
    size = text(size, " pid="); size = hex32(size, (uint32_t)pid);
    size = text(size, " obj="); size = hex32(size, (uint32_t)object);
    size = text(size, " rc="); size = hex32(size, (uint32_t)result);
    size = text(size, " sp="); size = hex32(size, stack);
    if (TLS_FIXER_STACK_HEADROOM) { size = text(size, " free="); size = hex32(size, stack_free); }
    size = text(size, " us="); size = hex32(size, (uint32_t)(now >> 32)); size = hex32(size, (uint32_t)now);
    size = text(size, " stage="); size = text(size, stage);
#if TLS_FIXER_TRACE_MODULE_PATHS
    if (include_path) {
        static const char digits[] = "0123456789abcdef";
        _Static_assert(TLS_FIXER_BOOT_TRACE_RECORD_SIZE >= 192 + 24 + 2 * TLS_FIXER_BOOT_TRACE_PATH_BYTES,
            "Path records require space for the complete bounded encoding");
        size = text(size, " pathlen="); size = hex32(size, path_length);
        size = text(size, " path=");
        size_t captured = path_length > TLS_FIXER_BOOT_TRACE_PATH_BYTES ? TLS_FIXER_BOOT_TRACE_PATH_BYTES : path_length;
        if (path == NULL) captured = 0;
        for (size_t i = 0; i < captured; ++i) {
            unsigned char byte = (unsigned char)path[i];
            record[size++] = digits[byte >> 4];
            record[size++] = digits[byte & 15];
        }
    }
#endif
    record[size++] = '\n';
#if TLS_FIXER_TRACE_MODULE_PATHS
    if (__atomic_load_n(&deferred, __ATOMIC_ACQUIRE)) {
        uint32_t tail = __atomic_load_n(&queue_tail, __ATOMIC_RELAXED);
        uint32_t head = __atomic_load_n(&queue_head, __ATOMIC_ACQUIRE);
        if (tail - head >= TLS_FIXER_BOOT_TRACE_QUEUE_RECORDS) {
            failure_step = TLS_FIXER_TRACE_ERROR_QUEUE;
            goto broken;
        }
        size_t slot = tail % TLS_FIXER_BOOT_TRACE_QUEUE_RECORDS;
        memcpy(queue[slot].data, record, size);
        queue[slot].size = (uint16_t)size;
        __atomic_store_n(&queue_tail, tail + 1, __ATOMIC_RELEASE);
        ++records;
        status = 0;
        goto done;
    }
    failure_step = TLS_FIXER_TRACE_ERROR_WRITE;
#endif
    while (sent < size) {
        int written = ksceIoPwrite(descriptor, record + sent, (SceSize)(size - sent), position + (SceOff)sent);
        if (written <= 0 || (size_t)written > size - sent) {
            status = written < 0 ? written : -1;
            goto broken;
        }
        sent += (size_t)written;
    }
#if TLS_FIXER_TRACE_MODULE_PATHS
    failure_step = TLS_FIXER_TRACE_ERROR_SYNC;
#endif
    int sync_result = ksceIoSync(TLS_FIXER_BOOT_TRACE_PATH, 0);
    if (sync_result < 0) { status = sync_result; goto broken; }
    position += (SceOff)size;
    ++records;
    status = 0;
    goto done;
broken:
#if TLS_FIXER_TRACE_MODULE_PATHS
    record_failure(failure_step, status);
#endif
    __atomic_store_n(&failed, 1, __ATOMIC_RELEASE);
done:
    __atomic_store_n(&busy, 0, __ATOMIC_RELEASE);
    return status;
}

int tls_fixer_boot_trace_event(const char *stage, int32_t pid, int32_t object, int32_t result) {
    return trace_event(stage, pid, object, result
#if TLS_FIXER_TRACE_MODULE_PATHS
        , NULL, 0, 0
#endif
    );
}

#if TLS_FIXER_TRACE_MODULE_PATHS
int tls_fixer_boot_trace_path(const char *stage, int32_t pid, int32_t object, int32_t result,
    const char *path) {
    uint32_t length = 0;
    if (path == NULL) length = UINT32_MAX;
    else while (length < 1024 && path[length] != '\0') ++length;
    return trace_event(stage, pid, object, result, path, length, 1);
}
#endif

int tls_fixer_boot_trace_open(void) {
    uint32_t expected = 0;
    if (!__atomic_compare_exchange_n(&started, &expected, 1, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) return -1;
    if (TLS_FIXER_STACK_HEADROOM) {
        int probe = tls_fixer_stack_probe_init();
        if (probe < 0) return probe;
    }
    /* Kernel-mode exFAT creation rejects POSIX 0600; 0006 selects a supported mode. */
    descriptor = ksceIoOpen(TLS_FIXER_BOOT_TRACE_PATH, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0006);
    if (descriptor < 0) return descriptor;
    int result = tls_fixer_boot_trace_event("trace.open", 0, 0, 0);
    if (result == 0) return 0;
    (void)tls_fixer_boot_trace_close();
    return result;
}

int tls_fixer_boot_trace_close(void) {
    uint32_t expected = 0;
    int result = 0;
#if TLS_FIXER_TRACE_MODULE_PATHS
    if (!__atomic_compare_exchange_n(&drain_busy, &expected, 1, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) return -1;
    expected = 0;
#endif
    if (!__atomic_compare_exchange_n(&busy, &expected, 1, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
#if TLS_FIXER_TRACE_MODULE_PATHS
        __atomic_store_n(&drain_busy, 0, __ATOMIC_RELEASE);
#endif
        return -1;
    }
    __atomic_store_n(&failed, 1, __ATOMIC_RELEASE);
    if (descriptor >= 0) {
        result = ksceIoClose(descriptor);
        descriptor = -1;
    }
    __atomic_store_n(&busy, 0, __ATOMIC_RELEASE);
#if TLS_FIXER_TRACE_MODULE_PATHS
    __atomic_store_n(&drain_busy, 0, __ATOMIC_RELEASE);
#endif
    return result;
}
