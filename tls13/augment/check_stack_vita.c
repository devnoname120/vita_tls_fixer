#include <psp2/kernel/threadmgr/thread.h>
#include <taihen.h>
#include <stdint.h>
#include <stdatomic.h>

typedef int (*Record)(const char *, ...);
static int (*initialize)(unsigned int);
static _Atomic int init_result, free_stack, sdk_free_stack;
static _Atomic uintptr_t stack_base, entry_sp;
static _Atomic unsigned int stack_bytes;
static _Atomic int worker_id;
static _Atomic unsigned int marked_bytes, observing, phase_count;
static struct { const char *name; unsigned int after, used; } phases[64];
typedef void (*StackObserver)(const char *, unsigned int, uintptr_t);

static void stack_observer(const char *name, unsigned int after, uintptr_t sp) {
    uintptr_t base = stack_base;
    unsigned int bytes = stack_bytes, count = phase_count, marked = marked_bytes;
    if (!observing || sp < base || sp >= base + bytes || count >= 64) return;
    volatile unsigned char *begin = (volatile unsigned char *)base;
    unsigned int unused = 0;
    /* No I/O, formatting or library calls on the measured worker's stack. */
    while (unused < marked && begin[unused] == 0xa5) ++unused;
    phases[count].name = name;
    phases[count].after = after;
    phases[count].used = bytes - unused;
    phase_count = count + 1;
}

static int worker(unsigned int arguments, void *argument) {
    (void)arguments; (void)argument;
    /* Approximate the existing DailyChecker caller frames, separately from
     * the HTTP implementation. First measure on a large stack. */
    volatile unsigned char caller_frames[1536];
    for (unsigned int i = 0; i < sizeof(caller_frames); ++i) caller_frames[i] = (unsigned char)i;
    worker_id = sceKernelGetThreadId();
    sdk_free_stack = sceKernelGetThreadStackFreeSize(worker_id);
    uintptr_t sp;
    __asm__ volatile("mov %0, sp" : "=r"(sp) : : "memory");
    uintptr_t base = stack_base;
    unsigned int bytes = stack_bytes;
    entry_sp = sp;
    if (sp < base + 128 || sp > base + bytes) return -1;
    /* Only this dormant-then-owned thread's unused mapped stack is colored.
     * Leave room below the current frame; no function call occurs while filling. */
    volatile unsigned char *begin = (volatile unsigned char *)base;
    unsigned int marked = (unsigned int)(sp - base - 128);
    for (unsigned int i = 0; i < marked; ++i) begin[i] = 0xa5;
    marked_bytes = marked;
    observing = 1;
    init_result = initialize(128 * 1024);
    observing = 0;
    unsigned int unused = 0;
    while (unused < marked && begin[unused] == 0xa5) ++unused;
    free_stack = (int)unused;
    return caller_frames[0];
}

int tls_fixer_embedded_check_stack(Record log) {
    uintptr_t init_address = 0, term_address = 0;
    if (taiGetModuleExportFunc("SceLibHttp", 0xe8f15cde, 0x214926d9, &init_address) < 0 ||
        taiGetModuleExportFunc("SceLibHttp", 0xe8f15cde, 0xc9076666, &term_address) < 0) return -1;
    initialize = (void *)init_address;
    int (*terminate)(void) = (void *)term_address;
    uintptr_t observer_address = 0;
    void (*set_observer)(StackObserver) = NULL;
    if (taiGetModuleExportFunc("SceLibHttp", 0x7f10b001, 0x7f10b005, &observer_address) == 0)
        set_observer = (void *)observer_address;
    log("stack.observer available=%d\n", set_observer != NULL);
    const unsigned int sizes[] = {65536, 4096};
    for (unsigned int i = 0; i < 2; ++i) {
        SceUID thread = sceKernelCreateThread("tls_fixer stack check", worker, 0x10000100,
            sizes[i], 0, 0, NULL);
        log("stack.create bytes=%u thread=%08X padding=1536\n", sizes[i], thread);
        if (thread < 0) return -1;
        SceKernelThreadInfo info = {.size = sizeof(info)};
        int info_rc = sceKernelGetThreadInfo(thread, &info);
        log("stack.info rc=%08X base=%08X actual_bytes=%d\n", info_rc,
            (unsigned int)(uintptr_t)info.stack, info.stackSize);
        if (info_rc < 0 || !info.stack || info.stackSize != (int)sizes[i]) {
            sceKernelDeleteThread(thread);
            return -1;
        }
        stack_base = (uintptr_t)info.stack; stack_bytes = sizes[i];
        init_result = -1; free_stack = -1; sdk_free_stack = -1; worker_id = -1; entry_sp = 0;
        phase_count = 0; observing = 0; marked_bytes = 0;
        if (set_observer) set_observer(stack_observer);
        int rc = sceKernelStartThread(thread, 0, NULL);
        if (rc < 0) { sceKernelDeleteThread(thread); return -1; }
        int result = -1;
        unsigned int timeout = 30000000;
        rc = sceKernelWaitThreadEnd(thread, &result, &timeout);
        log("stack.join bytes=%u rc=%08X result=%08X init=%08X free=%d sdk_free_before=%d tid=%08X entry_sp=%08X\n",
            sizes[i], rc, result, init_result, free_stack, sdk_free_stack, worker_id, (unsigned int)entry_sp);
        if (rc < 0) return -1; /* Do not unload code under an unknown live worker. */
        if (set_observer) set_observer(NULL);
        for (unsigned int phase = 0; phase < phase_count; ++phase)
            log("stack.phase bytes=%u used=%u after=%u event=%s\n", sizes[i], phases[phase].used,
                phases[phase].after, phases[phase].name);
        if (sceKernelDeleteThread(thread) < 0 || init_result != 0 || result != 0) return -1;
        int remaining = free_stack;
        rc = terminate();
        log("stack.term bytes=%u rc=%08X used=%d\n", sizes[i], rc,
            remaining < 0 ? -1 : (int)sizes[i] - remaining);
        if (rc < 0 || remaining < 0 || remaining > (int)sizes[i]) return -1;
        if (i == 0 && sizes[i] - (unsigned int)remaining > 3584) {
            log("stack.small.skipped reason=insufficient_measured_margin\n");
            return -1;
        }
        if (i == 1 && remaining < 512) return -1;
    }
    return 0;
}
