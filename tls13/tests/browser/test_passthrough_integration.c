#include "backend.h"
#include "module_descriptor.h"
#include "tls_fixer/browser_start_diagnostics.h"
#include <psp2/kernel/sysmem.h>
#include <psp2common/kernel/modulemgr.h>
#include <taihen.h>
#include <vita_mock.h>

#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int module_start(SceSize, const void *);
int module_stop(SceSize, const void *);

enum { CLOSE, PENDING, CHECK, CONNECT, HOOK_COUNT };
static SceKernelModuleInfo mapped;
static struct _tai_hook_user references[HOOK_COUNT], next_hooks[HOOK_COUNT];
static const void *callbacks[HOOK_COUNT];
static int hook_attempts, installed, fail_hook = -1;
static unsigned int original_calls[HOOK_COUNT], next_calls[HOOK_COUNT];
static _Thread_local void *expected_connection;
static _Thread_local int expected_index, expected_result;
static _Thread_local unsigned char expected_nonblocking, expected_done;

int sceKernelGetModuleInfo(SceUID id, SceKernelModuleInfo *info) {
    assert(id == 88 && info->size == sizeof(*info));
    *info = mapped;
    return 0;
}

SceUID sceKernelGetModuleIdByAddr(void *address) {
    (void)address;
    return -1;
}

int sceKernelGetMemBlockInfoByAddr(void *base, SceKernelMemBlockInfo *info) {
    (void)base;
    (void)info;
    return -1;
}

static int original_result(unsigned int kind, void *connection, int index) {
    assert(connection == expected_connection && index == expected_index);
    __atomic_add_fetch(&original_calls[kind], 1, __ATOMIC_RELAXED);
    return expected_result;
}

static int original_close(void *connection, int index) { return original_result(CLOSE, connection, index); }
static int original_pending(void *connection, int index) { return original_result(PENDING, connection, index); }
static int original_check(void *connection) { return original_result(CHECK, connection, expected_index); }
static int original_connect(void *connection, int index, unsigned char nonblocking, unsigned char *done) {
    assert(nonblocking == expected_nonblocking && done != NULL);
    *done = expected_done;
    return original_result(CONNECT, connection, index);
}

static int next_close(void *connection, int index) {
    __atomic_add_fetch(&next_calls[CLOSE], 1, __ATOMIC_RELAXED);
    return original_close(connection, index);
}
static int next_pending(void *connection, int index) {
    __atomic_add_fetch(&next_calls[PENDING], 1, __ATOMIC_RELAXED);
    return original_pending(connection, index);
}
static int next_check(void *connection) {
    __atomic_add_fetch(&next_calls[CHECK], 1, __ATOMIC_RELAXED);
    return original_check(connection);
}
static int next_connect(void *connection, int index, unsigned char nonblocking, unsigned char *done) {
    __atomic_add_fetch(&next_calls[CONNECT], 1, __ATOMIC_RELAXED);
    return original_connect(connection, index, nonblocking, done);
}

int taiHookFunctionOffset(tai_hook_ref_t *reference, int id, int segment,
    size_t offset, int thumb, const void *function) {
    static const size_t offsets[] = {TLS_FIXER_BROWSER_CLOSE_OFFSET, TLS_FIXER_BROWSER_PENDING_OFFSET,
        TLS_FIXER_BROWSER_CHECK_OFFSET, TLS_FIXER_BROWSER_CONNECT_OFFSET};
    static void *const originals[] = {(void *)original_close, (void *)original_pending,
        (void *)original_check, (void *)original_connect};
    int attempt = hook_attempts++;
    assert(id == 88 && segment == 0 && thumb == 1 && attempt < HOOK_COUNT);
    assert(offset == offsets[attempt] && function != NULL);
    if (attempt == fail_hook) return -1234;
    references[attempt].func = (void *)function;
    references[attempt].old = originals[attempt];
    callbacks[attempt] = function;
    *reference = (uintptr_t)&references[attempt];
    ++installed;
    return attempt + 1;
}

int __wrap_sceNetSend(int fd, const void *data, unsigned int size, int flags) {
    (void)fd; (void)data; (void)size; (void)flags;
    assert(!"The disabled provider must not perform TLS network I/O");
    return -1;
}
int __wrap_sceNetRecv(int fd, void *data, unsigned int size, int flags) {
    (void)fd; (void)data; (void)size; (void)flags;
    assert(!"The disabled provider must not perform TLS network I/O");
    return -1;
}

static void *exercise(void *unused) {
    static const int results[] = {-1, 0, 1, 35, 81};
    unsigned char native[512], before[sizeof(native)];
    (void)unused;
    /* Invalid embedded pointers expose accidental option parsing in the disabled backend. */
    memset(native, 0xa5, sizeof(native));
    memcpy(before, native, sizeof(before));
    expected_connection = native;
    for (unsigned int iteration = 0; iteration < 100; ++iteration) {
        expected_index = (int)(iteration % 2);
        expected_nonblocking = (unsigned char)((iteration / 2) % 2);
        expected_done = (unsigned char)((iteration / 4) % 2);
        expected_result = results[iteration % (sizeof(results) / sizeof(results[0]))];
        for (int kind = 0; kind < installed; ++kind) {
            int result;
            if (kind == CONNECT) {
                unsigned char done = 0xff;
                int (*call)(void *, int, unsigned char, unsigned char *) = (void *)callbacks[kind];
                result = call(native, expected_index, expected_nonblocking, &done);
                assert(done == expected_done);
            } else if (kind == CHECK) {
                int (*call)(void *) = (void *)callbacks[kind];
                result = call(native);
            } else {
                int (*call)(void *, int) = (void *)callbacks[kind];
                result = call(native, expected_index);
            }
            assert(result == expected_result);
            assert(memcmp(native, before, sizeof(native)) == 0);
            assert(tls_fixer_browser_connection_count() == 0);
        }
    }
    expected_connection = NULL;
    return NULL;
}

int main(int argc, char **argv) {
    assert(argc == 3);
    const char *scenario = argv[2];
    int chain = strcmp(scenario, "chain") == 0 || strcmp(scenario, "concurrent") == 0;
    unsigned int workers = strcmp(scenario, "concurrent") == 0 ? 4 : 1;
    unsigned char *text = calloc(1, TLS_FIXER_BROWSER_TEXT_MEMSZ);
    unsigned char *data = calloc(1, TLS_FIXER_BROWSER_DATA_MEMSZ);
    assert(text != NULL && data != NULL);
    mock_ca_file = argv[1];
    mapped.size = sizeof(mapped);
    strcpy(mapped.module_name, "ScePsp2Compat");
    strcpy(mapped.path, "vs0:/data/external/tls_fixer/ScePsp2Compat.suprx");
    mapped.segments[0] = (SceKernelSegmentInfo){.vaddr = text,
        .filesz = TLS_FIXER_BROWSER_TEXT_FILESZ, .memsz = TLS_FIXER_BROWSER_TEXT_MEMSZ};
    mapped.segments[1] = (SceKernelSegmentInfo){.vaddr = data,
        .filesz = TLS_FIXER_BROWSER_DATA_FILESZ, .memsz = TLS_FIXER_BROWSER_DATA_MEMSZ};
    for (size_t i = 0; i < browser_descriptor.signature_count; ++i) {
        const TlsFixerMaskedSignature *signature = &browser_signatures[i];
        memcpy(text + signature->offset, signature->bytes, signature->length);
    }
    if (strncmp(scenario, "hook-", 5) == 0) {
        fail_hook = atoi(scenario + 5);
        assert(fail_hook >= 0 && fail_hook < HOOK_COUNT);
    }
    TlsFixerBrowserStartArgs args = {TLS_FIXER_BROWSER_START_MAGIC, TLS_FIXER_BROWSER_START_VERSION, 88, 0};
    int result = module_start(sizeof(args), &args);
    assert(result == (fail_hook < 0 ? SCE_KERNEL_START_SUCCESS :
        tls_fixer_browser_start_failure((TlsFixerBrowserStartStage)(TLS_FIXER_START_HOOK_CLOSE + fail_hook),
            (uint32_t)-1234, SCE_KERNEL_START_FAILED)));
    assert(installed == (fail_hook < 0 ? HOOK_COUNT : fail_hook));
    assert(hook_attempts == (fail_hook < 0 ? HOOK_COUNT : fail_hook + 1));
    if (chain) {
        void *functions[] = {(void *)next_close, (void *)next_pending, (void *)next_check, (void *)next_connect};
        for (int kind = 0; kind < installed; ++kind) {
            next_hooks[kind].func = functions[kind];
            references[kind].next = &next_hooks[kind];
        }
    }
    unsigned int entropy_before = mock_entropy_calls;
    pthread_t threads[4];
    for (unsigned int i = 0; i < workers; ++i) assert(pthread_create(&threads[i], NULL, exercise, NULL) == 0);
    for (unsigned int i = 0; i < workers; ++i) assert(pthread_join(threads[i], NULL) == 0);
    assert(mock_entropy_calls == entropy_before);
    for (int kind = 0; kind < installed; ++kind) {
        assert(original_calls[kind] == 100 * workers);
        assert(next_calls[kind] == (chain ? 100 * workers : 0));
    }
    assert(module_stop(0, NULL) == SCE_KERNEL_STOP_FAIL);
    assert(tls_fixer_browser_connection_count() == 0);
    /* No fixture callback is executing when the test tears down retained backend state. */
    assert(tls_fixer_browser_destroy() == 0);
    free(data);
    free(text);
    printf("real backend plus module passthrough: %s PASS\n", scenario);
    return 0;
}
