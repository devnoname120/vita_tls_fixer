#include "code_snapshot.h"
#include <kernel_mock.h>
#include <assert.h>
#include <stdio.h>

static unsigned int copies, events, fail_event;
static int copy_result;
static uintptr_t expected_address;
static struct { const char *stage; uint32_t object, result; } recorded[8];

int ksceKernelCopyFromUserProc(SceUID pid, void *output, const void *input, SceSize size) {
    assert(pid == 99 && (uintptr_t)input == expected_address && size == 16);
    ++copies;
    memset(output, 0xff, size);
    if (copy_result == 0) {
        for (unsigned int i = 0; i < size; ++i) ((unsigned char *)output)[i] = (unsigned char)i;
    }
    return copy_result;
}

int tls_fixer_boot_trace_event(const char *stage, int32_t pid, int32_t object, int32_t result) {
    assert(pid == 99 && events < sizeof(recorded) / sizeof(recorded[0]));
    recorded[events].stage = stage;
    recorded[events].object = (uint32_t)object;
    recorded[events].result = (uint32_t)result;
    ++events;
    return fail_event == events ? -83 : 0;
}

static void reset(void) {
    copies = events = fail_event = 0;
    copy_result = 0;
    memset(recorded, 0, sizeof(recorded));
}

int main(void) {
    SceKernelModuleInfo module;
    memset(&module, 0, sizeof(module));
    module.size = sizeof(module);
    module.segments[0].vaddr = (void *)(uintptr_t)0x81300450;
    module.segments[0].filesz = 0x39f508;
    module.segments[0].memsz = 0x39f630;
    expected_address = 0x813a631e;
    assert(tls_fixer_code_snapshot(99, &module, 0xa5ece, "code.before") == 0);
    assert(copies == 1 && events == 6);
    assert(strcmp(recorded[0].stage, "code.copy.enter") == 0);
    assert(recorded[0].object == expected_address && recorded[0].result == 16);
    assert(strcmp(recorded[1].stage, "code.copy.return") == 0 && recorded[1].result == 0);
    for (unsigned int i = 0; i < 4; ++i) {
        assert(strcmp(recorded[i + 2].stage, "code.before") == 0);
        assert(recorded[i + 2].object == expected_address + 4 * i);
        assert(recorded[i + 2].result == UINT32_C(0x03020100) + UINT32_C(0x04040404) * i);
    }
    for (unsigned int i = 1; i <= 6; ++i) {
        reset();
        fail_event = i;
        assert(tls_fixer_code_snapshot(99, &module, 0xa5ece, "code.after") < 0);
        assert(events == i && copies == (i != 1));
    }
    for (int i = -1; i <= 1; i += 2) {
        reset();
        copy_result = i;
        assert(tls_fixer_code_snapshot(99, &module, 0xa5ece, "code.after") < 0);
        assert(copies == 1 && events == 2 && recorded[1].result == (uint32_t)i);
    }
    reset();
    assert(tls_fixer_code_snapshot(0, &module, 0, "code.before") < 0);
    assert(tls_fixer_code_snapshot(-1, &module, 0, "code.before") < 0);
    assert(tls_fixer_code_snapshot(99, NULL, 0, "code.before") < 0);
    assert(tls_fixer_code_snapshot(99, &module, 0, NULL) < 0);
    assert(tls_fixer_code_snapshot(99, &module, SIZE_MAX, "code.before") < 0);
    assert(tls_fixer_code_snapshot(99, &module, module.segments[0].filesz - 15, "code.before") < 0);
    module.segments[0].memsz = 15;
    assert(tls_fixer_code_snapshot(99, &module, 0, "code.before") < 0);
    module.segments[0].vaddr = (void *)(uintptr_t)UINT32_C(0xfffffff0);
    module.segments[0].memsz = 64;
    assert(tls_fixer_code_snapshot(99, &module, 1, "code.before") < 0);
    module.segments[0].vaddr = NULL;
    assert(tls_fixer_code_snapshot(99, &module, 0, "code.before") < 0);
    assert(copies == 0 && events == 0);
    puts("bounded code snapshots: native-copy status and exact bytes, no invalid-range read PASS");
    return 0;
}
