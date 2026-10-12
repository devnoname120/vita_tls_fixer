#define main tls_fixer_module_fixture_main
#include "test_module.c"
#undef main

#ifndef TLS_FIXER_BROWSER_HOOK_MASK
#error "This fixture requires an explicit hook selection"
#endif

int main(int argc, char **argv) {
    static const size_t sites[] = {TLS_FIXER_BROWSER_CLOSE_OFFSET, TLS_FIXER_BROWSER_PENDING_OFFSET,
        TLS_FIXER_BROWSER_CHECK_OFFSET, TLS_FIXER_BROWSER_CONNECT_OFFSET};
    unsigned int selected[4], count = 0;
    unsigned char *arena = mmap((void *)(uintptr_t)0x25000000, 0x500000, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    TlsFixerBrowserStartArgs args = {TLS_FIXER_BROWSER_START_MAGIC, TLS_FIXER_BROWSER_START_VERSION, 88, 0};
    assert(argc == 2 && arena != MAP_FAILED);
    setup_webkit_fixture();
    fail_hook = atoi(argv[1]);
    assert(fail_hook >= -1 && fail_hook < 4);
    for (unsigned int i = 0; i < 4; ++i) {
        if (TLS_FIXER_BROWSER_HOOK_MASK & (1u << i)) selected[count++] = i;
    }
    mapped.size = sizeof(mapped);
    strcpy(mapped.module_name, "ScePsp2Compat");
    strcpy(mapped.path, "wb0:/tls_fixer/ScePsp2Compat.suprx");
    mapped.segments[0] = (SceKernelSegmentInfo){.vaddr = arena,
        .filesz = TLS_FIXER_BROWSER_TEXT_FILESZ, .memsz = TLS_FIXER_BROWSER_TEXT_MEMSZ};
    mapped.segments[1] = (SceKernelSegmentInfo){.vaddr = arena + 0x400000,
        .filesz = TLS_FIXER_BROWSER_DATA_FILESZ, .memsz = TLS_FIXER_BROWSER_DATA_MEMSZ};
    for (size_t i = 0; i < browser_descriptor.signature_count; ++i) {
        const TlsFixerMaskedSignature *s = &browser_signatures[i];
        memcpy(arena + s->offset, s->bytes, s->length);
    }
    int failed = fail_hook >= 0 && (unsigned int)fail_hook < count;
    int expected_installed = failed ? fail_hook : (int)count;
    int result = module_start(sizeof(args), &args);
    assert(installed == expected_installed);
    assert(hook_calls == expected_installed + failed);
    assert(initialized == 1 && !enabled);
    if (failed) {
        TlsFixerBrowserStartStage stage = (TlsFixerBrowserStartStage)(TLS_FIXER_START_HOOK_CLOSE + selected[fail_hook]);
        assert(result == tls_fixer_browser_start_failure(stage, (uint32_t)-1234,
            expected_installed ? SCE_KERNEL_START_SUCCESS : SCE_KERNEL_START_FAILED));
        assert(destroyed == (expected_installed == 0));
    } else {
        assert(result == SCE_KERNEL_START_SUCCESS && !destroyed);
    }
    for (int i = 0; i < installed; ++i) {
        assert(offsets[i] == sites[selected[i]]);
        if (selected[i] == 3) {
            unsigned char done = 0;
            int (*fn)(void *, int, unsigned char, unsigned char *) = references[i].func;
            assert(fn(NULL, 1, 1, &done) == 29 && done);
        } else if (selected[i] == 2) {
            int (*fn)(void *) = references[i].func;
            assert(fn(NULL) == 31);
        } else {
            int (*fn)(void *, int) = references[i].func;
            assert(fn(NULL, 1) == (selected[i] ? 23 : 17));
        }
    }
    assert(module_stop(0, NULL) == SCE_KERNEL_STOP_FAIL);
    assert(module_start(sizeof(args), &args) ==
        tls_fixer_browser_start_failure(TLS_FIXER_START_REPEAT, 0, SCE_KERNEL_START_FAILED));
    teardown_webkit_fixture();
    munmap(arena, 0x500000);
    printf("hook selection mask=%u failure=%d: PASS\n", (unsigned int)TLS_FIXER_BROWSER_HOOK_MASK, fail_hook);
    return 0;
}
