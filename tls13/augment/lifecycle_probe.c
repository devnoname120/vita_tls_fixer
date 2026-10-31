#include <stdint.h>

typedef int (*ModuleEntry)(uint32_t argc, const void *args);

typedef struct TlsFixerAugmentProbe {
    uint32_t magic;
    uint32_t version;
    ModuleEntry native_start;
    ModuleEntry native_stop;
    uint32_t start_calls;
    uint32_t stop_calls;
    int last_start_result;
    int last_stop_result;
} TlsFixerAugmentProbe;

_Static_assert(sizeof(TlsFixerAugmentProbe) == 32, "augmentation probe ABI");

/* The offline merger binds the two native entries with ordinary SCE
 * relocations. No hooks, allocations, threads, imports or file writes. */
TlsFixerAugmentProbe g_tls_fixer_augment_probe = {0x41584654, 1, 0, 0, 0, 0, 0, 0};

int module_start(uint32_t argc, const void *args) {
    if (g_tls_fixer_augment_probe.native_start == 0) return -1;
    int result = g_tls_fixer_augment_probe.native_start(argc, args);
    ++g_tls_fixer_augment_probe.start_calls;
    g_tls_fixer_augment_probe.last_start_result = result;
    return result;
}

int module_stop(uint32_t argc, const void *args) {
    if (g_tls_fixer_augment_probe.native_stop == 0) return -1;
    int result = g_tls_fixer_augment_probe.native_stop(argc, args);
    ++g_tls_fixer_augment_probe.stop_calls;
    g_tls_fixer_augment_probe.last_stop_result = result;
    return result;
}

const TlsFixerAugmentProbe *tls_fixer_augment_probe_snapshot(void) {
    return &g_tls_fixer_augment_probe;
}
