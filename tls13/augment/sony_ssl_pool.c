#include "sony_ssl_pool.h"
#include "sony_ssl_pool_profile.h"
#include "optional_syscall.h"
#include <psp2/kernel/modulemgr.h>
#include <psp2/kernel/sysmem.h>
#include <string.h>
#include <stdint.h>

#define SSL_BEFORE_INIT ((int32_t)UINT32_C(0x80435001))
#define SSL_INVALID ((int32_t)UINT32_C(0x804351fe))
static SceKernelModuleInfo g_info; /* Avoid adding this structure to 4 KiB callers' stacks. */
static const volatile uint32_t *g_initialized, *g_heap_address;
static const volatile int32_t *g_block;

static int thumb_immediate(const unsigned char *p, int top, unsigned reg, uint32_t *value) {
    uint16_t a = (uint16_t)(p[0] | (uint16_t)p[1] << 8);
    uint16_t b = (uint16_t)(p[2] | (uint16_t)p[3] << 8);
    if ((a & 0xfbf0u) != (top ? 0xf2c0u : 0xf240u) ||
        (b & 0x8f00u) != reg << 8) return 0;
    *value = (uint32_t)(a & 15u) << 12 | (uint32_t)(a & 0x400u) << 1 |
        (uint32_t)(b & 0x7000u) >> 4 | (b & 0xffu);
    return 1;
}
static int address_pair(const unsigned char *w, const unsigned char *t, unsigned reg, uintptr_t expected) {
    uint32_t low, high;
    return thumb_immediate(w, 0, reg, &low) && thumb_immediate(t, 1, reg, &high) &&
        (low | high << 16) == expected;
}
static int profile_matches(const unsigned char *p, const unsigned char *expected,
                           size_t n, size_t first, size_t second, int extra_pair) {
    for (size_t i = 0; i < n; ++i)
        if (!((i >= first && i < first + 4) || (i >= second && i < second + 4) ||
              (extra_pair && ((i >= 12 && i < 16) || (i >= 18 && i < 22)))) &&
            p[i] != expected[i]) return 0;
    return 1;
}

int tls_fixer_sony_ssl_pool_prepare(const void *import) {
    g_initialized = g_heap_address = NULL; g_block = NULL;
    const volatile uint32_t *stub = import;
    if (!tls_fixer_user_stub_bound(stub)) return SSL_BEFORE_INIT;
    uint32_t low = (stub[0] & 0xfffu) | ((stub[0] >> 4) & 0xf000u);
    uint32_t high = (stub[1] & 0xfffu) | ((stub[1] >> 4) & 0xf000u);
    uintptr_t target = low | high << 16;
    if (!(target & 1u)) return SSL_INVALID;
    SceUID module = sceKernelGetModuleIdByAddr((void *)(target & ~(uintptr_t)1));
    if (module < 0) return module;
    memset(&g_info, 0, sizeof(g_info)); g_info.size = sizeof(g_info);
    int rc = sceKernelGetModuleInfo(module, &g_info);
    if (rc < 0) return rc;
    if (strcmp(g_info.module_name, "SceLibSsl") || g_info.segments[0].memsz != 421540u ||
        g_info.segments[1].memsz != 20392u) return SSL_INVALID;
    const unsigned char *text = g_info.segments[0].vaddr;
    uintptr_t data = (uintptr_t)g_info.segments[1].vaddr;
    if (target != (uintptr_t)text + 0x48141u) return SSL_INVALID;
    const unsigned char *get = text + 0x48140u, *allocate = text + 0x47e28u;
    /* Both the instruction shapes and relocated destinations must match. */
    if (!address_pair(get, get + 4, 3, data + 0x4f78u) ||
        !address_pair(get + 12, get + 18, 3, data + 0x4fa0u) ||
        !address_pair(allocate + 2, allocate + 6, 3, data + 0x4f7cu) ||
        !address_pair(text + 0x47f7cu, text + 0x47f90u, 7, data + 0x4114u) ||
        !profile_matches(get, g_get_crypto_code, sizeof(g_get_crypto_code), 0, 4, 1) ||
        !profile_matches(allocate, g_malloc_code, sizeof(g_malloc_code), 2, 6, 0)) return SSL_INVALID;
    /* The second MOVW/MOVT pair in get was validated above, but also relocates. */
    g_initialized = (const volatile uint32_t *)(data + 0x4f78u);
    g_heap_address = (const volatile uint32_t *)(data + 0x4f7cu);
    g_block = (const volatile int32_t *)(data + 0x4114u);
    return 0;
}
int tls_fixer_sony_ssl_pool_read(void *context, TlsFixerSslPoolView *view) {
    (void)context;
    if (!view || !g_initialized || *g_initialized != 1u || !*g_heap_address || *g_block < 0)
        return SSL_BEFORE_INIT;
    /* The UID distinguishes a destroyed/recreated pool even if its address is reused. */
    view->heap = (void *)(uintptr_t)*g_heap_address;
    view->block = *g_block;
    return 0;
}
