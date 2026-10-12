#define _GNU_SOURCE
#include "backend.h"
#include "module_descriptor.h"
#include "webkit_callback.h"
#include "tls_fixer/browser_start_diagnostics.h"
#include <psp2/kernel/sysmem.h>
#include <psp2common/kernel/modulemgr.h>
#include <taihen.h>

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#ifndef TLS_FIXER_BROWSER_PASSTHROUGH_ONLY
#define TLS_FIXER_BROWSER_PASSTHROUGH_ONLY 0
#endif
#ifndef TLS_FIXER_BROWSER_INITIALIZE_ONLY
#define TLS_FIXER_BROWSER_INITIALIZE_ONLY 0
#endif

int module_start(SceSize, const void *);
int module_stop(SceSize, const void *);

static SceKernelModuleInfo mapped;
static SceKernelModuleInfo webkit_mapped;
static SceKernelMemBlockInfo webkit_userdata_info;
static unsigned char *webkit_text, *webkit_userdata;
static SceUID webkit_lookup_result = 99;
static int webkit_info_result, webkit_userdata_info_result;
static void *webkit_lookup_address;
static int fail_hook = -1, hook_calls, installed, initialized, enabled, destroyed;
static int init_error;
static struct _tai_hook_user references[4];
static size_t offsets[4];

#if TLS_FIXER_TEST_WEBKIT_DIAGNOSTICS
static unsigned int callback_diagnostic_calls, callback_diagnostic_reason;
void tls_fixer_trace(const char *format, ...) {
    va_list args;
    if (strcmp(format, "browser default callback rejected: reason=%u") != 0) return;
    va_start(args, format);
    callback_diagnostic_reason = va_arg(args, unsigned int);
    va_end(args);
    ++callback_diagnostic_calls;
}
#endif

#if TLS_FIXER_ENABLE_RUNTIME_UDP && TLS_FIXER_TEST_WEBKIT_DIAGNOSTICS
static unsigned int callback_runtime_calls;
static int32_t callback_runtime_reason;
void tls_fixer_runtime_mark(unsigned int stage, int32_t value) {
    if (stage == 37) { ++callback_runtime_calls; callback_runtime_reason = value; }
}
#endif

static void expect_callback_rejected(TlsFixerBrowserContextCallbackValidator validator,
    const void *callback, const void *userdata, unsigned int reason) {
#if TLS_FIXER_TEST_WEBKIT_DIAGNOSTICS
    callback_diagnostic_calls = 0;
    callback_diagnostic_reason = 0;
#else
    (void)reason;
#endif
#if TLS_FIXER_ENABLE_RUNTIME_UDP && TLS_FIXER_TEST_WEBKIT_DIAGNOSTICS
    callback_runtime_calls = 0;
    callback_runtime_reason = 0;
#endif
    assert(!validator(callback, userdata));
#if TLS_FIXER_ENABLE_RUNTIME_UDP && TLS_FIXER_TEST_WEBKIT_DIAGNOSTICS
    assert(callback_runtime_calls == 1 && callback_runtime_reason == (int32_t)reason);
#endif
#if TLS_FIXER_TEST_WEBKIT_DIAGNOSTICS
    assert(callback_diagnostic_calls == 1 && callback_diagnostic_reason == reason);
#endif
}

int sceKernelGetModuleInfo(SceUID modid, SceKernelModuleInfo *info) {
    assert(info->size == sizeof(*info));
    if (modid == 88) {
        *info = mapped;
        return 0;
    }
    if (modid == 99) {
        *info = webkit_mapped;
        return webkit_info_result;
    }
    return -1;
}

SceUID sceKernelGetModuleIdByAddr(void *address) {
    webkit_lookup_address = address;
    return webkit_lookup_result;
}

int sceKernelGetMemBlockInfoByAddr(void *base, SceKernelMemBlockInfo *info) {
    assert(info->size == sizeof(*info));
    if (base != webkit_userdata) return -1;
    *info = webkit_userdata_info;
    return webkit_userdata_info_result;
}

static void setup_webkit_fixture(void) {
    webkit_text = mmap((void *)(uintptr_t)0x26000000, 0xb00000, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    webkit_userdata = mmap((void *)(uintptr_t)0x27000000, 0x1000, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    assert(webkit_text != MAP_FAILED && webkit_userdata != MAP_FAILED);

    webkit_mapped.size = sizeof(webkit_mapped);
    strcpy(webkit_mapped.module_name, TLS_FIXER_WEBKIT_MODULE_NAME);
    webkit_mapped.segments[0] = (SceKernelSegmentInfo){.vaddr = webkit_text,
        .filesz = TLS_FIXER_WEBKIT_TEXT_FILESZ, .memsz = TLS_FIXER_WEBKIT_TEXT_MEMSZ};
    webkit_mapped.segments[1] = (SceKernelSegmentInfo){.vaddr = webkit_text + 0x1000,
        /* Original filesz from the 440-byte 3.60 module-info capture, not the memory dump. */
        .filesz = 52788, .memsz = TLS_FIXER_WEBKIT_DATA_MEMSZ};
    /* Original module identity is distinct from memory-dump geometry. */
    strcpy((char *)webkit_text + 0x85fb08, "SceWebKit");
    webkit_text[0x85fb23] = 6;
    uint32_t webkit_nid = UINT32_C(0x20163df2);
    memcpy(webkit_text + 0x85fb38, &webkit_nid, sizeof(webkit_nid));
    memcpy(webkit_text + TLS_FIXER_WEBKIT_CTX_CALLBACK_OFFSET,
        tls_fixer_webkit_ctx_callback_signature, sizeof(tls_fixer_webkit_ctx_callback_signature));
    *(uint32_t *)webkit_userdata = (uint32_t)(uintptr_t)
        (webkit_text + TLS_FIXER_WEBKIT_REQUEST_VTABLE_OFFSET);
    webkit_userdata_info = (SceKernelMemBlockInfo){
        .size = sizeof(webkit_userdata_info),
        .mappedBase = webkit_userdata,
        .mappedSize = 0x1000,
        .access = SCE_KERNEL_MEMORY_ACCESS_R | SCE_KERNEL_MEMORY_ACCESS_W
    };
}

static void teardown_webkit_fixture(void) {
    assert(munmap(webkit_text, 0xb00000) == 0);
    assert(munmap(webkit_userdata, 0x1000) == 0);
    webkit_text = NULL;
    webkit_userdata = NULL;
}

static int original_close(void *connection, int index) { assert(connection == NULL && index == 1); return 17; }
static int original_pending(void *connection, int index) { assert(connection == NULL && index == 1); return 23; }
static int original_check(void *connection) { assert(connection == NULL); return 31; }
static int original_connect(void *connection, int index, unsigned char nonblocking, unsigned char *done) {
    assert(connection == NULL && index == 1 && nonblocking == 1);
    *done = 1;
    return 29;
}

int taiHookFunctionOffset(tai_hook_ref_t *reference, int modid, int segment,
    size_t offset, int thumb, const void *function) {
    int attempt = hook_calls++;
    assert(modid == 88 && segment == 0 && thumb == 1 && attempt < 4);
    if (attempt == fail_hook) return -1234;
    references[attempt].func = (void *)function;
    references[attempt].old = offset == TLS_FIXER_BROWSER_CLOSE_OFFSET ? (void *)original_close :
        offset == TLS_FIXER_BROWSER_PENDING_OFFSET ? (void *)original_pending :
        offset == TLS_FIXER_BROWSER_CHECK_OFFSET ? (void *)original_check : (void *)original_connect;
    offsets[attempt] = offset;
    *reference = (uintptr_t)&references[attempt];
    ++installed;
    return attempt + 1;
}

int tls_fixer_browser_init(const TlsFixerBrowserOps *ops) {
    const void *callback = webkit_text + TLS_FIXER_WEBKIT_CTX_CALLBACK_OFFSET + 1;
    uint32_t saved_vtable = *(const uint32_t *)webkit_userdata;
    SceSize saved_size = webkit_userdata_info.mappedSize;
    uint32_t saved_access = webkit_userdata_info.access;
    unsigned char saved_signature = webkit_text[TLS_FIXER_WEBKIT_CTX_CALLBACK_OFFSET];
    char saved_name = webkit_mapped.module_name[0];

    assert(ops->timeleft == (void *)((uintptr_t)mapped.segments[0].vaddr + TLS_FIXER_BROWSER_TIMELEFT_OFFSET + 1));
    assert(ops->socket_wait == (void *)((uintptr_t)mapped.segments[0].vaddr + TLS_FIXER_BROWSER_WAIT_OFFSET + 1));
    assert(ops->is_default_ctx_callback != NULL);
    assert(strcmp(ops->default_ciphers, TLS_FIXER_BROWSER_DEFAULT_CIPHERS) == 0);
    assert(strcmp(ops->default_ca_path, "wb0:/cert/CA_LIST.cer") == 0);
    assert(ops->is_default_ctx_callback(callback, webkit_userdata));
    webkit_mapped.segments[1].filesz = 71104;
    expect_callback_rejected(ops->is_default_ctx_callback, callback, webkit_userdata, 6);
    webkit_mapped.segments[1].filesz = 52788;
    assert(webkit_lookup_address == webkit_text + TLS_FIXER_WEBKIT_CTX_CALLBACK_OFFSET);
    expect_callback_rejected(ops->is_default_ctx_callback,
        (const unsigned char *)callback + 2, webkit_userdata, 7);
    expect_callback_rejected(ops->is_default_ctx_callback, callback, NULL, 1);
    expect_callback_rejected(ops->is_default_ctx_callback, callback, webkit_userdata + 1, 1);
    webkit_lookup_result = -1;
    expect_callback_rejected(ops->is_default_ctx_callback, callback, webkit_userdata, 2);
    webkit_lookup_result = 99;
    webkit_info_result = -1;
    expect_callback_rejected(ops->is_default_ctx_callback, callback, webkit_userdata, 3);
    webkit_info_result = 0;
    webkit_mapped.module_name[0] ^= 1;
    expect_callback_rejected(ops->is_default_ctx_callback, callback, webkit_userdata, 4);
    webkit_mapped.module_name[0] = saved_name;
    webkit_mapped.segments[1].vaddr = NULL;
    expect_callback_rejected(ops->is_default_ctx_callback, callback, webkit_userdata, 5);
    webkit_mapped.segments[1].vaddr = webkit_text + 0x1000;
    --webkit_mapped.segments[0].filesz;
    expect_callback_rejected(ops->is_default_ctx_callback, callback, webkit_userdata, 6);
    ++webkit_mapped.segments[0].filesz;
    webkit_text[TLS_FIXER_WEBKIT_CTX_CALLBACK_OFFSET] ^= 1;
    expect_callback_rejected(ops->is_default_ctx_callback, callback, webkit_userdata, 8);
    webkit_text[TLS_FIXER_WEBKIT_CTX_CALLBACK_OFFSET] = saved_signature;
    webkit_userdata_info_result = -1;
    expect_callback_rejected(ops->is_default_ctx_callback, callback, webkit_userdata, 9);
    webkit_userdata_info_result = 0;
    webkit_userdata_info.mappedSize = TLS_FIXER_WEBKIT_REQUEST_SIZE - 1;
    expect_callback_rejected(ops->is_default_ctx_callback, callback, webkit_userdata, 10);
    webkit_userdata_info.mappedSize = saved_size;
    webkit_userdata_info.access = SCE_KERNEL_MEMORY_ACCESS_R;
    expect_callback_rejected(ops->is_default_ctx_callback, callback, webkit_userdata, 11);
    webkit_userdata_info.access = saved_access;
    *(uint32_t *)webkit_userdata ^= 4;
    expect_callback_rejected(ops->is_default_ctx_callback, callback, webkit_userdata, 13);
    *(uint32_t *)webkit_userdata = saved_vtable;
    ++initialized;
    return init_error;
}
void tls_fixer_browser_enable(int value) { enabled = value; }
int tls_fixer_browser_destroy(void) { ++destroyed; return 0; }
int tls_fixer_browser_connect(void *c, int i, unsigned char n, unsigned char *d, int *h) {
    (void)c; (void)i; (void)n; (void)d; *h = 0; return 0;
}
int tls_fixer_browser_close(void *c, int i, int *h) { (void)c; (void)i; *h = 0; return 0; }
int tls_fixer_browser_pending(void *c, int i, int *h) { (void)c; (void)i; *h = 0; return 0; }
int tls_fixer_browser_check(void *c, int *h) { (void)c; *h = 0; return 0; }

int main(int argc, char **argv) {
    unsigned char *arena = mmap((void *)(uintptr_t)0x25000000, 0x500000, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    TlsFixerBrowserStartArgs args = {TLS_FIXER_BROWSER_START_MAGIC, TLS_FIXER_BROWSER_START_VERSION, 88, 0};
    const void *arg_data = &args;
    SceSize arg_size = sizeof(args);
    TlsFixerBrowserStartStage rejected_stage = TLS_FIXER_START_ARGUMENT_MAGIC;
    uint32_t rejected_detail = 0;
    const char *scenario;
    int result, expect_gate_failure = 0;
    assert(argc == 2 && arena != MAP_FAILED);
    setup_webkit_fixture();
    scenario = argv[1];
    mapped.size = sizeof(mapped);
    strcpy(mapped.module_name, "ScePsp2Compat");
    strcpy(mapped.path, "wb0:/tls_fixer/ScePsp2Compat.suprx");
    mapped.segments[0] = (SceKernelSegmentInfo){.vaddr = arena,
        .filesz = TLS_FIXER_BROWSER_TEXT_FILESZ, .memsz = TLS_FIXER_BROWSER_TEXT_MEMSZ};
    mapped.segments[1] = (SceKernelSegmentInfo){.vaddr = arena + 0x400000,
        .filesz = TLS_FIXER_BROWSER_DATA_FILESZ, .memsz = TLS_FIXER_BROWSER_DATA_MEMSZ};
    for (size_t i = 0; i < browser_descriptor.signature_count; ++i) {
        const TlsFixerMaskedSignature *signature = &browser_signatures[i];
        memcpy(arena + signature->offset, signature->bytes, signature->length);
    }
    if (strncmp(scenario, "hook-", 5) == 0) fail_hook = atoi(scenario + 5);
    if (strcmp(scenario, "bad-args") == 0) {
        args.magic ^= 1; expect_gate_failure = 1; rejected_detail = args.magic;
    }
    if (strcmp(scenario, "bad-buffer") == 0 || strcmp(scenario, "bad-arg-size") == 0) {
        if (strcmp(scenario, "bad-buffer") == 0) arg_data = NULL;
        else --arg_size;
        expect_gate_failure = 1; rejected_stage = TLS_FIXER_START_ARGUMENT_BUFFER; rejected_detail = arg_size;
    }
    if (strcmp(scenario, "bad-version") == 0) {
        args.version = 99; expect_gate_failure = 1;
        rejected_stage = TLS_FIXER_START_ARGUMENT_VERSION; rejected_detail = args.version;
    }
    if (strcmp(scenario, "bad-reserved") == 0) {
        args.reserved = 1; expect_gate_failure = 1;
        rejected_stage = TLS_FIXER_START_ARGUMENT_RESERVED; rejected_detail = args.reserved;
    }
    if (strcmp(scenario, "bad-negative-id") == 0) {
        args.compat_modid = -1; expect_gate_failure = 1;
        rejected_stage = TLS_FIXER_START_ARGUMENT_MODULE; rejected_detail = UINT32_MAX;
    }
    if (strcmp(scenario, "bad-id") == 0) {
        args.compat_modid = 87; expect_gate_failure = 1;
        rejected_stage = TLS_FIXER_START_MODULE_INFO; rejected_detail = UINT32_MAX;
    }
    if (strcmp(scenario, "bad-name") == 0) {
        mapped.module_name[0] ^= 1; expect_gate_failure = 1; rejected_stage = TLS_FIXER_START_MODULE_NAME;
    }
    if (strcmp(scenario, "bad-address") == 0) {
        mapped.segments[1].vaddr = NULL; expect_gate_failure = 1; rejected_stage = TLS_FIXER_START_SEGMENT_ADDRESS;
    }
    if (strcmp(scenario, "bad-size") == 0) {
        --mapped.segments[0].filesz; expect_gate_failure = 1;
        rejected_stage = TLS_FIXER_START_TEXT_FILESZ; rejected_detail = mapped.segments[0].filesz;
    }
    if (strcmp(scenario, "bad-text-memsz") == 0) {
        --mapped.segments[0].memsz; expect_gate_failure = 1;
        rejected_stage = TLS_FIXER_START_TEXT_MEMSZ; rejected_detail = mapped.segments[0].memsz;
    }
    if (strcmp(scenario, "bad-data-filesz") == 0) {
        --mapped.segments[1].filesz; expect_gate_failure = 1;
        rejected_stage = TLS_FIXER_START_DATA_FILESZ; rejected_detail = mapped.segments[1].filesz;
    }
    if (strcmp(scenario, "bad-data-memsz") == 0) {
        --mapped.segments[1].memsz; expect_gate_failure = 1;
        rejected_stage = TLS_FIXER_START_DATA_MEMSZ; rejected_detail = mapped.segments[1].memsz;
    }
    if (strcmp(scenario, "bad-path") == 0) {
        memset(mapped.path, 'x', sizeof(mapped.path)); expect_gate_failure = 1; rejected_stage = TLS_FIXER_START_CA_PATH;
    }
    if (strcmp(scenario, "init-fail") == 0)
        init_error = tls_fixer_browser_start_failure(TLS_FIXER_START_CA_LOAD, (uint32_t)-0x2180, -0x2180);
    if (strncmp(scenario, "bad-site-", 9) == 0) {
        unsigned int site = (unsigned int)strtoul(scenario + 9, NULL, 10);
        assert(site < browser_descriptor.signature_count);
        arena[browser_signatures[site].offset] ^= 1;
        expect_gate_failure = 1;
        rejected_stage = TLS_FIXER_START_SIGNATURE;
        rejected_detail = site << 8;
    }
    result = module_start(arg_size, arg_data);
    if (expect_gate_failure) {
        assert(result == tls_fixer_browser_start_failure(rejected_stage, rejected_detail, SCE_KERNEL_START_FAILED));
        assert(!installed && !initialized && !enabled);
    } else if (init_error) {
        assert(result == tls_fixer_browser_start_failure(TLS_FIXER_START_CA_LOAD, (uint32_t)-0x2180, SCE_KERNEL_START_FAILED));
        assert(!installed && initialized == 1 && !enabled);
    } else if (TLS_FIXER_BROWSER_INITIALIZE_ONLY) {
        assert(result == SCE_KERNEL_START_SUCCESS && initialized == 1 && !destroyed);
        assert(hook_calls == 0 && installed == 0 && !enabled);
        assert(module_stop(0, NULL) == SCE_KERNEL_STOP_FAIL);
        assert(module_start(sizeof(args), &args) ==
            tls_fixer_browser_start_failure(TLS_FIXER_START_REPEAT, 0, SCE_KERNEL_START_FAILED));
    } else if (fail_hook == 0) {
        assert(result == tls_fixer_browser_start_failure(TLS_FIXER_START_HOOK_CLOSE, (uint32_t)-1234, SCE_KERNEL_START_FAILED));
        assert(!installed && initialized == 1 && destroyed == 1 && !enabled);
    } else {
        assert(result == (fail_hook < 0 ? SCE_KERNEL_START_SUCCESS :
            tls_fixer_browser_start_failure((TlsFixerBrowserStartStage)(TLS_FIXER_START_HOOK_CLOSE + fail_hook),
                (uint32_t)-1234, SCE_KERNEL_START_SUCCESS)));
        assert(initialized == 1 && !destroyed);
        assert(installed == (fail_hook < 0 ? 4 : fail_hook));
        assert(enabled == (fail_hook < 0 && !TLS_FIXER_BROWSER_PASSTHROUGH_ONLY));
        for (int i = 0; i < installed; ++i) {
            if (offsets[i] == TLS_FIXER_BROWSER_CONNECT_OFFSET) {
                unsigned char done = 0;
                int (*function)(void *, int, unsigned char, unsigned char *) = references[i].func;
                assert(function(NULL, 1, 1, &done) == 29 && done);
            } else if (offsets[i] == TLS_FIXER_BROWSER_CHECK_OFFSET) {
                int (*function)(void *) = references[i].func;
                assert(function(NULL) == 31);
            } else {
                int (*function)(void *, int) = references[i].func;
                assert(function(NULL, 1) == (offsets[i] == TLS_FIXER_BROWSER_CLOSE_OFFSET ? 17 : 23));
            }
        }
        assert(module_stop(0, NULL) == SCE_KERNEL_STOP_FAIL);
        assert(module_start(sizeof(args), &args) ==
            tls_fixer_browser_start_failure(TLS_FIXER_START_REPEAT, 0, SCE_KERNEL_START_FAILED));
    }
    munmap(arena, 0x500000);
    teardown_webkit_fixture();
    printf("browser module: %s PASS\n", scenario);
    return 0;
}
