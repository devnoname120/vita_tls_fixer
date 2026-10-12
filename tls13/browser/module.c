#include "backend.h"
#include "module_descriptor.h"
#include "diagnostics.h"
#include "runtime_udp.h"
#include "webkit_callback.h"
#include "tls_fixer/path.h"
#include "tls_fixer/browser_start_diagnostics.h"

#include <psp2/kernel/modulemgr.h>
#include <psp2common/kernel/modulemgr.h>
#include <taihen.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifndef TLS_FIXER_BROWSER_PASSTHROUGH_ONLY
#define TLS_FIXER_BROWSER_PASSTHROUGH_ONLY 0
#endif
#ifndef TLS_FIXER_BROWSER_INITIALIZE_ONLY
#define TLS_FIXER_BROWSER_INITIALIZE_ONLY 0
#endif
#if TLS_FIXER_BROWSER_PASSTHROUGH_ONLY && (!TLS_FIXER_BROWSER_START_DIAGNOSTICS || TLS_FIXER_ENABLE_RUNTIME_UDP)
#error "Passthrough control requires startup diagnostics without the UDP recorder"
#endif
#if TLS_FIXER_BROWSER_INITIALIZE_ONLY && !TLS_FIXER_BROWSER_PASSTHROUGH_ONLY
#error "Initialization-only control requires the disabled-transport diagnostic"
#endif
#ifdef TLS_FIXER_BROWSER_HOOK_MASK
#if !TLS_FIXER_BROWSER_PASSTHROUGH_ONLY || TLS_FIXER_BROWSER_INITIALIZE_ONLY
#error "Selective hooks require the passthrough control, not initialization-only"
#endif
#if TLS_FIXER_BROWSER_HOOK_MASK < 0 || TLS_FIXER_BROWSER_HOOK_MASK > 15
#error "Hook selection must fit the four browser hooks"
#endif
/* Retain every callback and its dependencies even when this control selects no hooks. */
static const volatile uint32_t control_hook_mask = TLS_FIXER_BROWSER_HOOK_MASK;
#endif

enum { BROWSER_HOOK_CLOSE, BROWSER_HOOK_PENDING, BROWSER_HOOK_CHECK, BROWSER_HOOK_CONNECT, BROWSER_HOOK_COUNT };
static tai_hook_ref_t hook_refs[BROWSER_HOOK_COUNT];
static int hook_ids[BROWSER_HOOK_COUNT];
static uint32_t starting;
static char ca_path[256];

static int reject_identity(TlsFixerBrowserStartStage stage, uint32_t detail) {
    TLS_FIXER_LOG("browser module identity rejected: stage=%u detail=0x%08X", (unsigned int)stage, detail);
    return tls_fixer_browser_start_failure(stage, detail, -1);
}

static int reject_start(int result) {
#if TLS_FIXER_BROWSER_START_DIAGNOSTICS
    if (tls_fixer_browser_is_start_code(result)) return result;
#endif
    return tls_fixer_browser_start_failure(TLS_FIXER_START_INIT_OTHER, (uint32_t)result, SCE_KERNEL_START_FAILED);
}

static void *continuation(tai_hook_ref_t reference) {
    struct _tai_hook_user *current = (struct _tai_hook_user *)reference;
    struct _tai_hook_user *next = (struct _tai_hook_user *)current->next;
    return next == NULL ? current->old : next->func;
}

static int hook_connect(void *connection, int index, unsigned char nonblocking, unsigned char *done) {
    typedef int (*Original)(void *, int, unsigned char, unsigned char *);
    int handled;
    tls_fixer_runtime_mark(TLS_FIXER_RT_CONNECT_ENTER, index);
    int result = tls_fixer_browser_connect(connection, index, nonblocking, done, &handled);
    if (handled) {
        tls_fixer_runtime_mark(TLS_FIXER_RT_CONNECT_RETURN, result);
        return result;
    }
    tls_fixer_runtime_mark(TLS_FIXER_RT_LEGACY_ENTER, index);
    result = ((Original)continuation(hook_refs[BROWSER_HOOK_CONNECT]))(connection, index, nonblocking, done);
    tls_fixer_runtime_mark(TLS_FIXER_RT_LEGACY_RETURN, result);
    return result;
}

static int hook_close(void *connection, int index) {
    typedef int (*Original)(void *, int);
    int handled;
    tls_fixer_runtime_mark(TLS_FIXER_RT_CLOSE_ENTER, index);
    int result = tls_fixer_browser_close(connection, index, &handled);
    if (!handled) result = ((Original)continuation(hook_refs[BROWSER_HOOK_CLOSE]))(connection, index);
    tls_fixer_runtime_mark(TLS_FIXER_RT_CLOSE_RETURN, result);
    return result;
}

static int hook_pending(void *connection, int index) {
    typedef int (*Original)(void *, int);
    int handled;
    tls_fixer_runtime_mark(TLS_FIXER_RT_PENDING_ENTER, index);
    int result = tls_fixer_browser_pending(connection, index, &handled);
    if (!handled) result = ((Original)continuation(hook_refs[BROWSER_HOOK_PENDING]))(connection, index);
    tls_fixer_runtime_mark(TLS_FIXER_RT_PENDING_RETURN, result);
    return result;
}

static int hook_check(void *connection) {
    typedef int (*Original)(void *);
    int handled;
    tls_fixer_runtime_mark(TLS_FIXER_RT_CHECK_ENTER, 0);
    int result = tls_fixer_browser_check(connection, &handled);
    if (!handled) result = ((Original)continuation(hook_refs[BROWSER_HOOK_CHECK]))(connection);
    tls_fixer_runtime_mark(TLS_FIXER_RT_CHECK_RETURN, result);
    return result;
}

static int validate_module(int modid, uintptr_t *text) {
    SceKernelModuleInfo info;
    size_t signature = SIZE_MAX, byte = SIZE_MAX;
    int result;

    memset(&info, 0, sizeof(info));
    info.size = sizeof(info);
    result = sceKernelGetModuleInfo(modid, &info);
    if (result < 0) return reject_identity(TLS_FIXER_START_MODULE_INFO, (uint32_t)result);
    if (memcmp(info.module_name, "ScePsp2Compat", sizeof("ScePsp2Compat")) != 0)
        return reject_identity(TLS_FIXER_START_MODULE_NAME, 0);
    if (info.segments[0].vaddr == NULL || info.segments[1].vaddr == NULL)
        return reject_identity(TLS_FIXER_START_SEGMENT_ADDRESS, 0);
    if (info.segments[0].filesz != TLS_FIXER_BROWSER_TEXT_FILESZ)
        return reject_identity(TLS_FIXER_START_TEXT_FILESZ, info.segments[0].filesz);
    if (info.segments[0].memsz != TLS_FIXER_BROWSER_TEXT_MEMSZ)
        return reject_identity(TLS_FIXER_START_TEXT_MEMSZ, info.segments[0].memsz);
    if (info.segments[1].filesz != TLS_FIXER_BROWSER_DATA_FILESZ)
        return reject_identity(TLS_FIXER_START_DATA_FILESZ, info.segments[1].filesz);
    if (info.segments[1].memsz != TLS_FIXER_BROWSER_DATA_MEMSZ)
        return reject_identity(TLS_FIXER_START_DATA_MEMSZ, info.segments[1].memsz);
    result = tls_fixer_validate_module_text(info.segments[0].vaddr, info.segments[0].filesz,
        &browser_descriptor, &signature, &byte);
    if (result != TLS_FIXER_MODULE_GATE_OK) {
        TLS_FIXER_LOG("browser module signature rejected: index=%u byte=%u result=%d",
            (unsigned int)signature, (unsigned int)byte, result);
        return tls_fixer_browser_start_failure(TLS_FIXER_START_SIGNATURE,
            ((uint32_t)signature & UINT32_C(0xff)) << 8 | ((uint32_t)byte & UINT32_C(0xff)), result);
    }
    if (memchr(info.path, '\0', sizeof(info.path)) == NULL ||
        !tls_fixer_browser_ca_path(info.path, ca_path, sizeof(ca_path))) {
        TLS_FIXER_LOG("browser module path rejected");
        return tls_fixer_browser_start_failure(TLS_FIXER_START_CA_PATH, 0, -1);
    }
    *text = (uintptr_t)info.segments[0].vaddr;
    return 0;
}

int module_start(SceSize size, const void *data) {
    static const struct { size_t offset; const void *function; } hooks[] = {
        {TLS_FIXER_BROWSER_CLOSE_OFFSET, hook_close},
        {TLS_FIXER_BROWSER_PENDING_OFFSET, hook_pending},
        {TLS_FIXER_BROWSER_CHECK_OFFSET, hook_check},
        {TLS_FIXER_BROWSER_CONNECT_OFFSET, hook_connect}
    };
    TlsFixerBrowserStartArgs args;
    TlsFixerBrowserOps ops = {0};
    uintptr_t text;
    uint32_t expected = 0;
    int result;

    if (!__atomic_compare_exchange_n(&starting, &expected, 1, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        return tls_fixer_browser_start_failure(TLS_FIXER_START_REPEAT, 0, SCE_KERNEL_START_FAILED);
    }
    if (data == NULL || size != sizeof(args))
        return tls_fixer_browser_start_failure(TLS_FIXER_START_ARGUMENT_BUFFER, size, SCE_KERNEL_START_FAILED);
    memcpy(&args, data, sizeof(args));
    if (args.magic != TLS_FIXER_BROWSER_START_MAGIC)
        return tls_fixer_browser_start_failure(TLS_FIXER_START_ARGUMENT_MAGIC, args.magic, SCE_KERNEL_START_FAILED);
    if (args.version != TLS_FIXER_BROWSER_START_VERSION)
        return tls_fixer_browser_start_failure(TLS_FIXER_START_ARGUMENT_VERSION, args.version, SCE_KERNEL_START_FAILED);
    if (args.compat_modid < 0)
        return tls_fixer_browser_start_failure(TLS_FIXER_START_ARGUMENT_MODULE, (uint32_t)args.compat_modid, SCE_KERNEL_START_FAILED);
    if (args.reserved != 0)
        return tls_fixer_browser_start_failure(TLS_FIXER_START_ARGUMENT_RESERVED, args.reserved, SCE_KERNEL_START_FAILED);
    result = validate_module(args.compat_modid, &text);
    if (result != 0) return reject_start(result);
    ops.timeleft = (int (*)(void *, void *, int))(text + TLS_FIXER_BROWSER_TIMELEFT_OFFSET + 1);
    ops.socket_wait = (int (*)(int, int, int, int))(text + TLS_FIXER_BROWSER_WAIT_OFFSET + 1);
    ops.is_default_ctx_callback = tls_fixer_webkit_is_default_ctx_callback;
    ops.default_ciphers = TLS_FIXER_BROWSER_DEFAULT_CIPHERS;
    ops.default_ca_path = ca_path;
    result = tls_fixer_browser_init(&ops);
    if (result != 0) {
        TLS_FIXER_LOG("browser TLS initialization failed: 0x%08X", result);
        return reject_start(result);
    }
    if (TLS_FIXER_BROWSER_INITIALIZE_ONLY) {
        tls_fixer_browser_enable(0);
        TLS_FIXER_LOG("browser initialization control: no hooks published");
        return SCE_KERNEL_START_SUCCESS;
    }
    for (size_t i = 0; i < BROWSER_HOOK_COUNT; ++i) hook_ids[i] = -1;
    unsigned int published = 0;
#ifdef TLS_FIXER_BROWSER_HOOK_MASK
    const uint32_t selected_hooks = control_hook_mask;
#else
    const uint32_t selected_hooks = 15;
#endif
    for (size_t i = 0; i < BROWSER_HOOK_COUNT; ++i) {
        if ((selected_hooks & (UINT32_C(1) << i)) == 0) continue;
        hook_ids[i] = taiHookFunctionOffset(&hook_refs[i], args.compat_modid, 0,
            hooks[i].offset, 1, hooks[i].function);
        if (hook_ids[i] < 0) {
            TLS_FIXER_LOG("browser TLS inactive: hook=%u error=0x%08X", (unsigned int)i, hook_ids[i]);
            if (published == 0) {
                (void)tls_fixer_browser_destroy();
                return tls_fixer_browser_start_failure((TlsFixerBrowserStartStage)(TLS_FIXER_START_HOOK_CLOSE + i),
                    (uint32_t)hook_ids[i], SCE_KERNEL_START_FAILED);
            }
            /* Published continuations may still be executing on another thread. */
            TLS_FIXER_LOG("browser passthrough hooks retained until process exit");
            return tls_fixer_browser_start_failure((TlsFixerBrowserStartStage)(TLS_FIXER_START_HOOK_CLOSE + i),
                (uint32_t)hook_ids[i], SCE_KERNEL_START_SUCCESS);
        }
        ++published;
    }
    tls_fixer_browser_enable(!TLS_FIXER_BROWSER_PASSTHROUGH_ONLY);
    TLS_FIXER_LOG("browser TLS %s: compat=0x%08X text=0x%08X",
        TLS_FIXER_BROWSER_PASSTHROUGH_ONLY ? "passthrough control" : "active",
        args.compat_modid, (unsigned int)text);
    return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize size, const void *args) {
    (void)size;
    (void)args;
    return SCE_KERNEL_STOP_FAIL;
}

#ifndef TLS_FIXER_HOST_MODULE_TEST
int _start(SceSize size, const void *args) __attribute__((weak, alias("module_start")));
#endif
