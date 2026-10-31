/* SPDX-License-Identifier: 0BSD */
#include "psn_redirect.h"
#include "native_module_api.h"

#include <psp2kern/io/stat.h>
#include <psp2kern/kernel/debug.h>
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/kernel/sysroot.h>
#include <psp2kern/kernel/threadmgr/misc.h>
#include <psp2kern/kernel/threadmgr/mutex.h>
#include <stdint.h>
#include <taihen.h>

#ifndef TLS_FIXER_PSN_REDIRECT_PATH
#define TLS_FIXER_PSN_REDIRECT_PATH "vs0:/data/external/tls_fixer/native/tls_fixer_psn.suprx"
#endif
#define TLS_FIXER_PSN_REDIRECT_NAME "tls_fixer_psn"
#ifndef TLS_FIXER_STORE_COVER_PATH
#define TLS_FIXER_STORE_COVER_PATH "vs0:/data/external/tls_fixer/native/tls_fixer_store.suprx"
#endif
#define TAI_MODULE_NOT_FOUND ((int)UINT32_C(0x90010002))

static int g_ready;
static SceUID g_mutex = -1;

int tls_fixer_psn_redirect_init(void)
{
    SceIoStat status;
    if (g_mutex >= 0)
        return g_ready;
    if (ksceIoGetstat(TLS_FIXER_PSN_REDIRECT_PATH, &status) < 0)
        return 0;
    g_mutex = ksceKernelCreateMutex("tls_fixer reauth", 0, 0, NULL);
    g_ready = g_mutex >= 0;
    return g_ready;
}

void tls_fixer_psn_redirect_destroy(void)
{
    g_ready = 0;
    if (g_mutex >= 0)
        (void)ksceKernelDeleteMutex(g_mutex);
    g_mutex = -1;
}

/* Accept only the native Store module paths; the helper also checks its module identity. */
static int is_store_library(const char *path)
{
    return strcmp(path, "vs0:sys/external/np_commerce2.suprx") == 0 ||
           strcmp(path, "vs0:/sys/external/np_commerce2.suprx") == 0;
}

int tls_fixer_psn_redirect_wanted(SceUID pid, const char *path, int is_libhttp)
{
    if (!g_ready || pid <= 0 || path == NULL)
        return 0;
    if (is_libhttp)
        return pid == ksceKernelSysrootGetShellPid();
    return is_store_library(path) && pid != ksceKernelSysrootGetShellPid();
}

typedef struct ReauthCall
{
    SceUID pid;
    int result;
} ReauthCall;

static int lookup(SceUID pid, const char *name, tai_module_info_t *info)
{
    memset(info, 0, sizeof(*info));
    info->size = sizeof(*info);
    return taiGetModuleInfoForKernel(pid, name, info);
}

static void inject_store_cover(SceUID pid)
{
    char title[16] = {0};
    tai_module_info_t info;
    SceIoStat stat;
    int started = 0;
    /* Commerce also runs inside games and Shell. Artwork is strictly Store-only,
     * before even checking its optional payload or allocating a user module. */
    if (pid == ksceKernelSysrootGetShellPid() ||
        ksceKernelSysrootGetProcessTitleId(pid, title, sizeof(title)) < 0 ||
        strcmp(title, "NPXS10002") != 0)
        return;
    if (lookup(pid, "SceStoreBrowser", &info) != 0 ||
        lookup(pid, "tls_fixer_store", &info) != TAI_MODULE_NOT_FOUND ||
        ksceIoGetstat(TLS_FIXER_STORE_COVER_PATH, &stat) < 0)
        return;
    /* This optional image fallback must never change PSN redirect success. */
    (void)ksceKernelLoadStartModuleForPid(pid, TLS_FIXER_STORE_COVER_PATH,
        0, NULL, 0, NULL, &started);
}

static int inject_on_stack(void *opaque)
{
    ReauthCall *call = opaque;
    tai_module_info_t info;
    int status = 0;

    /* The process must hold the module the redirect hooks */
    const char *target = call->pid == ksceKernelSysrootGetShellPid() ? "SceShell" : "SceNpCommerce2";
    if (lookup(call->pid, target, &info) != 0)
    {
        call->result = 0;
        return 0;
    }
    inject_store_cover(call->pid);
    /* Once per process: hooking the same import twice is never needed */
    int found = lookup(call->pid, TLS_FIXER_PSN_REDIRECT_NAME, &info);
    if (found != TAI_MODULE_NOT_FOUND)
    {
        call->result = found == 0 ? 0 : found;
        return 0;
    }
    SceUID modid = ksceKernelLoadStartModuleForPid(call->pid, TLS_FIXER_PSN_REDIRECT_PATH, 0, NULL, 0, NULL, &status);
    call->result = modid < 0 ? modid : status == SCE_KERNEL_START_SUCCESS ? 0 : -1;
    return 0;
}

int tls_fixer_psn_redirect_inject(SceUID pid)
{
    ReauthCall call = {pid, -1};
    if (!g_ready || pid <= 0)
        return -1;
    int result = ksceKernelLockMutex(g_mutex, 1, NULL);
    if (result < 0)
        return result;
    /* Module loading must not run on the nested native loader's kernel stack */
    result = ksceKernelRunWithStack(16384, inject_on_stack, &call);
    (void)ksceKernelUnlockMutex(g_mutex, 1);
    return result < 0 ? result : call.result;
}
