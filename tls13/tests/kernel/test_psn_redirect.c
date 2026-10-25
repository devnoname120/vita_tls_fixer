#include "psn_redirect.h"
#include <kernel_mock.h>
#include <taihen.h>
#include <assert.h>
#include <stdio.h>

#define SHELL_PID 50
#define NOT_FOUND ((int)UINT32_C(0x90010002))

static int stat_result, mutex_live, locked, create_failure, run_failure;
static int shell_present, store_present, reauth_lookup = NOT_FOUND;
static int loads, load_result = 77, on_stack;
static SceUID loaded_pid;
static char loaded_path[128];

int ksceIoGetstat(const char *path, SceIoStat *status) {
    (void)status;
    assert(strcmp(path, "vs0:/data/external/tls_fixer/native/tls_fixer_psn.suprx") == 0);
    return stat_result;
}
SceUID ksceKernelCreateMutex(const char *name, unsigned int attr, int count, const void *options) {
    assert(name != NULL && attr == 0 && count == 0 && options == NULL && !mutex_live);
    if (create_failure) return -61;
    mutex_live = 1;
    return 23;
}
int ksceKernelDeleteMutex(SceUID id) { assert(id == 23 && mutex_live && !locked); mutex_live = 0; return 0; }
int ksceKernelLockMutex(SceUID id, int count, unsigned int *timeout) {
    assert(id == 23 && mutex_live && !locked && count == 1 && timeout == NULL);
    locked = 1;
    return 0;
}
int ksceKernelUnlockMutex(SceUID id, int count) { assert(id == 23 && count == 1 && locked); locked = 0; return 0; }
SceUID ksceKernelSysrootGetShellPid(void) { return SHELL_PID; }
int ksceDebugPrintf(const char *format, ...) { (void)format; return 0; }
int ksceKernelRunWithStack(SceSize size, int (*function)(void *), void *argument) {
    /* The module load runs on its own stack, while the injection lock is held */
    assert(size == 16384 && locked && !on_stack);
    if (run_failure) return -64;
    on_stack = 1;
    int result = function(argument);
    on_stack = 0;
    return result;
}
int taiGetModuleInfoForKernel(SceUID pid, const char *name, tai_module_info_t *info) {
    assert(on_stack && pid > 0 && info->size == sizeof(*info));
    if (strcmp(name, "SceShell") == 0) {
        assert(pid == SHELL_PID);
        return shell_present ? 0 : NOT_FOUND;
    }
    if (strcmp(name, "SceNpCommerce2") == 0) {
        assert(pid != SHELL_PID);
        return store_present ? 0 : NOT_FOUND;
    }
    assert(strcmp(name, "tls_fixer_psn") == 0);
    return reauth_lookup;
}
SceUID ksceKernelLoadStartModuleForPid(SceUID pid, const char *path, SceSize size, const void *args,
    int flags, const void *options, int *status) {
    assert(on_stack && size == 0 && args == NULL && flags == 0 && options == NULL && status != NULL);
    ++loads;
    loaded_pid = pid;
    strcpy(loaded_path, path);
    *status = 0;
    return load_result;
}

static void reset(void) {
    shell_present = store_present = 1;
    reauth_lookup = NOT_FOUND;
    loads = 0;
    load_result = 77;
    run_failure = 0;
    loaded_pid = 0;
    loaded_path[0] = '\0';
}

int main(void) {
    /* Nothing happens until the module is known to be installed */
    stat_result = -1;
    assert(tls_fixer_psn_redirect_init() == 0 && !mutex_live);
    assert(tls_fixer_psn_redirect_wanted(SHELL_PID, "vs0:sys/external/libhttp.suprx", 1) == 0);
    assert(tls_fixer_psn_redirect_inject(SHELL_PID) < 0 && loads == 0);
    stat_result = 0;
    create_failure = 1;
    assert(tls_fixer_psn_redirect_init() == 0);
    create_failure = 0;
    assert(tls_fixer_psn_redirect_init() == 1 && mutex_live);
    assert(tls_fixer_psn_redirect_init() == 1);

    /* Triggers: the shell's libhttp, and the Store library in any other process */
    assert(tls_fixer_psn_redirect_wanted(SHELL_PID, "vs0:sys/external/libhttp.suprx", 1) == 1);
    assert(tls_fixer_psn_redirect_wanted(99, "vs0:sys/external/libhttp.suprx", 1) == 0);
    assert(tls_fixer_psn_redirect_wanted(99, "vs0:sys/external/np_commerce2.suprx", 0) == 1);
    assert(tls_fixer_psn_redirect_wanted(99, "vs0:/sys/external/np_commerce2.suprx", 0) == 1);
    assert(tls_fixer_psn_redirect_wanted(SHELL_PID, "vs0:sys/external/np_commerce2.suprx", 0) == 0);
    assert(tls_fixer_psn_redirect_wanted(99, "ux0:app/commerce2.suprx", 0) == 0);
    assert(tls_fixer_psn_redirect_wanted(99, "vs0:sys/external/np_commerce.suprx", 0) == 0);
    assert(tls_fixer_psn_redirect_wanted(99, "vs0:sys/external/libssl.suprx", 0) == 0);
    assert(tls_fixer_psn_redirect_wanted(0, "vs0:sys/external/np_commerce2.suprx", 0) == 0);
    assert(tls_fixer_psn_redirect_wanted(99, NULL, 0) == 0);

    reset();
    assert(tls_fixer_psn_redirect_inject(SHELL_PID) == 0 && loads == 1 && loaded_pid == SHELL_PID);
    assert(strcmp(loaded_path, "vs0:/data/external/tls_fixer/native/tls_fixer_psn.suprx") == 0);
    reset();
    assert(tls_fixer_psn_redirect_inject(99) == 0 && loads == 1 && loaded_pid == 99);

    /* Not loaded when the hooked module is missing, or when it is already in the process */
    reset();
    shell_present = 0;
    assert(tls_fixer_psn_redirect_inject(SHELL_PID) == 0 && loads == 0);
    reset();
    store_present = 0;
    assert(tls_fixer_psn_redirect_inject(99) == 0 && loads == 0);
    reset();
    reauth_lookup = 0;
    assert(tls_fixer_psn_redirect_inject(99) == 0 && loads == 0);
    reset();
    reauth_lookup = -55;
    assert(tls_fixer_psn_redirect_inject(99) == -55 && loads == 0);

    /* Failures are reported and leave the lock free */
    reset();
    load_result = -66;
    assert(tls_fixer_psn_redirect_inject(99) == -66 && loads == 1 && !locked);
    reset();
    run_failure = 1;
    assert(tls_fixer_psn_redirect_inject(99) == -64 && loads == 0 && !locked);
    assert(tls_fixer_psn_redirect_inject(0) < 0);

    tls_fixer_psn_redirect_destroy();
    assert(!mutex_live);
    assert(tls_fixer_psn_redirect_wanted(SHELL_PID, "vs0:sys/external/libhttp.suprx", 1) == 0);
    assert(tls_fixer_psn_redirect_inject(SHELL_PID) < 0);
    puts("PSN redirect: shell and Store triggers, once per process, missing targets and failures PASS");
    return 0;
}
