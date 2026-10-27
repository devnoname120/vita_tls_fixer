#define main unused_route_suite
#include "test_route.c"
#undef main

static int mutex_live, mutex_locked, native_starts;
SceUID ksceKernelCreateMutex(const char *name, unsigned int attr, int count, const void *options) {
    assert_startup_disarm();
    assert(hook_installations == 0);
    assert(name != NULL && attr == 0 && count == 0 && options == NULL && !mutex_live);
    mutex_live = 1;
    return 41;
}
int ksceKernelDeleteMutex(SceUID id) {
    assert(id == 41 && mutex_live && !mutex_locked && installed_start == NULL);
    mutex_live = 0;
    return 0;
}
int ksceKernelLockMutex(SceUID id, int count, unsigned int *timeout) {
    assert(id == 41 && mutex_live && !mutex_locked && count == 1 && timeout == NULL);
    mutex_locked = 1;
    return 0;
}
int ksceKernelUnlockMutex(SceUID id, int count) {
    assert(id == 41 && mutex_locked && count == 1);
    mutex_locked = 0;
    return 0;
}
static int original_start(SceUID pid, SceUID module, SceSize size, const void *data,
    uint32_t flags, const void *options, int *status) {
    assert(pid == 0 && module == 88 && size == 3 && data == (void *)(uintptr_t)0x12340000);
    assert(flags == 0x8001 && options == (void *)(uintptr_t)0x56780000 && status != NULL);
    assert(!mutex_locked && injections == 0);
    ++native_starts;
    native_link_finished = 1;
    *status = 19;
    return 0;
}
int main(void) {
    reset(); checking_startup = 1;
#if !TLS_FIXER_ENABLE_SELF_DISARM
    /* A disarm failure must be irrelevant when normal activation omits it. */
    disarm_result = -1;
#endif
    assert(module_start(0, NULL) == SCE_KERNEL_START_SUCCESS);
    assert(disarm_calls == (TLS_FIXER_ENABLE_SELF_DISARM ? 1 : 0));
    assert(hook_installations == 2 && installed_start != NULL && mutex_live);
    checking_startup = 0;
    int options = 4, status = -999;
    assert(load_for_pid_patched(0,"wb0:/webcore/ScePsp2Compat.suprx",0x8001,&options)==88);
    assert(injections == 0 && dns_loads == 0);
    current_pid = 99;
    assert(installed_start(0,88,3,(void *)(uintptr_t)0x12340000,0x8001,
        (void *)(uintptr_t)0x56780000,&status)==0);
    assert(native_starts == 1 && status == 19 && injections == 1 && injected_pid == 99);
    assert(strcmp(provider_path,"wb0:/tls_fixer/tls_fixer.suprx")==0);
    /* The isolation control suppresses HTTP only; normal packaging retains it. */
    reset();
    assert(load_for_pid_patched(0,"vs0:sys/external/libhttp.suprx",0,&options)==88);
    assert(injections == 0);
    current_pid = 99;
    assert(installed_start(0,88,3,(void *)(uintptr_t)0x12340000,0x8001,
        (void *)(uintptr_t)0x56780000,&status)==0);
    assert(native_starts == 2 && status == 19);
    assert(injections == (TLS_FIXER_SKIP_HTTP_START ? 0 : 1));
    if (!TLS_FIXER_SKIP_HTTP_START) assert(injected_pid == 99);
    reset();
    g_dns_fix_state = 2;
    assert(load_for_pid_patched(0, "vs0:sys/external/libssl.suprx", 0, NULL) == 88);
    assert(dns_loads == (TLS_FIXER_SKIP_DNS_START ? 0 : 1));
    assert(strcmp(selected_path, g_replacement_modules[2]) == 0);
    /* Only eligible HTTP/SSL replacement code becomes private. Preserve every
     * other flag, excluded-process sharing and Browser's independent mapping. */
    const char *private_paths[] = {"vs0:sys/external/libhttp.suprx", "vs0:sys/external/libssl.suprx"};
    for (unsigned i=0;i<2;++i) {
        reset(); http_process_allowed = 1;
        assert(load_for_pid_patched(0, private_paths[i], 0x08008001, NULL)==88);
        assert(seen_flags==(TLS_FIXER_SKIP_HTTP_START ? 0x08008001u : 0x8000u));
        reset(); http_process_allowed = 0;
        assert(load_for_pid_patched(0, private_paths[i], 0x08008001, NULL)==88);
        assert(seen_flags==0x08008001);
    }
    http_process_allowed = 1;
    reset();
    assert(load_for_pid_patched(0, "wb0:/webcore/ScePsp2Compat.suprx", 0x8001, NULL)==88);
    assert(seen_flags==0x8001);
    /* Regression: reAuth rewrites both library names in SceSysmodule before
     * the kernel loader sees them. Config presence alone does not activate TLS. */
    const char *redirected_paths[] = {
        "ur0:data/reAuth/libhttp.suprx", "ur0:/data/reAuth/libhttp.suprx",
        "vs0:/data/external/itls/libhttp.suprx", "vs0:data/external/itls/libhttp.suprx",
        "ur0:data/reAuth/libssl.suprx", "ur0:/data/reAuth/libssl.suprx",
        "vs0:/data/external/itls/libssl.suprx", "vs0:data/external/itls/libssl.suprx"
    };
    /* Clear any pending fixture load before checking each isolated request. */
    (void)tls_fixer_post_start_complete(99, 88, -1);
    for (unsigned i = 0; i < sizeof(redirected_paths) / sizeof(redirected_paths[0]); ++i) {
        int is_http = i < 4;
        reset();
        assert(load_for_pid_patched(0, redirected_paths[i], 0x08008001, &options) == 88);
        assert(strcmp(selected_path, g_replacement_modules[is_http ? 1 : 2]) == 0);
        assert(seen_flags == (TLS_FIXER_SKIP_HTTP_START ? 0x08008001u : 0x8000u));
        assert(injections == 0 && seen_pid == 0 && seen_options == &options);
        current_pid = 99;
        assert(installed_start(0, 88, 3, (void *)(uintptr_t)0x12340000, 0x8001,
            (void *)(uintptr_t)0x56780000, &status) == 0);
        assert(injections == (is_http && !TLS_FIXER_SKIP_HTTP_START ? 1 : 0));
        /* Disabling the system component must leave these files alone. */
        reset(); g_replace_iap = 0;
        assert(load_for_pid_patched(0, redirected_paths[i], 0x08008001, NULL) == 88);
        assert(strcmp(selected_path, redirected_paths[i]) == 0 && seen_flags == 0x08008001);
        assert(tls_fixer_post_start_complete(99, 88, 0) == 0 && injections == 0);
        /* A failed native load must never queue a provider. */
        reset(); load_result = -43;
        assert(load_for_pid_patched(0, redirected_paths[i], 0, NULL) == -43);
        assert(tls_fixer_post_start_complete(99, 88, 0) == 0 && injections == 0);
        reset(); http_process_allowed = 0;
        assert(load_for_pid_patched(0, redirected_paths[i], 0x08008001, NULL) == 88);
        assert(seen_flags == 0x08008001);
        (void)tls_fixer_post_start_complete(99, 88, -1);
        http_process_allowed = 1;
    }
    assert(module_stop(0,NULL)==SCE_KERNEL_STOP_FAIL);
    puts("production post-start: browser deferral, native results and application provider retained PASS");
}
