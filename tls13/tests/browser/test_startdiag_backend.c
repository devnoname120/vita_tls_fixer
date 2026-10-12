#include "backend.h"
#include "ca_file.h"
#include "crypto_platform.h"
#include "tls_fixer/browser_start_diagnostics.h"
#include "tls_fixer/registry.h"
#include <psa/crypto.h>
#include <vita_mock.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

static const char *failure;
static SceUID registry_id = -1, attach_id = -1;
static int ca_calls;

int __real_tls_fixer_crypto_platform_init(void);
psa_status_t __real_psa_crypto_init(void);
SceUID __real_sceKernelCreateMutex(const char *, unsigned int, int, const void *);
int __real_sceKernelDeleteMutex(SceUID);
int __real_tls_fixer_registry_init(TlsFixerRegistry *, const TlsFixerRegistryOps *);

int __wrap_tls_fixer_crypto_platform_init(void) {
    return strcmp(failure, "platform") == 0 ? -77 : __real_tls_fixer_crypto_platform_init();
}
psa_status_t __wrap_psa_crypto_init(void) {
    return strcmp(failure, "psa") == 0 ? PSA_ERROR_INSUFFICIENT_MEMORY : __real_psa_crypto_init();
}
int __wrap_tls_fixer_load_ca_file(mbedtls_x509_crt *chain, const char *path) {
    assert(chain != NULL && strcmp(path, "wb0:/cert/CA_LIST.cer") == 0);
    ++ca_calls;
    return strcmp(failure, "ca") == 0 ? -0x2180 : 0;
}
SceUID __wrap_sceKernelCreateMutex(const char *name, unsigned int attr, int count, const void *options) {
    int registry = strcmp(name, "tls_fixer browser registry") == 0;
    int attach = strcmp(name, "tls_fixer browser attach") == 0;
    if (registry && strcmp(failure, "registry-mutex") == 0) return -78;
    if (attach && strcmp(failure, "attach-mutex") == 0) return -79;
    SceUID result = __real_sceKernelCreateMutex(name, attr, count, options);
    if (registry) { assert(registry_id < 0); registry_id = result; }
    if (attach) { assert(attach_id < 0); attach_id = result; }
    return result;
}
int __wrap_sceKernelDeleteMutex(SceUID id) {
    if (id == registry_id) registry_id = -1;
    if (id == attach_id) attach_id = -1;
    return __real_sceKernelDeleteMutex(id);
}
int __wrap_tls_fixer_registry_init(TlsFixerRegistry *registry, const TlsFixerRegistryOps *ops) {
    return strcmp(failure, "registry") == 0 ? -81 : __real_tls_fixer_registry_init(registry, ops);
}

static int timeleft(void *easy, void *now, int connecting) {
    (void)easy; (void)now; (void)connecting;
    return 1000;
}
static int socket_wait(int a, int b, int c, int timeout) {
    (void)a; (void)b; (void)c; (void)timeout;
    return 0;
}

int main(int argc, char **argv) {
    const TlsFixerBrowserOps ops = {
        .timeleft = timeleft,
        .socket_wait = socket_wait,
        .is_default_ctx_callback = NULL,
        .default_ciphers = "known default",
        .default_ca_path = "wb0:/cert/CA_LIST.cer"
    };
    const struct { const char *name; TlsFixerBrowserStartStage stage; int detail; } cases[] = {
        {"argument", TLS_FIXER_START_INIT_ARGUMENT, -1},
        {"platform", TLS_FIXER_START_CRYPTO_PLATFORM, -77},
        {"psa", TLS_FIXER_START_PSA, PSA_ERROR_INSUFFICIENT_MEMORY},
        {"registry-mutex", TLS_FIXER_START_REGISTRY_MUTEX, -78},
        {"attach-mutex", TLS_FIXER_START_ATTACH_MUTEX, -79},
        {"registry", TLS_FIXER_START_REGISTRY, -81}
    };
    assert(argc == 2);
    failure = argv[1];
    int expected = 0;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
        if (strcmp(failure, cases[i].name) == 0)
            expected = tls_fixer_browser_start_code(cases[i].stage, (uint32_t)cases[i].detail);
    assert(expected != 0 || strcmp(failure, "valid") == 0 || strcmp(failure, "ca") == 0);
    assert(tls_fixer_browser_init(strcmp(failure, "argument") == 0 ? NULL : &ops) == expected);
    assert(ca_calls == 0);
    if (expected) {
        assert(registry_id < 0 && attach_id < 0);
        failure = "valid";
        assert(tls_fixer_browser_init(&ops) == 0);
    }
    assert(registry_id >= 0 && attach_id >= 0);
    assert(tls_fixer_browser_init(&ops) == tls_fixer_browser_start_code(TLS_FIXER_START_INIT_ARGUMENT, UINT32_MAX));
    assert(tls_fixer_browser_destroy() == 0);
    assert(registry_id < 0 && attach_id < 0);
    puts("browser initialization status and failed-attempt cleanup: PASS");
    return 0;
}
