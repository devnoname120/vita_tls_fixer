#include <psp2/kernel/modulemgr.h>
#include <psp2/kernel/processmgr.h>
#include <psp2/kernel/sysmem.h>
#include <psp2/kernel/threadmgr/thread.h>
#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#include <psp2/net/net.h>
#include <psp2/net/netctl.h>
#include <psp2/sysmodule.h>
#include <taihen.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int _newlib_heap_size_user = 512 * 1024;
#if TLS_FIXER_AUGMENT_TLS_CHECK
static const char *const g_path = TLS_FIXER_AUGMENT_MODULE_PATH;
static const char *const g_log_path = "ux0:/data/tls_fixer-augment/embedded-check.txt";
int tls_fixer_embedded_check_network(int (*log)(const char *, ...));
int tls_fixer_embedded_check_names(int (*log)(const char *, ...), int release);
int tls_fixer_embedded_check_ssl_term(int (*log)(const char *, ...));
#if TLS_FIXER_AUGMENT_SMALL_STACK_CHECK
int tls_fixer_embedded_check_stack(int (*log)(const char *, ...));
#endif
#if TLS_FIXER_AUGMENT_CUSTOM_CA_CHECK
int tls_fixer_embedded_check_custom_ca(int (*log)(const char *, ...));
#endif
#else
static const char *const g_path = "ux0:/data/tls_fixer-augment/http-lifecycle.suprx";
#endif
#if TLS_FIXER_AUGMENT_SHARED_CHECK
/* Verified retail 3.60 SceLibKernel wrappers, NIDs 4F2D8B15 / 657FA50E.
 * The underscored raw syscalls use a different fourth-argument ABI. */
extern SceUID sceKernelOpenModule(const char *, SceSize, void *, int, SceKernelLMOption *, int *);
extern int sceKernelCloseModule(SceUID, SceSize, void *, int, SceKernelULMOption *, int *);
#define load_module sceKernelOpenModule
#define close_module sceKernelCloseModule
#if !TLS_FIXER_AUGMENT_TLS_CHECK
static const char *const g_log_path = "ux0:/data/tls_fixer-augment/shared-check.txt";
#endif
#else
#define load_module sceKernelLoadStartModule
#define close_module sceKernelStopUnloadModule
#if !TLS_FIXER_AUGMENT_TLS_CHECK
static const char *const g_log_path = "ux0:/data/tls_fixer-augment/private-check.txt";
#endif
#endif
static int g_log = -1;
static unsigned char g_net_memory[256 * 1024];
#if TLS_FIXER_AUGMENT_CERT_CHECK
int tls_fixer_native_cert_check(int (*log)(const char *, ...));
#endif

static int record(const char *format, ...) {
    char text[512];
    va_list args;
    va_start(args, format);
    int n = vsnprintf(text, sizeof(text), format, args);
    va_end(args);
    if (n < 0 || (unsigned int)n >= sizeof(text)) return -1;
    if (sceIoWrite(g_log, text, n) != n) return -1;
    return sceIoSync("ux0:", 0);
}

int tls_fixer_augment_memory(const char *phase) {
    SceKernelFreeMemorySizeInfo info = {.size = sizeof(info)};
    int rc = sceKernelGetFreeMemorySize(&info);
    if (record("memory phase=%s rc=%08X user_free=%d cdram_free=%d phycont_free=%d\n",
        phase, rc, info.size_user, info.size_cdram, info.size_phycont) < 0) return -1;
    return rc;
}

static uintptr_t resolve(uint32_t library, uint32_t nid) {
    uintptr_t address = 0;
    int rc = taiGetModuleExportFunc("SceLibHttp", library, nid, &address);
    if (record("resolve library=%08X nid=%08X rc=%08X address=%08X\n",
               library, nid, rc, (unsigned int)address) < 0 || rc < 0) return 0;
    return address;
}

static int inspect(SceUID module) {
    SceKernelModuleInfo info;
    memset(&info, 0, sizeof(info));
    info.size = sizeof(info);
    int rc = sceKernelGetModuleInfo(module, &info);
    if (record("module.info rc=%08X name=%.28s path=%.256s\n", rc, info.module_name, info.path) < 0) return -1;
    if (rc < 0 || strcmp(info.module_name, "SceLibHttp") != 0) return -1;
    for (int i = 0; i < 2; ++i) {
        if (record("segment=%d base=%08X file=%u memory=%u permissions=%X\n", i,
                   (unsigned int)(uintptr_t)info.segments[i].vaddr, info.segments[i].filesz,
                   info.segments[i].memsz, info.segments[i].perms) < 0) return -1;
    }
    const uint32_t *(*snapshot)(void) = (void *)resolve(
        TLS_FIXER_AUGMENT_TLS_CHECK ? 0x7f10b001 : 0x7f10a001,
        TLS_FIXER_AUGMENT_TLS_CHECK ? 0x7f10b002 : 0x7f10a002);
    if (snapshot == NULL) return -1;
    const uint32_t *p = snapshot();
    if (p == NULL || p[0] != 0x41584654) return -1;
#if TLS_FIXER_AUGMENT_TLS_CHECK
    struct {
        uint32_t size;
        uint16_t version, attributes;
        uint32_t libnid, name;
        uint16_t functions, variables;
        uint32_t nids, entries;
    } library = {.size = sizeof(library)};
    int library_result = sceKernelGetLibraryInfoByNID(module, 0x7f10b001, (SceKernelLibraryInfo *)&library);
    record("embedded.library rc=%08X nid=%08X version=%u functions=%u\n",
           library_result, library.libnid, library.version, library.functions);
    if (library_result != 0 || library.libnid != 0x7f10b001) return -1;
    record("embedded.marker version=%u state=%u error=%08X capacity=%u used=%u\n", p[1],p[2],p[3],p[4],p[5]);
    return p[1] == 2 && p[2] == 0 && p[3] == 0 && p[4] == 0 ? 0 : -1;
#else
    if (p[1] != 1) return -1;
    if (record("probe state=%08X starts=%u stops=%u start_result=%08X stop_result=%08X\n",
               (unsigned int)(uintptr_t)p, p[4], p[5], p[6], p[7]) < 0) return -1;
    return p[4] == 1 && p[5] == 0 && p[6] == 0 ? 0 : -1;
#endif
}

static int http_cycle(void) {
    int (*initialize)(unsigned int) = (void *)resolve(0xe8f15cde, 0x214926d9);
    int (*terminate)(void) = (void *)resolve(0xe8f15cde, 0xc9076666);
    int (*create_template)(const char *, int, int) = (void *)resolve(0xe8f15cde, 0x62241dab);
    int (*delete_template)(int) = (void *)resolve(0xe8f15cde, 0xec85ecfb);
    int (*create_connection)(int, const char *, int) = (void *)resolve(0xe8f15cde, 0xc616c200);
    int (*delete_connection)(int) = (void *)resolve(0xe8f15cde, 0xf0f65c15);
    int (*create_request)(int, int, const char *, uint64_t) = (void *)resolve(0xe8f15cde, 0xbd5da1d0);
    int (*delete_request)(int) = (void *)resolve(0xe8f15cde, 0x3d3d29ad);
    if (!initialize || !terminate || !create_template || !delete_template || !create_connection ||
        !delete_connection || !create_request || !delete_request) return -1;
    int rc = initialize(128 * 1024);
    if (record("http.init=%08X\n", rc) < 0 || rc < 0) return -1;
    int tid = create_template("tls_fixer module check", 2, 0);
    int cid = -1, rid = -1, failed = tid < 0;
    record("http.template=%08X\n", tid);
    if (tid >= 0) {
        cid = create_connection(tid, "http://127.0.0.1/", 0);
        record("http.connection=%08X\n", cid);
        if (cid >= 0) {
            rid = create_request(cid, 0, "http://127.0.0.1/", 0);
            record("http.request=%08X\n", rid);
        }
        failed |= cid < 0 || rid < 0;
    }
    if (rid >= 0) { rc = delete_request(rid); failed |= rc < 0; record("http.delete_request=%08X\n", rc); }
    if (cid >= 0) { rc = delete_connection(cid); failed |= rc < 0; record("http.delete_connection=%08X\n", rc); }
    if (tid >= 0) { rc = delete_template(tid); failed |= rc < 0; record("http.delete_template=%08X\n", rc); }
    rc = terminate();
    record("http.term=%08X\n", rc);
    return failed || rc < 0 ? -1 : 0;
}

int main(void) {
    (void)sceIoMkdir("ux0:/data/tls_fixer-augment", 0777);
    g_log = sceIoOpen(g_log_path, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0666);
    if (g_log < 0) return 1;
    int failed = 1, net_ready = 0, netctl_ready = 0;
    SceUID module = -1;
    SceUID ssl_module = -1;
    int start_result = -1;
    if (record("begin module control shared=%d tls=%d; no boot changes\n",
               TLS_FIXER_AUGMENT_SHARED_CHECK, TLS_FIXER_AUGMENT_TLS_CHECK) < 0) goto finish;
    if (record("run.identity pid=%08X tid=%08X device_us=%llu\n", (unsigned int)sceKernelGetProcessId(),
               (unsigned int)sceKernelGetThreadId(), (unsigned long long)sceKernelGetSystemTimeWide()) < 0) goto finish;
    SceUID list[64]; SceSize count = 64;
    int rc = sceKernelGetModuleList(0xff, list, &count);
    record("module.list=%08X count=%u\n", rc, count);
    if (rc < 0 || count > 64) goto finish;
    for (SceSize i = 0; i < count; ++i) {
        SceKernelModuleInfo info = { .size = sizeof(info) };
        if (sceKernelGetModuleInfo(list[i], &info) < 0) goto finish;
        if (strcmp(info.module_name, "SceLibHttp") == 0) {
            record("refused: HTTP already mapped in diagnostic process\n");
            goto finish;
        }
    }
    rc = sceSysmoduleLoadModule(SCE_SYSMODULE_NET);
    record("dependency.net=%08X\n", rc);
    if (rc < 0) goto finish;
    SceNetInitParam net = { .memory = g_net_memory, .size = sizeof(g_net_memory), .flags = 0 };
    rc = sceNetInit(&net); record("net.init=%08X\n", rc);
    if (rc < 0) goto finish;
    net_ready = 1;
    rc = sceNetCtlInit(); record("netctl.init=%08X\n", rc);
    if (rc < 0) goto finish;
    netctl_ready = 1;
    if (tls_fixer_augment_memory("before_ssl_module") < 0) goto finish;
#if TLS_FIXER_AUGMENT_SHARED_CHECK
    /* Use the existing installed Sony SSL directly. Going through Sysmodule
     * would let the current coordinator force this dependency private. */
    if (record("dependency.ssl.shared.enter\n") < 0) goto finish;
    ssl_module = sceKernelOpenModule("vs0:/data/external/tls_fixer/libssl.suprx",
                                    0, NULL, 0, NULL, &start_result);
    record("dependency.ssl.shared.return module=%08X start=%08X\n", ssl_module, start_result);
    rc = ssl_module < 0 ? ssl_module : start_result;
#else
    rc = sceSysmoduleLoadModule(SCE_SYSMODULE_SSL);
#endif
    record("dependency.ssl=%08X\n", rc);
    if (rc < 0) goto finish;
    if (ssl_module >= 0) {
        SceKernelModuleInfo info = {.size = sizeof(info)};
        int info_rc = sceKernelGetModuleInfo(ssl_module, &info);
        record("dependency.ssl.info rc=%08X name=%.28s path=%.256s text=%u data=%u\n",
            info_rc, info.module_name, info.path, info.segments[0].memsz, info.segments[1].memsz);
        const uint32_t nids[] = {0x16d7c7ca, 0x3746501f};
        for (unsigned int i = 0; i < sizeof(nids) / sizeof(nids[0]); ++i) {
            uintptr_t address = 0;
            int lookup = taiGetModuleExportFunc("SceLibSsl", 0x68d6c3ff, nids[i], &address);
            record("dependency.ssl.export nid=%08X rc=%08X address=%08X\n", nids[i], lookup, (unsigned int)address);
        }
    }
    if (tls_fixer_augment_memory("before_http_module") < 0) goto finish;
#if TLS_FIXER_AUGMENT_DEPENDENCY_ONLY
    record("dependency.inventory.complete augmented_http_not_loaded=1\n");
    failed = 0;
    goto finish;
#endif
#if TLS_FIXER_AUGMENT_CERT_CHECK
    if (tls_fixer_native_cert_check(record) < 0) goto finish;
#endif
    if (record("load.enter path=%s\n", g_path) < 0) goto finish;
    module = load_module(g_path, 0, NULL, 0, NULL, &start_result);
    record("load.return module=%08X start=%08X\n", module, start_result);
    if (module < 0 || start_result != 0 || inspect(module) < 0) goto finish;
    if (tls_fixer_augment_memory("http_module_loaded") < 0) goto finish;
#if TLS_FIXER_AUGMENT_TLS_CHECK
#if TLS_FIXER_AUGMENT_SMALL_STACK_CHECK
    if (tls_fixer_embedded_check_stack(record) < 0) goto finish;
#endif
    if (tls_fixer_embedded_check_network(record) < 0) goto finish;
#if TLS_FIXER_AUGMENT_CUSTOM_CA_CHECK
    if (tls_fixer_embedded_check_custom_ca(record) < 0) goto finish;
#endif
#else
    if (http_cycle() < 0 || http_cycle() < 0) goto finish;
#endif
    if (record("stop.enter\n") < 0) goto finish;
    rc = close_module(module, 0, NULL, 0, NULL, &start_result);
    record("stop.return rc=%08X result=%08X\n", rc, start_result);
    if (rc < 0 || start_result != 0) goto finish;
    module = -1;
    if (tls_fixer_augment_memory("http_module_closed") < 0) goto finish;
#if TLS_FIXER_AUGMENT_TLS_CHECK
    if (tls_fixer_embedded_check_names(record, 0) < 0) goto finish;
#endif
    if (record("reload.enter\n") < 0) goto finish;
    module = load_module(g_path, 0, NULL, 0, NULL, &start_result);
    record("reload.return module=%08X start=%08X\n", module, start_result);
    if (module < 0 || start_result != 0 || inspect(module) < 0 || http_cycle() < 0) goto finish;
    rc = close_module(module, 0, NULL, 0, NULL, &start_result);
    record("final_stop rc=%08X result=%08X\n", rc, start_result);
    if (rc < 0 || start_result != 0) goto finish;
    module = -1;
#if TLS_FIXER_AUGMENT_TLS_CHECK
    if (tls_fixer_embedded_check_names(record, 1) < 0 || tls_fixer_embedded_check_ssl_term(record) < 0) goto finish;
#endif
    failed = 0;
finish:
    /* Process exit owns any still-loaded module after an unsuccessful check.
     * Do not attempt a second unload after an ambiguous failure. */
    if (module < 0) {
        if (ssl_module >= 0) {
            rc = close_module(ssl_module, 0, NULL, 0, NULL, &start_result);
            record("dependency.ssl.close=%08X result=%08X\n", rc, start_result);
            (void)tls_fixer_augment_memory("ssl_module_closed");
        }
        if (netctl_ready) sceNetCtlTerm();
        if (net_ready) sceNetTerm();
    }
    record("end passed=%d\n", !failed);
    sceIoClose(g_log);
    return failed;
}
