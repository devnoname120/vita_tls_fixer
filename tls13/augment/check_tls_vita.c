#include <psp2/libssl.h>
#include <psp2/net/http.h>
#include <psp2/rtc.h>
#include <taihen.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef int (*Record)(const char *, ...);
int tls_fixer_augment_memory(const char *phase);
static Record g_log;
static void *g_saved_name;
static uint32_t g_saved_digest, g_callbacks;
static void *(*g_subject)(void *);
static int (*g_name_count)(void *);
static int (*g_name_info)(void *, int, char *, unsigned int, char *, unsigned int, unsigned int *);
static int (*g_free_name)(void *);
static int (*g_ssl_term)(void);
static int g_ssl_live;

static uintptr_t resolve(const char *module, uint32_t library, uint32_t nid) {
    uintptr_t address = 0;
    int rc = taiGetModuleExportFunc(module, library, nid, &address);
    g_log("tls.resolve nid=%08X rc=%08X address=%08X\n", nid, rc, (unsigned int)address);
    return rc < 0 ? 0 : address;
}

static uint32_t name_digest(void *name) {
    int count = g_name_count(name);
    if (count < 0 || count > 32) return 0;
    uint32_t digest = 2166136261u;
    for (int i = 0; i < count; ++i) {
        char oid[128] = {0}, value[512] = {0};
        unsigned int length = 0;
        if (g_name_info(name, i, oid, sizeof(oid), value, sizeof(value), &length) < 0 || length > sizeof(value)) return 0;
        for (size_t j = 0; j < strlen(oid); ++j) digest = (digest ^ (unsigned char)oid[j]) * 16777619u;
        for (unsigned int j = 0; j < length; ++j) digest = (digest ^ (unsigned char)value[j]) * 16777619u;
    }
    return digest;
}

static int certificate_callback(unsigned int errors, SceSslCert *const certs[], int count, void *arg) {
    (void)arg;
    ++g_callbacks;
    g_log("tls.callback errors=%08X count=%d\n", errors, count);
    if (errors || count <= 0 || certs == NULL) return -1;
    if (g_saved_name == NULL) {
        g_saved_name = g_subject(certs[0]);
        if (g_saved_name == NULL) return -1;
        g_saved_digest = name_digest(g_saved_name);
        g_log("tls.callback.name object=%08X digest=%08X\n", (unsigned int)(uintptr_t)g_saved_name, g_saved_digest);
        if (g_saved_digest == 0) return -1;
    }
    return 0;
}

int tls_fixer_embedded_check_names(Record log, int release) {
    if (g_saved_name == NULL) return -1;
    uint32_t digest = name_digest(g_saved_name);
    log("tls.retained_name digest=%08X expected=%08X release=%d\n", digest, g_saved_digest, release);
    int good = digest == g_saved_digest && digest != 0;
    if (release) {
        int rc = g_free_name(g_saved_name);
        log("tls.retained_name.free=%08X\n", rc);
        g_saved_name = NULL;
        good &= rc == 0;
    }
    return good ? 0 : -1;
}

int tls_fixer_embedded_check_ssl_term(Record log) {
    if (!g_ssl_live) return 0;
    int rc = g_ssl_term();
    log("tls.ssl.term=%08X\n", rc);
    if (rc == 0) g_ssl_live = 0;
    return rc;
}

int tls_fixer_embedded_check_network(Record log) {
    g_log = log;
    g_subject = (void *)resolve("SceLibSsl", 0xcaf5f2e9, 0x9b2f1bc1);
    g_name_count = (void *)resolve("SceLibSsl", 0xcaf5f2e9, 0x95e14ca6);
    g_name_info = (void *)resolve("SceLibSsl", 0xcaf5f2e9, 0x2a857867);
    g_free_name = (void *)resolve("SceLibSsl", 0xcaf5f2e9, 0xc73687e4);
    int (*initialize)(unsigned int) = (void *)resolve("SceLibHttp", 0xe8f15cde, 0x214926d9);
    int (*terminate)(void) = (void *)resolve("SceLibHttp", 0xe8f15cde, 0xc9076666);
    int (*ssl_init)(unsigned int) = (void *)resolve("SceLibSsl", 0xcaf5f2e9, 0x3c733316);
    g_ssl_term = (void *)resolve("SceLibSsl", 0xcaf5f2e9, 0x03ce6e3a);
    const uint32_t *(*snapshot)(void) = (void *)resolve("SceLibHttp", 0x7f10b001, 0x7f10b002);
    int (*create_template)(const char *, int, int) = (void *)resolve("SceLibHttp", 0xe8f15cde, 0x62241dab);
    int (*delete_template)(int) = (void *)resolve("SceLibHttp", 0xe8f15cde, 0xec85ecfb);
    int (*create_connection)(int, const char *, int) = (void *)resolve("SceLibHttp", 0xe8f15cde, 0xc616c200);
    int (*delete_connection)(int) = (void *)resolve("SceLibHttp", 0xe8f15cde, 0xf0f65c15);
    int (*create_request)(int, int, const char *, uint64_t) = (void *)resolve("SceLibHttp", 0xe8f15cde, 0xbd5da1d0);
    int (*delete_request)(int) = (void *)resolve("SceLibHttp", 0xe8f15cde, 0x3d3d29ad);
    int (*send)(int, const void *, unsigned int) = (void *)resolve("SceLibHttp", 0xe8f15cde, 0x9ca58b99);
    int (*read)(int, void *, unsigned int) = (void *)resolve("SceLibHttp", 0xe8f15cde, 0x7ede3979);
    int (*http_code)(int, int *) = (void *)resolve("SceLibHttp", 0xe8f15cde, 0x27071691);
    int (*ssl_error)(int, int *, unsigned int *) = (void *)resolve("SceLibHttp", 0xe8f15cde, 0x2b79bde0);
    int (*enable)(unsigned int) = (void *)resolve("SceLibHttp", 0xe8f15cde, 0x9fbe2869);
    int (*set_callback)(int, SceHttpsCallback, void *) = (void *)resolve("SceLibHttp", 0xe8f15cde, 0xa0926037);
    int (*timeouts[4])(int, unsigned int);
    const uint32_t timeout_nids[] = {0x8455b5b3,0x237ca86e,0x8ae3f008,0x94bf196e};
    for (int i = 0; i < 4; ++i) timeouts[i] = (void *)resolve("SceLibHttp", 0xe8f15cde, timeout_nids[i]);
    if (!g_subject || !g_name_count || !g_name_info || !g_free_name || !initialize || !terminate || !ssl_init ||
        !g_ssl_term || !snapshot || !create_template || !delete_template || !create_connection || !delete_connection ||
        !create_request || !delete_request || !send || !read || !http_code || !ssl_error || !enable || !set_callback)
        return -1;
    for (int i = 0; i < 4; ++i) if (!timeouts[i]) return -1;
    int rc = ssl_init(256 * 1024);
    log("tls.ssl.init=%08X\n", rc);
    if (rc < 0) return -1;
    g_ssl_live = 1;
    if (tls_fixer_augment_memory("ssl_initialized") < 0) return -1;
    rc = initialize(128 * 1024);
    log("tls.http.init=%08X\n", rc);
    if (rc < 0) return -1;
    if (tls_fixer_augment_memory("http_initialized") < 0) { terminate(); return -1; }
    const uint32_t *stats = snapshot();
    log("tls.backend state=%u error=%08X capacity=%u used=%u peak=%u creates=%u fallbacks=%u calls=%u\n",
        stats[2], stats[3], stats[4], stats[5], stats[6], stats[7], stats[8], stats[9]);
    if (stats[2] != 2 || stats[3] != 0) { terminate(); return -1; }
    rc = enable(0x3d); /* Full server, name, time and trust verification. */
    log("tls.verify.enable=%08X flags=0000003D\n", rc);
    if (rc < 0) { terminate(); return -1; }
    const char *urls[] = {"https://tls13.browserleaks.com/",
        "https://cloudflare.com/cdn-cgi/trace?itls13=20261009-browser1&retry=20261029-embedded1",
        "https://tls12.browserleaks.com/"};
    int failed = 0;
    for (unsigned int i = 0; i < 3; ++i) {
        int tid = create_template("tls_fixer module check", 2, 0), cid = -1, rid = -1;
        log("tls.request.begin index=%u template=%08X url=%s\n", i, tid, urls[i]);
        if (tid < 0) { failed = 1; break; }
        for (int t = 0; t < 4; ++t) { rc = timeouts[t](tid, 8000000); if (rc < 0) failed = 1; }
        if (i == 0 && set_callback(tid, certificate_callback, NULL) < 0) failed = 1;
        cid = create_connection(tid, urls[i], 0);
        if (cid >= 0) rid = create_request(cid, SCE_HTTP_METHOD_GET, urls[i], 0);
        log("tls.request.objects connection=%08X request=%08X\n", cid, rid);
        if (rid >= 0 && !failed) {
            log("tls.send.enter index=%u\n", i);
            rc = send(rid, NULL, 0);
            int code = 0, error = 0; unsigned int detail = 0;
            int code_rc = http_code(rid, &code);
            ssl_error(rid, &error, &detail);
            log("tls.send.return index=%u rc=%08X http=%d code_rc=%08X ssl=%08X detail=%08X\n", i, rc, code, code_rc, error, detail);
            if (rc == 0 && code == 200) {
                char body[8192] = {0}; size_t used = 0;
                while (used < sizeof(body) - 1) {
                    rc = read(rid, body + used, sizeof(body) - 1 - used);
                    if (rc <= 0) break;
                    used += (unsigned int)rc;
                }
                body[used] = 0;
                log("tls.body index=%u bytes=%u read_rc=%08X trace_tls13=%d\n", i, (unsigned int)used, rc,
                    strstr(body, "tls=TLSv1.3") != NULL);
                if (rc < 0 || (i == 1 && strstr(body, "tls=TLSv1.3") == NULL)) failed = 1;
            } else failed = 1;
        } else failed = 1;
        if (rid >= 0) delete_request(rid);
        if (cid >= 0) delete_connection(cid);
        delete_template(tid);
        if (failed) break;
    }
    stats = snapshot();
    log("tls.backend.final state=%u used=%u peak=%u creates=%u fallbacks=%u callbacks=%u\n",
        stats[2], stats[5], stats[6], stats[7], stats[8], g_callbacks);
    if (stats[7] < 3 || stats[8] != 0 || g_callbacks == 0) failed = 1;
    if (tls_fixer_augment_memory("requests_deleted") < 0) failed = 1;
    rc = terminate();
    stats = snapshot();
    log("tls.http.term=%08X state=%u error=%08X capacity=%u used=%u\n", rc, stats[2], stats[3], stats[4], stats[5]);
    if (rc < 0 || stats[2] != 0 || stats[4] != 0 || stats[5] != 0) failed = 1;
    if (tls_fixer_augment_memory("http_terminated") < 0) failed = 1;
    return failed ? -1 : 0;
}
