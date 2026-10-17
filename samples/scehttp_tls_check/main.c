#include "diagnostics.h"
#include "font.h"
#include "input.h"
#include "model.h"
#include "probe.h"
#include "ui.h"
#include <psp2/ctrl.h>
#include <psp2/display.h>
#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#include <psp2/kernel/processmgr.h>
#include <psp2/kernel/modulemgr.h>
#include <psp2/kernel/sysmem.h>
#include <psp2/kernel/threadmgr.h>
#include <psp2/libssl.h>
#include <psp2/net/http.h>
#include <psp2/net/net.h>
#include <psp2/net/netctl.h>
#include <psp2/sysmodule.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned int _newlib_heap_size_user = 8u * 1024u * 1024u;
static CheckService service = {.tls_fixer_enabled = -1}, view, last_view;
static SceUID guard = -1, worker = -1;
static int busy, active_request = -1, cancelled, abort_sent;
static uint64_t request_begin;
static unsigned request_identity, next_request_identity, run_identity;
static char notice[120];
#define VERIFY_FLAGS (SCE_HTTPS_FLAG_SERVER_VERIFY | SCE_HTTPS_FLAG_CN_CHECK | \
    SCE_HTTPS_FLAG_NOT_AFTER_CHECK | SCE_HTTPS_FLAG_NOT_BEFORE_CHECK | SCE_HTTPS_FLAG_KNOWN_CA_CHECK)
static void startup_note(const char *stage, int result) {
    check_diag("event=startup stage=%s rc=%08X", stage, (unsigned)result);
    (void)sceIoMkdir("ux0:/data/vita-tls-check", 0777);
    int fd = sceIoOpen("ux0:/data/vita-tls-check/startup.txt",
                       SCE_O_WRONLY | SCE_O_CREAT | SCE_O_APPEND, 0666);
    if (fd >= 0) {
        char line[128];
        int n = snprintf(line, sizeof(line), "%llu %s 0x%08X\n",
                         (unsigned long long)sceKernelGetSystemTimeWide(), stage, (unsigned)result);
        if (n > 0 && (size_t)n < sizeof(line))
            (void)sceIoWrite(fd, line, (unsigned)n);
        (void)sceIoClose(fd);
    }
}
static uint64_t now_ms(void) { return sceKernelGetSystemTimeWide() / 1000; }
static void lock(void) { sceKernelLockMutex(guard, 1, NULL); }
static void unlock(void) { sceKernelUnlockMutex(guard, 1); }
static int stopped(void) {
    lock();
    int c = cancelled;
    unlock();
    return c;
}
static void publish(unsigned row, const CheckResult *r) {
    lock();
    if (row == CHECK_REPORT)
        service.connection = *r;
    else if (row == CHECK_PLAYSTATION)
        service.playstation = *r;
    else
        service.protocols[row] = *r;
    unlock();
}

/* Keep request ownership locked across abort/delete, but never across blocking
 * I/O. */
static void abort_current(int user_cancel) {
    lock();
    if (user_cancel)
        cancelled = 1;
    /* Recheck the current deadline under ownership lock; a new request may have
     * started. */
    if (active_request >= 0 && !abort_sent && (user_cancel || now_ms() - request_begin > 20000)) {
        abort_sent = 1;
        check_diag("event=api.enter request=%u handle=%08X "
                   "call=sceHttpAbortRequest reason=%s",
                   request_identity, (unsigned)active_request, user_cancel ? "cancel" : "deadline");
        int abort_result = sceHttpAbortRequest(active_request);
        check_diag("event=api.return request=%u call=sceHttpAbortRequest rc=%08X", request_identity,
                   (unsigned)abort_result);
    }
    unlock();
}
static int fetch(void *context, unsigned test, int verify, char *body, size_t *length,
                 CheckResult *r) {
    (void)context;
    int tmpl = -1, conn = -1, req = -1, rc = 0;
    uint64_t begin = now_ms();
    char url[320];
    const char *endpoint = check_endpoint(test);
    unsigned identity = ++next_request_identity;
    memset(r, 0, sizeof(*r));
    r->state = CHECK_FAIL;
    r->tls_fixer_active = service.tls_fixer_enabled == 1;
    *length = 0;
    snprintf(url, sizeof(url), "%s%ccheck=%llu", endpoint, strchr(endpoint, '?') ? '&' : '?',
             (unsigned long long)sceKernelGetSystemTimeWide());
    check_diag("event=request.begin run=%u request=%u service=%s endpoint=%s verify=%d", run_identity,
               identity, test == CHECK_PLAYSTATION ? "PlayStation" : "BrowserLeaks", endpoint, verify);
#define REQUIRE(call)                                                                              \
    do {                                                                                           \
        check_diag("event=api.enter request=%u call=%s", identity, #call);                         \
        uint64_t call_begin = check_diag_time();                                                   \
        rc = (call);                                                                               \
        check_diag("event=api.return request=%u rc=%08X elapsed_us=%llu call=%s", identity,        \
                   (unsigned)rc, (unsigned long long)(check_diag_time() - call_begin), #call);     \
        if (rc < 0)                                                                                \
            goto done;                                                                             \
    } while (0)
    if (stopped()) {
        rc = (int)0x80431080;
        goto done;
    }
    if (!verify && test >= 4) {
        rc = -1;
        snprintf(r->message, sizeof(r->message), "Unverified request refused for this endpoint");
        goto done;
    }
    /* sceHttps policy is global to this process. Only this worker sends HTTP.
     * Reset it before every fresh attempt, and restore it on every retry exit. */
    REQUIRE(sceHttpsEnableOption(VERIFY_FLAGS));
    if (!verify) {
        REQUIRE(sceHttpsDisableOption(VERIFY_FLAGS));
        r->verification_disabled = 1;
    }
    REQUIRE(tmpl = sceHttpCreateTemplate("Vita-TLS-Check/1.2", SCE_HTTP_VERSION_1_1, 0));
    REQUIRE(sceHttpSetResolveTimeOut(tmpl, 3000000));
    REQUIRE(sceHttpSetResolveRetry(tmpl, 1));
    REQUIRE(sceHttpSetConnectTimeOut(tmpl, 5000000));
    REQUIRE(sceHttpSetSendTimeOut(tmpl, 5000000));
    REQUIRE(sceHttpSetRecvTimeOut(tmpl, 5000000));
    REQUIRE(sceHttpSetAutoRedirect(tmpl, SCE_HTTP_DISABLE));
    REQUIRE(sceHttpSetCookieEnabled(tmpl, SCE_HTTP_DISABLE));
    REQUIRE(sceHttpSetResponseHeaderMaxSize(tmpl, 16384));
    REQUIRE(conn = sceHttpCreateConnectionWithURL(tmpl, url, SCE_HTTP_DISABLE));
    REQUIRE(req = sceHttpCreateRequestWithURL(conn, SCE_HTTP_METHOD_GET, url, 0));
    REQUIRE(sceHttpAddRequestHeader(req, "Accept-Encoding", "identity", SCE_HTTP_HEADER_OVERWRITE));
    REQUIRE(sceHttpAddRequestHeader(req, "Cache-Control", "no-cache", SCE_HTTP_HEADER_OVERWRITE));
    lock();
    active_request = req;
    request_identity = identity;
    request_begin = now_ms();
    abort_sent = 0;
    int stop = cancelled;
    unlock();
    if (stop) {
        rc = (int)0x80431080;
        goto done;
    }
    check_diag_sync();
    REQUIRE(sceHttpSendRequest(req, NULL, 0));
    REQUIRE(sceHttpGetStatusCode(req, &r->http_code));
    if (test == CHECK_PLAYSTATION) {
        /* This root URL is not a public Store operation. Any final HTTP response,
         * including 403/404/503, proves verified HTTPS reachability; no sign-in
         * or successful commerce operation is implied. Do not read its body. */
        if (r->http_code >= 200 && r->http_code <= 599) {
            r->state = CHECK_PASS;
            snprintf(r->message, sizeof(r->message), "Connected (HTTP %d)", r->http_code);
        } else {
            rc = -1;
            snprintf(r->message, sizeof(r->message), "Unexpected HTTP status %d", r->http_code);
        }
        goto done;
    }
    while (*length < CHECK_BODY_MAX) {
        if (stopped()) {
            rc = (int)0x80431080;
            goto done;
        }
        if (now_ms() - begin > 20000) {
            rc = (int)0x80431068;
            goto done;
        }
        check_diag("event=api.enter request=%u call=sceHttpReadData offset=%u capacity=%u",
                   identity, (unsigned)*length, (unsigned)(CHECK_BODY_MAX - *length));
        uint64_t read_begin = check_diag_time();
        int n = sceHttpReadData(req, body + *length, (unsigned)(CHECK_BODY_MAX - *length));
        check_diag("event=api.return request=%u call=sceHttpReadData rc=%08X "
                   "elapsed_us=%llu",
                   identity, (unsigned)n, (unsigned long long)(check_diag_time() - read_begin));
        if (n < 0) {
            rc = n;
            goto done;
        }
        if (!n)
            break;
        *length += (unsigned)n;
    }
    if (*length == CHECK_BODY_MAX) {
        snprintf(r->message, sizeof(r->message), "Response exceeds 96 KiB");
        rc = -1;
        goto done;
    }
    body[*length] = 0;
    if (r->http_code != 200) {
        snprintf(r->message, sizeof(r->message), "HTTP %d (no redirect followed)", r->http_code);
        rc = -1;
        goto done;
    }
    r->state = CHECK_PASS;
done:
    r->error = rc;
    r->elapsed_ms = (unsigned)(now_ms() - begin);
    if (req >= 0) {
        if (rc < 0) {
            int ssl_result = sceHttpsGetSslError(req, &r->ssl_error, &r->ssl_detail);
            check_diag("event=api.return request=%u call=sceHttpsGetSslError rc=%08X "
                       "ssl=%08X detail=%08X",
                       identity, (unsigned)ssl_result, (unsigned)r->ssl_error, r->ssl_detail);
        }
        lock();
        active_request = -1;
        int del = sceHttpDeleteRequest(req);
        check_diag("event=cleanup request=%u call=sceHttpDeleteRequest handle=%08X "
                   "rc=%08X",
                   identity, (unsigned)req, (unsigned)del);
        unlock();
        if (del < 0 && rc >= 0) {
            rc = del;
            r->error = del;
            r->state = CHECK_FAIL;
        }
    }
    if (conn >= 0) {
        int del = sceHttpDeleteConnection(conn);
        check_diag("event=cleanup request=%u call=sceHttpDeleteConnection "
                   "handle=%08X rc=%08X",
                   identity, (unsigned)conn, (unsigned)del);
        if (del < 0 && rc >= 0) {
            rc = del;
            r->error = del;
            r->state = CHECK_FAIL;
        }
    }
    if (tmpl >= 0) {
        int del = sceHttpDeleteTemplate(tmpl);
        check_diag("event=cleanup request=%u call=sceHttpDeleteTemplate "
                   "handle=%08X rc=%08X",
                   identity, (unsigned)tmpl, (unsigned)del);
        if (del < 0 && rc >= 0) {
            rc = del;
            r->error = del;
            r->state = CHECK_FAIL;
        }
    }
    if (!verify) {
        r->restore_error = sceHttpsEnableOption(VERIFY_FLAGS);
        check_diag("event=verification.restore request=%u rc=%08X", identity,
                   (unsigned)r->restore_error);
        if (r->restore_error < 0) {
            rc = r->error = r->restore_error;
            r->state = CHECK_FAIL;
            snprintf(r->message, sizeof(r->message), "Could not restore certificate checks");
        }
    }
    if (rc < 0 && !r->message[0])
        snprintf(r->message, sizeof(r->message), "%s",
                 check_error_name(rc, r->ssl_error, r->ssl_detail));
    check_diag("event=request.end run=%u request=%u rc=%08X http=%d ssl=%08X "
               "detail=%08X "
               "body_bytes=%u elapsed_ms=%u",
               run_identity, identity, (unsigned)rc, r->http_code, (unsigned)r->ssl_error,
               r->ssl_detail, (unsigned)*length, r->elapsed_ms);
    check_diag_sync();
    return rc;
#undef REQUIRE
}
static int detect_tls_fixer(void) {
    SceUID ids[128];
    SceSize count = sizeof(ids) / sizeof(ids[0]);
    int rc = sceKernelGetModuleList(0xff, ids, &count);
    if (rc >= 0) {
        for (unsigned i = 0; i < count && i < 128; ++i) {
            SceKernelModuleInfo info = {0};
            info.size = sizeof(info);
            if (sceKernelGetModuleInfo(ids[i], &info) == 0 &&
                check_provider_module_active(info.module_name, info.state)) {
                check_diag("event=provider.detect enabled=1 uid=%08X state=%u", (unsigned)ids[i],
                           (unsigned)info.state);
                return 1;
            }
        }
    }
    check_diag("event=provider.detect enabled=0 query_rc=%08X", (unsigned)rc);
    return 0;
}
static void save_report(const CheckService *s) {
    char path[160];
    snprintf(path, sizeof(path), "ux0:/data/vita-tls-check/%s-%08X-%llu.txt",
             "browserleaks", (unsigned)sceKernelGetProcessId(),
             (unsigned long long)sceKernelGetSystemTimeWide());
    (void)sceIoMkdir("ux0:/data/vita-tls-check", 0777);
    FILE *f = fopen(path, "w");
    if (!f) {
        lock();
        snprintf(notice, sizeof(notice), "Could not save report; results remain on screen.");
        unlock();
        return;
    }
    fprintf(f,
            "Vita TLS Check 1.2\nAPI=sceHttp\nservice=%s\nCertificate "
            "verification=enabled for primary requests\nConnection "
            "reuse=disabled\nRedirects=disabled\nProtocol-only diagnostic retries may disable "
            "certificate checks; both attempts are recorded.\n",
            "BrowserLeaks + PlayStation");
    fprintf(f, "tls_fix=%s (started provider in this process)\n",
            s->tls_fixer_enabled < 0 ? "checking" : s->tls_fixer_enabled ? "enabled" : "not enabled");
    for (unsigned i = 0; i < CHECK_TEST_COUNT; ++i) {
        const CheckResult *r = i == CHECK_REPORT ? &s->connection
                               : i == CHECK_PLAYSTATION ? &s->playstation : &s->protocols[i];
        fprintf(f,
                "\nURL=%s\nstate=%d\nHTTP=%d\nerror=0x%08X\nssl_error=0x%08X\nssl_"
                "detail=0x%"
                "08X\nelapsed_ms=%u\nresult=%s\n",
                check_endpoint(i), r->state,
                r->http_code, (unsigned)r->error, (unsigned)r->ssl_error, r->ssl_detail,
                r->elapsed_ms, r->message);
        fprintf(f, "protocol_confirmed=%d\nverification_restore_error=0x%08X\n",
                r->protocol_confirmed, (unsigned)r->restore_error);
        if (i < 4) {
            char detail[128];
            check_protocol_detail(i, r, detail, sizeof(detail));
            fprintf(f, "classification=%s\ndetail=%s\n",
                    check_protocol_display(i, r).label, detail);
            fprintf(f, "expected_tls_fixer_policy_block=%d\n",
                    check_expected_legacy_block(i, r));
        }
        if (r->retry.attempted)
            fprintf(f, "retry_verification=%s\nretry_protocol_confirmed=%d\n"
                    "retry_HTTP=%d\nretry_error=0x%08X\nretry_ssl_error=0x%08X\n"
                    "retry_ssl_detail=0x%08X\nretry_elapsed_ms=%u\n"
                    "retry_restore_error=0x%08X\n", r->retry.verification_disabled ? "disabled" : "unavailable",
                    r->retry.protocol_confirmed,
                    r->retry.http_code, (unsigned)r->retry.error, (unsigned)r->retry.ssl_error,
                    r->retry.ssl_detail, r->retry.elapsed_ms, (unsigned)r->retry.restore_error);
    }
    const CheckHandshake *h = &s->handshake;
    fprintf(f,
            "\nSelected protocol=%04X %s\nSelected cipher=%04X %s\nKey exchange=%04X "
            "%s\nSignature=%04X %s\nALPN offered=%s\nJA3=%s\nJA4=%s\n",
            h->version.id, h->version.name, h->cipher.id, h->cipher.name, h->group.id,
            h->group.name, h->signature.id, h->signature.name, h->alpn, h->ja3, h->ja4);
    const CheckNamed *lists[] = {h->ciphers, h->groups, h->extensions};
    const unsigned counts[] = {h->cipher_count, h->group_count, h->extension_count};
    const char *labels[] = {"Offered ciphers (not individually negotiated)", "Offered groups",
                            "Offered extensions"};
    for (unsigned l = 0; l < 3; ++l) {
        fprintf(f, "\n%s\n", labels[l]);
        for (unsigned n = 0; n < counts[l]; ++n)
            fprintf(f, "%04X %s\n", lists[l][n].id, lists[l][n].name);
    }
    int failed = ferror(f);
    if (fclose(f))
        failed = 1;
    lock();
    snprintf(service.report, sizeof(service.report), "%s", path);
    snprintf(notice, sizeof(notice), "%s",
             failed ? "Report write failed; results remain on screen."
                    : "Report saved: ux0:data/vita-tls-check/  (one file per run)");
    unlock();
}
static int run_checks(SceSize argc, void *argv) {
    (void)argc;
    (void)argv;
    check_diag("event=run.begin run=%u service=%s", run_identity, "BrowserLeaks+PlayStation");
    check_diag_modules("worker.before-requests");
    char *body = malloc(CHECK_BODY_MAX + 1);
    CheckHandshake *h = calloc(1, sizeof(*h));
    if (!body || !h) {
        check_diag("event=run.error run=%u reason=allocation_failed", run_identity);
        lock();
        snprintf(notice, sizeof(notice), "Out of memory");
        busy = 0;
        unlock();
        free(body);
        free(h);
        return 0;
    }
    /* Every check is independent. The optional report is last, so its request
     * and parser cannot gate the protocol tiles or PlayStation reachability. */
    static const unsigned order[] = {3, 2, 1, 0, CHECK_PLAYSTATION, CHECK_REPORT};
    int policy_failed = 0;
    for (unsigned step = 0; step < sizeof(order) / sizeof(order[0]); ++step) {
        unsigned test = order[step];
        CheckResult r = {0};
        if (stopped() || policy_failed) {
            r.state = CHECK_INFO;
            snprintf(r.message, sizeof(r.message), "%s", policy_failed
                     ? "Not tested: certificate policy error" : "Cancelled / not tested");
            publish((unsigned)test, &r);
            continue;
        }
        r.state = CHECK_RUNNING;
        publish((unsigned)test, &r);
        size_t n = 0;
        int fetched;
        if (test < 4) {
            check_run_protocol(test, fetch, NULL, body, &n, &r);
            fetched = r.error;
        } else
            fetched = fetch(NULL, test, 1, body, &n, &r);
        if (fetched < 0 && stopped()) {
            r.state = CHECK_INFO;
            snprintf(r.message, sizeof(r.message), "Cancelled / not tested");
        } else if (fetched == 0) {
            if (test == CHECK_REPORT) {
                int ok = check_parse_browserleaks(body, n, h);
                if (ok) {
                    r.state = CHECK_FAIL;
                    r.error = -1;
                    snprintf(r.message, sizeof(r.message), "Unexpected report format (HTTP 200)");
                    memset(h, 0, sizeof(*h));
                } else {
                    snprintf(r.message, sizeof(r.message), "Server report received");
                    lock();
                    service.handshake = *h;
                    unlock();
                }
            } else if (test == CHECK_PLAYSTATION) {
                /* fetch already confirmed the verified HTTPS response. */
            }
        }
        policy_failed = r.restore_error < 0;
        publish((unsigned)test, &r);
    }
    free(body);
    free(h);
    /* No UI read of the report path races this snapshot. */
    CheckService *snapshot = malloc(sizeof(*snapshot));
    if (snapshot) {
        lock();
        *snapshot = service;
        unlock();
        save_report(snapshot);
        free(snapshot);
    }
    lock();
    service.complete = 1;
    busy = 0;
    unlock();
    check_diag_modules("worker.after-requests");
    check_diag("event=run.end run=%u service=%s", run_identity, "BrowserLeaks+PlayStation");
    check_diag_sync();
    return 0;
}
static void start_checks(void) {
    if (worker >= 0) {
        sceKernelWaitThreadEnd(worker, NULL, NULL);
        sceKernelDeleteThread(worker);
        worker = -1;
    }
    lock();
    int enabled = service.tls_fixer_enabled;
    memset(&service, 0, sizeof(service));
    service.tls_fixer_enabled = enabled;
    service.started = 1;
    ++run_identity;
    busy = 1;
    cancelled = 0;
    notice[0] = 0;
    unlock();
    worker =
        sceKernelCreateThread("sceHttp TLS checks", run_checks, 0x10000100, 256 * 1024, 0, 0, NULL);
    int rc = worker < 0 ? worker : sceKernelStartThread(worker, 0, NULL);
    if (rc < 0) {
        lock();
        busy = 0;
        snprintf(notice, sizeof(notice), "Could not start network worker: %08X", (unsigned)rc);
        unlock();
    }
}

int main(void) {
    check_diag_init();
    (void)sceIoRemove("ux0:/data/vita-tls-check/startup.txt");
    startup_note("main.enter", 0);
    int exit_code = 1, net_ready = 0, ctl_ready = 0, ssl_ready = 0, http_ready = 0;
    int modules[2] = {0};
    /* Ask Sysmodule for the complete public HTTPS dependency group. */
    const int module_ids[2] = {SCE_SYSMODULE_NET, SCE_SYSMODULE_HTTPS};
    void *net_memory = NULL, *pixels = NULL;
    uint32_t *canvas = NULL;
    int font_ready = 0;
    SceUID display = -1;
    int display_active = 0;
    guard = sceKernelCreateMutex("TLS check state", 0, 0, NULL);
    startup_note("state.mutex", guard);
    if (guard < 0) {
        check_diag_close();
        return 1;
    }
    SceKernelAllocMemBlockOpt opt = {0};
    opt.size = sizeof(opt);
    opt.attr = 4;
    opt.alignment = 256 * 1024;
    display = sceKernelAllocMemBlock("TLS check screen", SCE_KERNEL_MEMBLOCK_TYPE_USER_CDRAM_RW,
                                     2 * 1024 * 1024, &opt);
    startup_note("display.allocate", display);
    if (display < 0 || sceKernelGetMemBlockBase(display, &pixels) < 0)
        goto cleanup;
    canvas = malloc(CHECK_WIDTH * CHECK_HEIGHT * sizeof(*canvas));
    if (!canvas)
        goto cleanup;
    int font_result = check_font_init();
    startup_note("font.init", font_result);
    if (font_result < 0)
        goto cleanup;
    font_ready = 1;
    check_draw(canvas, &service, 0, 0, 0, "Initializing Sony network modules...");
    memcpy(pixels, canvas, CHECK_WIDTH * CHECK_HEIGHT * sizeof(*canvas));
    SceDisplayFrameBuf frame = {0};
    frame.size = sizeof(frame);
    frame.base = pixels;
    frame.pitch = 960;
    frame.pixelformat = SCE_DISPLAY_PIXELFORMAT_A8B8G8R8;
    frame.width = 960;
    frame.height = 544;
    int display_result = sceDisplaySetFrameBuf(&frame, SCE_DISPLAY_SETBUF_NEXTFRAME);
    startup_note("display.present", display_result);
    if (display_result < 0)
        goto cleanup;
    display_active = 1;
    sceDisplayWaitSetFrameBuf();
    int rc = 0;
    check_diag_modules("main.before-network-load");
    for (int i = 0; i < 2; ++i) {
        check_diag("event=api.enter call=sceSysmoduleLoadModule module=%04X", module_ids[i]);
        check_diag_sync();
        uint64_t module_begin = check_diag_time();
        rc = sceSysmoduleLoadModule(module_ids[i]);
        check_diag("event=api.return call=sceSysmoduleLoadModule module=%04X rc=%08X "
                   "elapsed_us=%llu",
                   module_ids[i], (unsigned)rc,
                   (unsigned long long)(check_diag_time() - module_begin));
        if (rc < 0)
            goto init_failed;
        modules[i] = 1;
    }
    check_diag_modules("main.after-network-load");
    service.tls_fixer_enabled = detect_tls_fixer();
    net_memory = malloc(1024 * 1024);
    if (!net_memory) {
        rc = -1;
        goto init_failed;
    }
    SceNetInitParam net = {net_memory, 1024 * 1024, 0};
    check_diag("event=api.enter call=sceNetInit pool_bytes=1048576");
    rc = sceNetInit(&net);
    check_diag("event=api.return call=sceNetInit rc=%08X pool_bytes=%u", (unsigned)rc,
               (unsigned)net.size);
    if (rc < 0)
        goto init_failed;
    net_ready = 1;
    check_diag("event=api.enter call=sceNetCtlInit");
    rc = sceNetCtlInit();
    check_diag("event=api.return call=sceNetCtlInit rc=%08X", (unsigned)rc);
    if (rc < 0)
        goto init_failed;
    ctl_ready = 1;
    uint64_t deadline = now_ms() + 10000;
    int last_net_state = -1;
    for (;;) {
        int state = 0;
        rc = sceNetCtlInetGetState(&state);
        if (state != last_net_state || rc < 0) {
            check_diag("event=network.state rc=%08X state=%d", (unsigned)rc, state);
            last_net_state = state;
        }
        if (rc < 0)
            goto init_failed;
        if (state == SCE_NETCTL_STATE_CONNECTED)
            break;
        if (now_ms() > deadline) {
            rc = (int)0x80431068;
            goto init_failed;
        }
        sceKernelDelayThread(50000);
    }
    check_diag("event=api.enter call=sceSslInit pool_bytes=1048576");
    check_diag_sync();
    rc = sceSslInit(1024 * 1024);
    check_diag("event=api.return call=sceSslInit rc=%08X pool_bytes=1048576", (unsigned)rc);
    if (rc < 0)
        goto init_failed;
    ssl_ready = 1;
    check_diag("event=api.enter call=sceHttpInit pool_bytes=1048576");
    check_diag_sync();
    rc = sceHttpInit(1024 * 1024);
    check_diag("event=api.return call=sceHttpInit rc=%08X pool_bytes=1048576", (unsigned)rc);
    if (rc < 0)
        goto init_failed;
    http_ready = 1;
    check_diag("event=api.enter call=sceHttpsEnableOption verification=enabled");
    rc = sceHttpsEnableOption(VERIFY_FLAGS);
    check_diag("event=api.return call=sceHttpsEnableOption rc=%08X verification=enabled",
               (unsigned)rc);
    check_diag_modules("main.after-http-init");
    if (rc < 0)
        goto init_failed;
    exit_code = 0;
init_failed:
    startup_note("network.init", rc);
    if (rc < 0)
        snprintf(notice, sizeof(notice), "Sony network initialization failed: 0x%08X  /  O exit",
                 (unsigned)rc);
    startup_note("controller.analog", sceCtrlSetSamplingMode(SCE_CTRL_MODE_ANALOG));
    int page = 0, exiting = 0;
    check_diag("event=input.page page=0");
    CheckScrollRepeat repeat = {0};
    unsigned scroll = 0, previous = ~0u;
    int last_page = -1, last_busy = -1;
    unsigned last_scroll = ~0u;
    char last_notice[120] = "";
    if (!exit_code)
        start_checks();
    for (;;) {
        /* Drain queued samples so a short button press is not lost during font
         * rasterization. */
        SceCtrlData pads[64];
        int pad_count = sceCtrlReadBufferPositive(0, pads, 64);
        unsigned pressed = 0, page_presses = 0;
        int scroll_steps = 0;
        uint64_t sample_ms = now_ms();
        for (int i = 0; i < pad_count && i < 64; ++i) {
            unsigned edges = pads[i].buttons & ~previous;
            previous = pads[i].buttons;
            pressed |= edges;
            int direction = check_scroll_direction(
                pads[i].buttons & SCE_CTRL_UP, pads[i].buttons & SCE_CTRL_DOWN,
                pads[i].ly, pads[i].ry);
            scroll_steps += check_scroll_repeat(&repeat, direction, sample_ms);
            page_presses += (edges & SCE_CTRL_SQUARE) != 0;
        }
        lock();
        int is_busy = busy;
        uint64_t started = request_begin;
        int request = active_request;
        unlock();
        if (is_busy && request >= 0 && now_ms() - started > 20000)
            abort_current(0);
        if (pressed & SCE_CTRL_CIRCLE) {
            exiting = 1;
            if (is_busy)
                abort_current(1);
        }
        if (exiting && !is_busy)
            break;
        if (pressed & SCE_CTRL_TRIANGLE)
            abort_current(1);
        if (page_presses) {
            page = (int)((page + page_presses) % 3);
            scroll = 0;
            check_diag("event=input.page page=%d", page);
        }
        lock();
        unsigned count = service.handshake.cipher_count;
        unlock();
        unsigned old_scroll = scroll;
        scroll = check_scroll_move(scroll, page == 0 ? scroll_steps : 0,
                                   count, CHECK_VISIBLE_CIPHERS);
        if (old_scroll != scroll)
            check_diag("event=input.scroll before=%u after=%u steps=%d", old_scroll, scroll,
                       scroll_steps);
        if (!is_busy && !exiting && !exit_code && (pressed & SCE_CTRL_CROSS)) {
            start_checks();
            is_busy = 1;
        }
        char current_notice[120];
        lock();
        view = service;
        snprintf(current_notice, sizeof(current_notice), "%s", notice);
        unlock();
        if (last_page != page || last_scroll != scroll ||
            last_busy != is_busy || strcmp(last_notice, current_notice) != 0 ||
            memcmp(&last_view, &view, sizeof(view)) != 0) {
            /* One scanout buffer: never clear or draw text into the visible image.
             * Render a complete CPU canvas, then copy at vblank only when state
             * changes. */
            check_draw(canvas, &view, page, scroll, is_busy, current_notice);
            sceDisplayWaitVblankStart();
            memcpy(pixels, canvas, CHECK_WIDTH * CHECK_HEIGHT * sizeof(*canvas));
            last_view = view;
            last_page = page;
            last_scroll = scroll;
            last_busy = is_busy;
            snprintf(last_notice, sizeof(last_notice), "%s", current_notice);
        }
        sceDisplayWaitVblankStart();
        sceKernelDelayThread(30000);
    }
    if (worker >= 0) {
        sceKernelWaitThreadEnd(worker, NULL, NULL);
        sceKernelDeleteThread(worker);
    }
cleanup:
    if (http_ready)
        sceHttpTerm();
    if (ssl_ready)
        sceSslTerm();
    if (ctl_ready)
        sceNetCtlTerm();
    if (net_ready)
        sceNetTerm();
    free(net_memory);
    free(canvas);
    if (font_ready)
        check_font_close();
    for (int i = 1; i >= 0; --i)
        if (modules[i])
            sceSysmoduleUnloadModule(module_ids[i]);
    if (display_active) {
        if (sceDisplaySetFrameBuf(NULL, SCE_DISPLAY_SETBUF_NEXTFRAME) >= 0 &&
            sceDisplayWaitSetFrameBuf() >= 0) {
            sceKernelFreeMemBlock(display);
            display = -1;
        }
    } else if (display >= 0)
        sceKernelFreeMemBlock(display);
    sceKernelDeleteMutex(guard);
    check_diag_close();
    return exit_code;
}
