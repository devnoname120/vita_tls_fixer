/* Controlled-server checks for the embedded module. This app calls Sony APIs
 * only; the test root is loaded into its process, never installed system-wide. */
#include <psp2/net/http.h>
#include <taihen.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef int (*Record)(const char *, ...);
typedef struct Api {
    int (*init)(unsigned int), (*term)(void), (*enable)(unsigned int);
    int (*load)(int, const SceHttpsData **, const SceHttpsData *, const SceHttpsData *);
    int (*unload)(void);
    int (*template)(const char *, int, int), (*delete_template)(int);
    int (*connection)(int, const char *, int), (*delete_connection)(int);
    int (*request)(int, int, const char *, uint64_t), (*delete_request)(int);
    int (*send)(int, const void *, unsigned int), (*read)(int, void *, unsigned int);
    int (*code)(int, int *), (*error)(int, int *, unsigned int *);
    int (*enable_private)(int, unsigned int), (*disable_private)(int, unsigned int);
    int (*enable_public)(int, unsigned int), (*disable_public)(int, unsigned int);
    int (*timeouts[4])(int, unsigned int);
    const uint32_t *(*stats)(void);
} Api;

static uintptr_t resolve(uint32_t library, uint32_t nid) {
    uintptr_t address = 0;
    return taiGetModuleExportFunc("SceLibHttp", library, nid, &address) < 0 ? 0 : address;
}

static int read_url(FILE *file, char url[192]) {
    if (!fgets(url, 192, file)) return -1;
    size_t n = strcspn(url, "\r\n");
    if (!n || n >= 191) return -1;
    url[n] = 0;
    /* These are local test fixtures, not configurable public probes. */
    return strncmp(url, "https://192.168.", 16) == 0 ||
           strncmp(url, "https://10.", 11) == 0 ? 0 : -1;
}

static int request_with_profile(Api *api, Record log, const char *label, const char *url,
                   int connected, int fallback, const char *protocol, int profile) {
    const uint32_t *stats = api->stats();
    uint32_t creates_before = stats[7], fallbacks_before = stats[8];
    int tid = api->template("tls_fixer CA lifecycle check", 2, 0), cid = -1, rid = -1;
    int failed = tid < 0, rc = -1, code = 0, ssl = 0;
    unsigned int detail = 0;
    if (tid >= 0) {
        for (int i = 0; i < 4; ++i) if (api->timeouts[i](tid, 8000000) < 0) failed = 1;
        if (profile == 1) failed |= api->enable_private(tid, 0x40) < 0;
        cid = api->connection(tid, url, 0);
        if (cid >= 0 && profile == 1) failed |= api->disable_private(tid, 0x40) < 0;
        if (cid >= 0 && profile == 2) failed |= api->enable_private(cid, 0x40) < 0;
        if (cid >= 0) rid = api->request(cid, SCE_HTTP_METHOD_GET, url, 0);
        if (rid >= 0 && profile == 2) failed |= api->disable_private(cid, 0x40) < 0;
        if (rid >= 0 && profile == 3) failed |= api->enable_private(rid, 0x40) < 0;
        if (rid >= 0 && profile == 4) {
            failed |= api->disable_public(rid, 0x18) < 0;
            failed |= api->enable_public(rid, 0x18) < 0;
        }
        if (rid >= 0 && profile == 5) failed |= api->enable_private(rid, 0x240) >= 0;
        if (rid >= 0 && profile == 6) {
            failed |= api->enable_private(rid, 0x40) < 0;
            failed |= api->disable_private(rid, 0x40) < 0;
        }
        failed |= cid < 0 || rid < 0;
    }
    char body[256] = {0};
    if (!failed) {
        log("ca.send.enter case=%s\n", label);
        rc = api->send(rid, NULL, 0);
        (void)api->code(rid, &code);
        (void)api->error(rid, &ssl, &detail);
        if (connected) {
            failed |= rc < 0 || code != 200 || ssl != 0 || detail != 0;
            if (!failed) {
                unsigned int used = 0;
                int n = 0;
                while (used < sizeof(body) - 1 && (n = api->read(rid, body + used, sizeof(body) - 1 - used)) > 0)
                    used += (unsigned int)n;
                failed |= n < 0 || strstr(body, "tls_fixer custom CA accepted") == NULL ||
                    strstr(body, protocol) == NULL;
            }
        } else {
            failed |= rc >= 0 || (ssl == 0 && detail == 0);
        }
    }
    if (rid >= 0) failed |= api->delete_request(rid) < 0;
    if (cid >= 0) failed |= api->delete_connection(cid) < 0;
    if (tid >= 0) failed |= api->delete_template(tid) < 0;
    stats = api->stats();
    uint32_t creates = stats[7] - creates_before, fallbacks = stats[8] - fallbacks_before;
    failed |= fallback ? fallbacks != 1 || creates != 0 : fallbacks != 0 || creates != 1;
    log("ca.result case=%s rc=%08X http=%d ssl=%08X detail=%08X creates=%u fallbacks=%u passed=%d\n",
        label, rc, code, ssl, detail, creates, fallbacks, !failed);
    return failed ? -1 : 0;
}

static int request(Api *api, Record log, const char *label, const char *url, int connected, int fallback,
                   const char *protocol) {
    return request_with_profile(api, log, label, url, connected, fallback, protocol, 0);
}

int tls_fixer_embedded_check_custom_ca(Record log) {
    Api api = {0};
#define LOAD(field, nid) do { api.field = (void *)resolve(0xe8f15cde, nid); if (!api.field) return -1; } while (0)
    LOAD(init, 0x214926d9); LOAD(term, 0xc9076666); LOAD(enable, 0x9fbe2869);
    LOAD(load, 0xae8d7c33); LOAD(unload, 0x8577833f);
    LOAD(template, 0x62241dab); LOAD(delete_template, 0xec85ecfb);
    LOAD(connection, 0xc616c200); LOAD(delete_connection, 0xf0f65c15);
    LOAD(request, 0xbd5da1d0); LOAD(delete_request, 0x3d3d29ad);
    LOAD(send, 0x9ca58b99); LOAD(read, 0x7ede3979); LOAD(code, 0x27071691); LOAD(error, 0x2b79bde0);
    LOAD(timeouts[0], 0x8455b5b3); LOAD(timeouts[1], 0x237ca86e);
    LOAD(timeouts[2], 0x8ae3f008); LOAD(timeouts[3], 0x94bf196e);
    LOAD(enable_private, 0x72cb0741); LOAD(disable_private, 0x00659635);
    LOAD(enable_public, 0x1ea3bb9c); LOAD(disable_public, 0x2e77b201);
#undef LOAD
    api.stats = (void *)resolve(0x7f10b001, 0x7f10b002);
    if (!api.stats) return -1;
    unsigned char certificate_data[8192];
    FILE *file = fopen("ux0:/data/tls_fixer-augment/custom-root.pem", "rb");
    if (!file) return -1;
    size_t length = fread(certificate_data, 1, sizeof(certificate_data) - 1, file);
    int bad_file = !feof(file) || ferror(file) || length == 0;
    fclose(file);
    if (bad_file) return -1;
    certificate_data[length] = 0;
    char modern[192], legacy[192];
    file = fopen("ux0:/data/tls_fixer-augment/custom-urls.txt", "r");
    if (!file) return -1;
    bad_file = read_url(file, modern) < 0 || read_url(file, legacy) < 0;
    fclose(file);
    if (bad_file) return -1;
    SceHttpsData ca = {.ptr = (char *)certificate_data, .size = length + 1};
    const SceHttpsData *certificates[] = {&ca};
    int rc = api.init(128 * 1024), failed = 0;
    log("ca.init=%08X\n", rc);
    if (rc < 0) return -1;
    if (api.enable(0x3d) < 0 || request(&api, log, "untrusted", modern, 0, 0, NULL) < 0) { failed = 1; goto done; }
    rc = api.load(1, certificates, NULL, NULL);
    log("ca.load=%08X\n", rc);
    if (rc < 0 || request(&api, log, "trusted", modern, 1, 0, "TLSv1.3") < 0 ||
        request(&api, log, "trusted_rsa", legacy, 1, 0, "TLSv1.2") < 0) { failed = 1; goto done; }
#if TLS_FIXER_AUGMENT_PRIVATE_PROFILE_CHECK
    if (request_with_profile(&api, log, "profile_template_inherited", legacy, 1, 0, "TLSv1.2", 1) < 0 ||
        request_with_profile(&api, log, "profile_connection_inherited", legacy, 1, 0, "TLSv1.2", 2) < 0 ||
        request_with_profile(&api, log, "profile_request", legacy, 1, 0, "TLSv1.2", 3) < 0 ||
        request_with_profile(&api, log, "profile_template_reject_tls13", modern, 0, 0, NULL, 1) < 0 ||
        request_with_profile(&api, log, "profile_connection_reject_tls13", modern, 0, 0, NULL, 2) < 0 ||
        request_with_profile(&api, log, "profile_reject_tls13", modern, 0, 0, NULL, 3) < 0 ||
        request_with_profile(&api, log, "profile_public_preserves_tls13", modern, 1, 0, "TLSv1.3", 4) < 0 ||
        request_with_profile(&api, log, "profile_failed_call_preserves_tls13", modern, 1, 0, "TLSv1.3", 5) < 0 ||
        request_with_profile(&api, log, "profile_disabled_preserves_tls13", modern, 1, 0, "TLSv1.3", 6) < 0 ||
        request(&api, log, "profile_deleted_preserves_tls13", modern, 1, 0, "TLSv1.3") < 0) {
        failed = 1; goto done;
    }
#endif
    rc = api.unload();
    log("ca.unload=%08X\n", rc);
    if (rc < 0 || request(&api, log, "unloaded", modern, 0, 0, NULL) < 0) { failed = 1; goto done; }
    rc = api.load(1, certificates, NULL, NULL);
    if (rc < 0) { failed = 1; goto done; }
    /* Native partial/failed CA loads conservatively select native TLS until
     * unload. Verify that path can still perform a real TLS 1.2 exchange. */
    const unsigned char invalid_der[] = {0x30, 0x01, 0x00};
    SceHttpsData invalid = {.ptr = (void *)invalid_der, .size = sizeof(invalid_der)};
    const SceHttpsData *invalid_certificates[] = {&invalid};
    rc = api.load(1, invalid_certificates, NULL, NULL);
    log("ca.invalid_load=%08X\n", rc);
    /* Sony may defer parsing until use. Preserve and record its return value;
     * our failed mirror still has to select native TLS until the next unload. */
    if (request(&api, log, "native_fallback", legacy, 1, 1, "TLSv1.2") < 0) { failed = 1; goto done; }
    if (api.unload() < 0 || api.load(1, certificates, NULL, NULL) < 0 ||
        request(&api, log, "modern_restored", modern, 1, 0, "TLSv1.3") < 0) failed = 1;
done:
    rc = api.term();
    const uint32_t *stats = api.stats();
    failed |= rc < 0 || stats[2] != 0 || stats[4] != 0 || stats[5] != 0;
    log("ca.end rc=%08X state=%u capacity=%u used=%u passed=%d\n", rc, stats[2], stats[4], stats[5], !failed);
    return failed ? -1 : 0;
}
