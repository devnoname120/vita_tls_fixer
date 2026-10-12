#include <taihen.h>
#include <psp2/libssl.h>
#include <psp2/net/http.h>
#include <psp2/rtc.h>
#include <assert.h>
#include <stddef.h>
#include <string.h>

static struct {
    uint32_t nid;
    struct _tai_hook_user reference;
    int active;
} hooks[10];
int mock_hook_fail_index = -1;
int mock_legacy_certificate_result;

static int legacy_serial(SceSslCert *cert, const char **data, unsigned int *length) {
    (void)cert; (void)data; (void)length;
    return -271;
}
static SceSslCertName *legacy_name(SceSslCert *cert) { (void)cert; return NULL; }
static int legacy_time(SceSslCert *cert, SceRtcTick *tick) { (void)cert; (void)tick; return -271; }
static int legacy_free(SceSslCertName *name) { (void)name; return -271; }
static int legacy_count(SceSslCertName *name) { (void)name; return -271; }
static int legacy_info(SceSslCertName *name, int entry, char *oid, unsigned int oid_size,
                       char *value, unsigned int value_size, unsigned int *length) {
    (void)name; (void)entry; (void)oid; (void)oid_size; (void)value; (void)value_size; (void)length;
    return -271;
}
static int legacy_load(int count, const SceHttpsData **certs, const SceHttpsData *client,
                       const SceHttpsData *key) {
    (void)count; (void)certs; (void)client; (void)key;
    return mock_legacy_certificate_result;
}
static int legacy_unload(void) { return mock_legacy_certificate_result; }

int taiHookFunctionExport(tai_hook_ref_t *reference, const char *module,
                         uint32_t library, uint32_t nid, const void *function) {
    int index;
    void *original = NULL;
    (void)module; (void)library;
    for (index = 0; index < 10 && hooks[index].active; ++index) {}
    assert(index < 10);
    if (index == mock_hook_fail_index) return -990;
    switch (nid) {
        case 0xc73687e4: original = legacy_free; break;
        case 0x412711e5: case 0x9b2f1bc1: original = legacy_name; break;
        case 0x95e14ca6: original = legacy_count; break;
        case 0x2a857867: original = legacy_info; break;
        case 0xf5ed7b68: case 0x70dea174: original = legacy_time; break;
        case 0x901c5c15: original = legacy_serial; break;
        case 0xae8d7c33: original = legacy_load; break;
        case 0x8577833f: original = legacy_unload; break;
        default: assert(0);
    }
    hooks[index].active = 1;
    hooks[index].nid = nid;
    hooks[index].reference = (struct _tai_hook_user){ .func = (void *)function, .old = original };
    *reference = (uintptr_t)&hooks[index].reference;
    return index + 1;
}

int taiHookRelease(int id, tai_hook_ref_t reference) {
    assert(id >= 1 && id <= 10 && hooks[id - 1].active);
    assert(reference == (uintptr_t)&hooks[id - 1].reference);
    hooks[id - 1].active = 0;
    return 0;
}

const void *mock_hook_by_nid(uint32_t nid) {
    for (size_t i = 0; i < 10; ++i) {
        if (hooks[i].active && hooks[i].nid == nid) return hooks[i].reference.func;
    }
    return NULL;
}

unsigned int mock_hooks_active(void) {
    unsigned int active = 0;
    for (size_t i = 0; i < 10; ++i) active += hooks[i].active != 0;
    return active;
}
