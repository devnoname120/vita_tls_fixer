#include "config.h"
#include "../kernel/self_disarm.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char data[TLS_FIXER_SELF_DISARM_MAX_CONFIG + 1];
    size_t size;
    unsigned operations, fail_at, patches, appends;
    int partial_append, silent_patch, silent_section;
} File;
static int failure(File *f) { return ++f->operations == f->fail_at; }
static int read_file(void *context, char **data, size_t *size) {
    File *f = context;
    if (failure(f)) return -1;
    *data = malloc(f->size + 1); assert(*data); memcpy(*data, f->data, f->size);
    (*data)[f->size] = 0; *size = f->size; return 0;
}
static int append(void *context, const char *data, size_t size) {
    File *f = context; ++f->appends;
    if (failure(f)) return -1;
    size_t n = f->partial_append >= 0 && (size_t)f->partial_append < size ? (size_t)f->partial_append : size;
    assert(f->size + n <= TLS_FIXER_SELF_DISARM_MAX_CONFIG);
    memcpy(f->data + f->size, data, n); f->size += n; f->data[f->size] = 0;
    return n == size ? 0 : -1;
}
static int patch(void *context, size_t at, char expected, char value) {
    File *f = context; ++f->patches;
    if (failure(f)) return -1;
    assert(at < f->size && f->data[at] == expected);
    if (!f->silent_patch && !(f->silent_section && value == '*')) f->data[at] = value;
    return 0;
}
static int sync_file(void *context) { return failure(context) ? -1 : 0; }
static TlsFixerConfigIo io(File *f) { TlsFixerConfigIo out = {read_file, append, patch, sync_file, f}; return out; }
static void reset(File *f, const char *text) {
    memset(f, 0, sizeof(*f)); f->size = strlen(text); memcpy(f->data, text, f->size + 1); f->partial_append = -1;
}
static int active_target(const File *f) {
    /* Test fixture parser: only complete non-comment paths in KERNEL count. */
    int kernel = 0, count = 0;
    for (size_t at = 0; at < f->size;) {
        size_t begin = at; while (at < f->size && f->data[at] != '\n' && f->data[at] != '\r') ++at;
        size_t end = at; if (at < f->size) ++at;
        while (begin < end && (f->data[begin] == ' ' || f->data[begin] == '\t')) ++begin;
        if (begin == end || f->data[begin] == '#') continue;
        if (f->data[begin] == '*') kernel = end - begin == 7 && !memcmp(f->data + begin, "*KERNEL", 7);
        else if (kernel) {
            assert(end - begin != strlen("ur0:tai/tls_fixer.skprx") || memcmp(f->data + begin, "ur0:tai/tls_fixer.skprx", end - begin));
            if (end - begin == strlen(TLS_FIXER_REMOVABLE_KERNEL_PATH) &&
                !memcmp(f->data + begin, TLS_FIXER_REMOVABLE_KERNEL_PATH, end - begin)) ++count;
        }
    }
    return count;
}
int main(void) {
    static const char original[] = "*KERNEL\nur0:tai/storage.skprx\n*ALL\nur0:tai/user.suprx";
    File *f = malloc(sizeof(*f)); assert(f); reset(f, original); TlsFixerConfigIo o = io(f);
    assert(tls_fixer_config_enable(&o, TLS_FIXER_REMOVABLE_KERNEL_PATH) == 0);
    assert(f->size > strlen(original) && !memcmp(f->data, original, strlen(original)));
    assert(active_target(f) == 1 && f->appends == 1);
    unsigned operations = f->operations;
    assert(tls_fixer_config_disable(&o) == 0 && active_target(f) == 0);
    size_t size = f->size;
    assert(tls_fixer_config_enable(&o, TLS_FIXER_REMOVABLE_KERNEL_PATH) == 0 && f->size == size);
    assert(f->appends == 1 && active_target(f) == 1);

    const char *comments[] = {"*KERNEL\n#x0:/data/tls_fixer-one-shot/tls_fixer.skprx\n",
        "*KERNEL\n# ux0:/data/tls_fixer-one-shot/tls_fixer.skprx\n",
        "*KERNEL\n#ux0:/data/tls_fixer-one-shot/tls_fixer.skprx\n"};
    for (unsigned i = 0; i < sizeof(comments) / sizeof(comments[0]); ++i) {
        reset(f, comments[i]); size = f->size;
        assert(tls_fixer_config_enable(&o, TLS_FIXER_REMOVABLE_KERNEL_PATH) == 0);
        assert(f->size == size && f->appends == 0 && active_target(f) == 1);
    }
    reset(f, "*KERNEL\nur0:tai/tls_fixer.skprx\nux0:/data/tls_fixer-one-shot/tls_fixer.skprx\n");
    assert(tls_fixer_config_enable(&o, TLS_FIXER_REMOVABLE_KERNEL_PATH) == 0 && active_target(f) == 1);
    reset(f, "*KERNEL\nux0:/other/tls_fixer.skprx\n");
    assert(tls_fixer_config_enable(&o, TLS_FIXER_REMOVABLE_KERNEL_PATH) < 0 && f->patches == 0 && f->appends == 0);
    reset(f, original); f->data[3] = 0;
    assert(tls_fixer_config_enable(&o, TLS_FIXER_REMOVABLE_KERNEL_PATH) < 0 && f->patches == 0);
    for (unsigned failure = 1; failure <= operations; ++failure) {
        reset(f, original); f->fail_at = failure;
        assert(tls_fixer_config_enable(&o, TLS_FIXER_REMOVABLE_KERNEL_PATH) < 0);
        assert(f->size >= strlen(original) && !memcmp(f->data, original, strlen(original)));
        assert(active_target(f) <= 1);
    }
    for (int partial = 0; partial < 75; ++partial) {
        reset(f, original); f->partial_append = partial;
        int rc = tls_fixer_config_enable(&o, TLS_FIXER_REMOVABLE_KERNEL_PATH);
        if (rc < 0) assert(active_target(f) == 0);
        assert(!memcmp(f->data, original, strlen(original)));
    }
    reset(f, comments[0]); f->silent_patch = 1;
    assert(tls_fixer_config_enable(&o, TLS_FIXER_REMOVABLE_KERNEL_PATH) < 0);
    reset(f, original); f->silent_section = 1;
    assert(tls_fixer_config_enable(&o, TLS_FIXER_REMOVABLE_KERNEL_PATH) < 0 && active_target(f) == 0);
    reset(f, "*KERNEL\nur0:tai/tls_fixer.skprx\n"); f->silent_patch = 1;
    assert(tls_fixer_config_disable(&o) < 0);
    /* The persistent release uses the same checked edits for its normal UR0
     * entry, including configs without the old exact marker/newline block. */
    static const char normal[] = "ur0:tai/tls_fixer.skprx";
    const char *release_configs[] = {original,
        "*KERNEL\nur0:tai/tls_fixer.skprx\n",
        "*KERNEL\nur0:/tai/tls_fixer.skprx\n",
        "*KERNEL\n#r0:tai/tls_fixer.skprx\n",
        "*KERNEL\n#r0:/tai/tls_fixer.skprx\n",
        "*KERNEL\n# ur0:/tai/tls_fixer.skprx\n"};
    for (unsigned i = 0; i < sizeof(release_configs) / sizeof(release_configs[0]); ++i) {
        reset(f, release_configs[i]); size = f->size;
        assert(tls_fixer_config_enabled(&o, normal) == (i == 1 || i == 2));
        assert(tls_fixer_config_enable(&o, normal) == 0);
        assert(tls_fixer_config_enabled(&o, normal));
        assert(!tls_fixer_config_enabled(&o, TLS_FIXER_REMOVABLE_KERNEL_PATH));
        if (i) assert(f->size == size && f->appends == 0);
        assert(tls_fixer_config_disable(&o) == 0 && !tls_fixer_config_enabled(&o, normal));
    }
    reset(f, "*KERNEL\nur0:/tai/tls_fixer.skprx\nux0:/data/tls_fixer-one-shot/tls_fixer.skprx\n");
    assert(tls_fixer_config_enable(&o, normal) == 0);
    assert(tls_fixer_config_enabled(&o, normal) && !tls_fixer_config_enabled(&o, TLS_FIXER_REMOVABLE_KERNEL_PATH));
    reset(f, original); f->fail_at = 1;
    assert(!tls_fixer_config_enabled(&o, normal));
    free(f); puts("PASS in-place config edits, commented append, slot reuse and failure boundaries"); return 0;
}
