#include "conflicts.h"
#include "../kernel/self_disarm.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct World World;
typedef struct {
    World *world;
    char data[4096], durable[4096];
    size_t size;
    int oversized;
} Config;
struct World {
    Config config[2];
    const char *paths[32];
    unsigned paths_count, operations, fail_at, patches, deletions;
    int silent_patch, silent_delete;
};
static int failure(World *w) { return ++w->operations == w->fail_at; }
static int read_config(void *context, char **data, size_t *size) {
    Config *c = context; *data = NULL; *size = 0;
    if (failure(c->world)) return -1;
    *data = malloc(c->size + 1); assert(*data);
    memcpy(*data, c->data, c->size + 1);
    *size = c->oversized ? TLS_FIXER_SELF_DISARM_MAX_CONFIG + 1 : c->size;
    return 0;
}
static int patch_config(void *context, size_t at, char expected, char value) {
    Config *c = context; ++c->world->patches;
    if (failure(c->world)) return -1;
    assert(at < c->size && c->data[at] == expected);
    if (!c->world->silent_patch) c->data[at] = value;
    return 0;
}
static int sync_config(void *context) {
    Config *c = context;
    if (failure(c->world)) return -1;
    memcpy(c->durable, c->data, c->size + 1); return 0;
}
static int has_active(const char *text) {
    for (const char *line = text; *line;) {
        const char *end = strchr(line, '\n'); if (!end) end = line + strlen(line);
        while (line < end && (*line == ' ' || *line == '\t')) ++line;
        if (line < end && *line != '#' && *line != '*') {
            const char *a = strstr(line, "itls."), *b = strstr(line, "vitals.");
            if ((a && a < end) || (b && b < end)) return 1;
        }
        line = *end ? end + 1 : end;
    }
    return 0;
}
static int path_exists(void *context, const char *path) {
    World *w = context;
    if (failure(w)) return -1;
    for (unsigned i = 0; i < w->paths_count; ++i) if (!strcmp(w->paths[i], path)) return 1;
    return 0;
}
static int remove_path(void *context, const char *path, int directory) {
    World *w = context;
    if (failure(w)) return -1;
    /* Independent safety invariant: the stored configs must have no active
     * competing entry when the first plugin or runtime file is deleted. */
    for (unsigned i = 0; i < 2; ++i) assert(!has_active(w->config[i].durable));
    if (w->silent_delete) return 0;
    size_t n = strlen(path);
    for (unsigned i = 0; i < w->paths_count;) {
        if (!strcmp(w->paths[i], path) || (directory && !strncmp(w->paths[i], path, n) && w->paths[i][n] == '/')) {
            w->paths[i] = w->paths[--w->paths_count]; ++w->deletions;
        } else ++i;
    }
    return 0;
}
static int sync_files(void *context) { return failure(context) ? -1 : 0; }
static void config(Config *c, const char *text) {
    c->size = strlen(text); assert(c->size < sizeof(c->data));
    memcpy(c->data, text, c->size + 1); memcpy(c->durable, text, c->size + 1);
}
static void seed(World *w) {
    memset(w, 0, sizeof(*w));
    for (unsigned i = 0; i < 2; ++i) w->config[i].world = w;
    config(&w->config[0], "# keep this comment\r\n*KERNEL\r\nur0:tai/storage.skprx\r\n"
        "ur0:tai/itls.skprx\r\n\tur0:/tai/vitals.skprx # duplicate\r\n"
        "ur0:/tai/vitals.skprx\r\n*ALL\r\nur0:tai/user.suprx\r\n");
    config(&w->config[1], "*KERNEL\numa0:/custom/vitals.skprx\n"
        "# ur0:/custom/itls.suprx\n#x0:/extra/itls.skprx\n"
        "*NPXS10003\nur0:tai/other.suprx");
    static const char *const paths[] = {
        "ur0:tai/itls.skprx", "ur0:/tai/vitals.skprx", "ur0:tai/vitals.skprx",
        "uma0:/custom/vitals.skprx", "ur0:/custom/itls.suprx", "ux0:/extra/itls.skprx",
        "vs0:/data/external/itls", "vs0:/data/external/itls/libhttp.suprx",
        "vs0:/data/external/vitals", "vs0:/data/external/vitals/native/vitals-reauth.suprx",
        "ur0:tai/vitals-native", "ur0:tai/vitals-native/vitals.suprx",
        "ux0:data/vitals", "ux0:data/vitals/redirects.txt",
        "vs0:/data/external/cert/CA_LIST.cer", "vs0:/data/external/cert/CA_LIST.cer_old",
        "ur0:tai/storage.skprx", "ur0:tai/tls_fixer.skprx", "ux0:data/tls_fixer/redirects.txt",
        "vs0:/data/external/tls_fixer/native/libhttp.suprx",
        "vs0:/sys/external/libhttp.suprx",
    };
    w->paths_count = sizeof(paths) / sizeof(paths[0]); memcpy(w->paths, paths, sizeof(paths));
}
static void ops(World *w, TlsFixerConfigIo configs[2], TlsFixerConflictFiles *files) {
    for (unsigned i = 0; i < 2; ++i)
        configs[i] = (TlsFixerConfigIo){read_config, NULL, patch_config, sync_config, &w->config[i]};
    *files = (TlsFixerConflictFiles){path_exists, remove_path, sync_files, w};
}
int main(void) {
    World w; TlsFixerConfigIo configs[2]; TlsFixerConflictFiles files;
    seed(&w); ops(&w, configs, &files);
    assert(tls_fixer_conflicts_present(configs, 2, &files) == 1 && !w.patches && !w.deletions);
    w.operations = 0;
    assert(tls_fixer_remove_conflicts(configs, 2, &files) == 0);
    unsigned operations = w.operations;
    assert(w.deletions == 14 && w.paths_count == 7);
    assert(strstr(w.config[0].data, "# keep this comment\r\n*KERNEL\r\nur0:tai/storage.skprx\r\n"));
    assert(strstr(w.config[0].data, "*ALL\r\nur0:tai/user.suprx\r\n"));
    assert(strstr(w.config[1].data, "*NPXS10003\nur0:tai/other.suprx"));
    for (unsigned i = 0; i < 2; ++i) {
        assert(!strstr(w.config[i].data, "itls.") && !strstr(w.config[i].data, "vitals."));
        assert(!strcmp(w.config[i].data, w.config[i].durable));
    }
    assert(path_exists(&w, "vs0:/data/external/cert/CA_LIST.cer_old") == 1);
    assert(path_exists(&w, "vs0:/sys/external/libhttp.suprx") == 1);
    assert(tls_fixer_conflicts_present(configs, 2, &files) == 0);
    unsigned deleted = w.deletions, patched = w.patches;
    assert(tls_fixer_remove_conflicts(configs, 2, &files) == 0 && w.deletions == deleted && w.patches == patched);
    /* Inject failure at every acknowledged read, patch, flush, stat and
     * deletion boundary. No new component can run after a cleanup error. */
    for (unsigned fail = 1; fail <= operations; ++fail) {
        seed(&w); ops(&w, configs, &files); w.fail_at = fail;
        assert(tls_fixer_remove_conflicts(configs, 2, &files) < 0);
        if (w.deletions) for (unsigned i = 0; i < 2; ++i) assert(!has_active(w.config[i].durable));
        assert(strstr(w.config[0].data, "ur0:tai/storage.skprx\r\n"));
        assert(strstr(w.config[1].data, "*NPXS10003\nur0:tai/other.suprx"));
        w.fail_at = 0;
        int retried = tls_fixer_remove_conflicts(configs, 2, &files);
        if (retried < 0) fprintf(stderr, "Retry failed after boundary %u:\n%s\n%s\n", fail, w.config[0].data, w.config[1].data);
        assert(retried == 0);
        assert(path_exists(&w, "uma0:/custom/vitals.skprx") == 0);
        assert(path_exists(&w, "vs0:/data/external/cert/CA_LIST.cer_old") == 1);
    }
    seed(&w); ops(&w, configs, &files); w.config[1].data[2] = 0;
    assert(tls_fixer_remove_conflicts(configs, 2, &files) < 0 && !w.patches && !w.deletions);
    seed(&w); ops(&w, configs, &files); w.config[1].oversized = 1;
    assert(tls_fixer_remove_conflicts(configs, 2, &files) < 0 && !w.patches && !w.deletions);
    seed(&w); ops(&w, configs, &files); config(&w.config[1], "*KERNEL\nur0:/../other/vitals.skprx\n");
    assert(tls_fixer_remove_conflicts(configs, 2, &files) < 0 && !w.patches && !w.deletions);
    seed(&w); ops(&w, configs, &files); w.silent_patch = 1;
    assert(tls_fixer_remove_conflicts(configs, 2, &files) < 0 && !w.deletions);
    seed(&w); ops(&w, configs, &files); w.silent_delete = 1;
    assert(tls_fixer_remove_conflicts(configs, 2, &files) < 0);
    seed(&w); ops(&w, configs, &files);
    config(&w.config[0], "*KERNEL\nur0:tai/not_itls.skprx\nur0:tai/vitals-helper.skprx\n# itls.skprx is not a path\n");
    config(&w.config[1], "");
    w.paths_count = 0;
    assert(tls_fixer_conflicts_present(configs, 2, &files) == 0);
    assert(tls_fixer_remove_conflicts(configs, 2, &files) == 0 && !w.patches && !w.deletions);
    seed(&w); ops(&w, configs, &files);
    config(&w.config[0], "*ALL\n  UR0:/custom/ITLS.SUPRX\n"); config(&w.config[1], "");
    assert(tls_fixer_remove_conflicts(configs, 2, &files) == 0);
    assert(!strstr(w.config[0].data, "ITLS.SUPRX"));
    puts("PASS conflict removal, both configs, relocated paths, certificate backup and failure boundaries");
    return 0;
}
