#include "conflicts.h"
#include "../kernel/self_disarm.h"
#include <stdlib.h>
#include <string.h>

/* These are installed runtime files, not the installer applications. The
 * shared CA_LIST.cer_old is Sony's uninstall backup and must be retained. */
static const char *const plugins[] = {
    "ur0:tai/itls.skprx", "ur0:tai/itls.suprx", "ur0:tai/vitals.skprx",
    "ux0:tai/itls.skprx", "ux0:tai/itls.suprx", "ux0:tai/vitals.skprx",
};
static const char *const directories[] = {
    "vs0:/data/external/itls", "vs0:/data/external/vitals",
    "ur0:tai/itls-native", "ur0:tai/vitals-native",
    "ux0:tai/itls-native", "ux0:tai/vitals-native",
    "ux0:data/vitals",
};
typedef struct { char *data; size_t size; } Config;
typedef struct {
    size_t begin, end, path_begin, path_size;
    int commented, missing_prefix, erase_only;
} Entry;
static const char *const mounts[] = {
    "ur0", "ux0", "uma0", "imc0", "xmc0", "vs0", "vd0", "ud0", "sa0", "sd0",
    "os0", "tm0", "pd0", "host0", "gro0", "grw0", "app0", "addcont0", "savedata0",
};
typedef int (*Visit)(const Config *, const Entry *, void *);
static int whitespace(char c) { return c == ' ' || c == '\t'; }
static unsigned char lower(unsigned char c) { return c >= 'A' && c <= 'Z' ? c + 'a' - 'A' : c; }
static int equal(const char *a, size_t n, const char *b) {
    if (n != strlen(b)) return 0;
    for (size_t i = 0; i < n; ++i) if (lower((unsigned char)a[i]) != lower((unsigned char)b[i])) return 0;
    return 1;
}
static int valid_path(const char *path, size_t size, size_t mount) {
    if (!mount || mount > 8) return 0;
    for (size_t i = 0; i < mount; ++i) {
        unsigned char ch = lower((unsigned char)path[i]);
        if (!((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9'))) return 0;
    }
    for (size_t i = mount + 1; i < size;) {
        size_t start = i;
        while (i < size && path[i] != '/') {
            if ((unsigned char)path[i] < 32 || path[i] == ':' || path[i] == '\\') return 0;
            ++i;
        }
        if ((i - start == 1 && path[start] == '.') ||
            (i - start == 2 && path[start] == '.' && path[start + 1] == '.')) return 0;
        if (i < size) ++i;
    }
    return 1;
}
static int scan(const Config *c, Visit visit, void *context) {
    int found = 0;
    for (size_t at = 0; at < c->size;) {
        Entry e = {0};
        e.begin = at;
        while (at < c->size && c->data[at] != '\r' && c->data[at] != '\n') ++at;
        e.end = at;
        if (at < c->size) ++at;
        while (e.begin < e.end && whitespace(c->data[e.begin])) ++e.begin;
        e.path_begin = e.begin;
        if (e.path_begin < e.end && c->data[e.path_begin] == '#') {
            e.commented = 1; ++e.path_begin;
            while (e.path_begin < e.end && whitespace(c->data[e.path_begin])) ++e.path_begin;
        }
        size_t end = e.path_begin;
        while (end < e.end && !whitespace(c->data[end])) ++end;
        e.path_size = end - e.path_begin;
        const char *path = c->data + e.path_begin;
        size_t base = 0;
        for (size_t i = 0; i < e.path_size; ++i) if (path[i] == '/' || path[i] == ':') base = i + 1;
        if (!equal(path + base, e.path_size - base, "itls.skprx") &&
            !equal(path + base, e.path_size - base, "itls.suprx") &&
            !equal(path + base, e.path_size - base, "vitals.skprx")) continue;
        /* A comment mentioning a filename is not a plugin entry. Paths must
         * be mount-qualified, without traversal or ambiguous suffixes. */
        while (end < e.end && whitespace(c->data[end])) ++end;
        if (end < e.end && c->data[end] != '#') { if (e.commented) continue; return -1; }
        const char *colon = memchr(path, ':', e.path_size);
        size_t mount = colon ? (size_t)(colon - path) : 0;
        if (e.path_size >= 255) return -1;
        if (!colon || !valid_path(path, e.path_size, mount)) {
            if (!e.commented) return -1;
            /* A prior interruption may have cleared only the path prefix.
             * Its file was already removed before erasure started. */
            e.erase_only = 1;
        }
        /* Recover paths left by an interrupted one-byte disarm, including
         * relocated plugins on removable/internal storage. */
        if (!e.erase_only && e.commented && e.path_begin == e.begin + 1) {
            int complete = 0, shortened = 0;
            for (size_t i = 0; i < sizeof(mounts) / sizeof(mounts[0]); ++i) {
                complete |= equal(path, mount, mounts[i]);
                shortened |= equal(path, mount, mounts[i] + 1);
            }
            e.missing_prefix = !complete && shortened;
        }
        ++found;
        if (visit) { int rc = visit(c, &e, context); if (rc < 0) return rc; }
    }
    return found;
}
static int load(const TlsFixerConfigIo *io, Config *c) {
    if (!io->read || !io->patch || !io->sync || io->read(io->context, &c->data, &c->size) < 0 ||
        !c->data || c->size > TLS_FIXER_SELF_DISARM_MAX_CONFIG || memchr(c->data, 0, c->size)) return -1;
    return scan(c, NULL, NULL) < 0 ? -1 : 0;
}
static int inventory(const TlsFixerConflictFiles *f, int removing) {
    int found = 0;
    for (unsigned group = 0; group < 2; ++group) {
        const char *const *paths = group ? directories : plugins;
        size_t count = group ? sizeof(directories) / sizeof(directories[0]) : sizeof(plugins) / sizeof(plugins[0]);
        for (size_t i = 0; i < count; ++i) {
            int present = f->exists(f->context, paths[i]);
            if (present < 0) return present;
            if (present) {
                ++found;
                if (removing) { int rc = f->remove(f->context, paths[i], (int)group); if (rc < 0) return rc; }
            }
        }
    }
    return found;
}
int tls_fixer_conflicts_present(const TlsFixerConfigIo *configs, size_t count,
    const TlsFixerConflictFiles *files) {
    if (!configs || !count || !files || !files->exists) return -1;
    int found = 0;
    for (size_t i = 0; i < count; ++i) {
        Config c = {0}; int rc = load(&configs[i], &c);
        if (rc == 0) { rc = scan(&c, NULL, NULL); found |= rc > 0; }
        free(c.data); if (rc < 0) return rc;
    }
    int rc = inventory(files, 0);
    return rc < 0 ? rc : found || rc > 0;
}
static int disarm(const Config *c, const Entry *e, void *context) {
    const TlsFixerConfigIo *io = context;
    return e->commented ? 0 : io->patch(io->context, e->begin, c->data[e->begin], '#');
}
static int erase(const Config *c, const Entry *e, void *context) {
    const TlsFixerConfigIo *io = context;
    /* Delete the entry text in place without ever truncating/replacing the
     * active config. Flush the cleared path before removing its leading '#',
     * so interruption cannot make a partially cleared path active again. */
    for (size_t i = e->begin + 1; i < e->end; ++i)
        if (c->data[i] != ' ' && io->patch(io->context, i, c->data[i], ' ') < 0) return -1;
    if (io->sync(io->context) < 0) return -1;
    return io->patch(io->context, e->begin, '#', ' ');
}
static int inactive(const Config *c, const Entry *e, void *context) {
    (void)c; (void)context; return e->commented ? 0 : -1;
}
static int remove_entry_file(const Config *c, const Entry *e, void *context) {
    const TlsFixerConflictFiles *f = context;
    if (e->erase_only) return 0;
    const char *original = c->data + e->path_begin;
    size_t mount = (size_t)((const char *)memchr(original, ':', e->path_size) - original);
    for (size_t i = 0; i < (e->missing_prefix ? sizeof(mounts) / sizeof(mounts[0]) : 1); ++i) {
        char path[256]; size_t prefix = e->missing_prefix ? 1 : 0;
        if (prefix) {
            if (!equal(original, mount, mounts[i] + 1)) continue;
            path[0] = mounts[i][0];
        }
        memcpy(path + prefix, original, e->path_size); path[prefix + e->path_size] = 0;
        int rc = f->remove(f->context, path, 0);
        if (rc < 0) return rc;
        if (f->exists(f->context, path) != 0) return -1;
    }
    return 0;
}
int tls_fixer_remove_conflicts(const TlsFixerConfigIo *configs, size_t count,
    const TlsFixerConflictFiles *files) {
    if (!configs || !count || !files || !files->exists || !files->remove || !files->sync) return -1;
    Config *snapshots = calloc(count, sizeof(*snapshots));
    if (!snapshots) return -1;
    int rc = -1;
    for (size_t i = 0; i < count; ++i) if (load(&configs[i], &snapshots[i]) < 0) goto done;
    if (inventory(files, 0) < 0) goto done;
    for (size_t i = 0; i < count; ++i)
        if (scan(&snapshots[i], disarm, (void *)&configs[i]) < 0 || configs[i].sync(configs[i].context) < 0) goto done;
    /* Confirm every config is inactive before deleting files. Keep the paths
     * until their files are removed so an interrupted cleanup can be retried. */
    for (size_t i = 0; i < count; ++i) {
        Config verified = {0}; int result = load(&configs[i], &verified);
        if (result == 0) result = scan(&verified, inactive, NULL);
        free(verified.data); if (result < 0) goto done;
    }
    for (size_t i = 0; i < count; ++i)
        if (scan(&snapshots[i], remove_entry_file, (void *)files) < 0) goto done;
    if (inventory(files, 1) < 0 || files->sync(files->context) < 0 || inventory(files, 0) != 0) goto done;
    for (size_t i = 0; i < count; ++i) {
        if (scan(&snapshots[i], erase, (void *)&configs[i]) < 0 || configs[i].sync(configs[i].context) < 0) goto done;
        Config verified = {0}; int result = load(&configs[i], &verified);
        if (result == 0) result = scan(&verified, NULL, NULL);
        free(verified.data); if (result != 0) goto done;
    }
    rc = 0;
done:
    for (size_t i = 0; i < count; ++i) free(snapshots[i].data);
    free(snapshots); return rc < 0 ? rc : 0;
}
