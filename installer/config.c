#include "config.h"
#include "../kernel/self_disarm.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int space(unsigned char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\v' || c == '\f'; }
static int equal(const char *a, size_t length, const char *b) {
    if (length != strlen(b)) return 0;
    for (size_t i = 0; i < length; ++i) {
        unsigned char x = (unsigned char)a[i], y = (unsigned char)b[i];
        if (x >= 'A' && x <= 'Z') x = (unsigned char)(x + 'a' - 'A');
        if (y >= 'A' && y <= 'Z') y = (unsigned char)(y + 'a' - 'A');
        if (x != y) return 0;
    }
    return 1;
}
static int own(const char *text, size_t length) {
    static const char *const paths[] = {"ur0:tai/tls_fixer.skprx", "ur0:/tai/tls_fixer.skprx",
        TLS_FIXER_REMOVABLE_KERNEL_PATH, TLS_FIXER_REMOVABLE_KERNEL_PATH_NO_SLASH};
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i)
        if (equal(text, length, paths[i])) return 1;
    size_t base = 0;
    for (size_t i = 0; i < length; ++i) if (text[i] == '/' || text[i] == ':') base = i + 1;
    return length - base >= strlen("tls_fixer.skprx") &&
        equal(text + base, strlen("tls_fixer.skprx"), "tls_fixer.skprx") ? -1 : 0;
}
static int same_target(const char *text, size_t length, const char *target) {
    if (equal(text, length, target)) return 1;
    if (!strcmp(target, TLS_FIXER_REMOVABLE_KERNEL_PATH))
        return equal(text, length, TLS_FIXER_REMOVABLE_KERNEL_PATH_NO_SLASH);
    if (!strcmp(target, "ur0:tai/tls_fixer.skprx"))
        return equal(text, length, "ur0:/tai/tls_fixer.skprx");
    return 0;
}
typedef struct { size_t offset; char expected, enabled; unsigned active, target_active; } Slot;
/* Validate all active own entries before making changes. Disabled entries can
 * be either the kernel's '#x0:' form or an ordinary '# ux0:' comment. */
static int scan(const char *data, size_t size, const char *target, Slot *slot,
    const TlsFixerConfigIo *io, int disarm) {
    size_t at = 0; int kernel = 0;
    while (at < size) {
        size_t begin = at;
        while (at < size && data[at] != '\n' && data[at] != '\r') ++at;
        size_t end = at; if (at < size) ++at;
        while (begin < end && space((unsigned char)data[begin])) ++begin;
        while (end > begin && space((unsigned char)data[end - 1])) --end;
        if (begin == end) continue;
        if (data[begin] == '*') {
            size_t name = begin + 1;
            while (name < end && space((unsigned char)data[name])) ++name;
            if (name < end && data[name] == '!') ++name;
            while (name < end && space((unsigned char)data[name])) ++name;
            kernel = end - name == 6 && !memcmp(data + name, "KERNEL", 6); continue;
        }
        if (!kernel) continue;
        if (data[begin] == '#') {
            if (!target || slot->offset != SIZE_MAX) continue;
            size_t comment = begin + 1;
            while (comment < end && space((unsigned char)data[comment])) ++comment;
            if (same_target(data + comment, end - comment, target)) {
                slot->offset = begin; slot->expected = '#'; slot->enabled = ' ';
            } else if (end - begin == strlen(target) &&
                       equal(data + begin + 1, end - begin - 1, target + 1)) {
                slot->offset = begin; slot->expected = '#'; slot->enabled = target[0];
            } else if (!strcmp(target, TLS_FIXER_REMOVABLE_KERNEL_PATH) &&
                       end - begin == strlen(TLS_FIXER_REMOVABLE_KERNEL_PATH_NO_SLASH) &&
                       equal(data + begin + 1, end - begin - 1, &TLS_FIXER_REMOVABLE_KERNEL_PATH_NO_SLASH[1])) {
                slot->offset = begin; slot->expected = '#'; slot->enabled = target[0];
            } else if (!strcmp(target, "ur0:tai/tls_fixer.skprx") &&
                       end - begin == strlen("ur0:/tai/tls_fixer.skprx") &&
                       equal(data + begin + 1, end - begin - 1, "r0:/tai/tls_fixer.skprx")) {
                slot->offset = begin; slot->expected = '#'; slot->enabled = 'u';
            }
            continue;
        }
        int match = own(data + begin, end - begin);
        if (match < 0) return -1;
        if (match) {
            ++slot->active;
            if (target && same_target(data + begin, end - begin, target)) ++slot->target_active;
        }
        if (match && disarm && io->patch(io->context, begin, data[begin], '#') < 0) return -1;
    }
    return 0;
}
static int read_config(const TlsFixerConfigIo *io, char **data, size_t *size) {
    *data = NULL; *size = 0;
    if (!io || !io->read || !io->append || !io->patch || !io->sync ||
        io->read(io->context, data, size) < 0 || !*data) return -1;
    if (*size > TLS_FIXER_SELF_DISARM_MAX_CONFIG || memchr(*data, 0, *size)) {
        free(*data); *data = NULL; return -1;
    }
    return 0;
}
int tls_fixer_config_check(const TlsFixerConfigIo *io) {
    char *data; size_t size; Slot slot = {.offset = SIZE_MAX};
    if (read_config(io, &data, &size) < 0) { free(data); return -1; }
    int rc = scan(data, size, NULL, &slot, io, 0); free(data); return rc;
}
int tls_fixer_config_disable(const TlsFixerConfigIo *io) {
    char *data; size_t size; Slot unused = {.offset = SIZE_MAX};
    if (read_config(io, &data, &size) < 0) { free(data); return -1; }
    int rc = scan(data, size, NULL, &unused, io, 0);
    if (rc == 0) rc = scan(data, size, NULL, &unused, io, 1);
    free(data);
    if (rc < 0 || io->sync(io->context) < 0) return -1;
    /* A second scan rejects an unsuccessful write even if the callback did
     * not report it. No active own entry may remain after this operation. */
    if (read_config(io, &data, &size) < 0) { free(data); return -1; }
    unused = (Slot){.offset = SIZE_MAX};
    rc = scan(data, size, NULL, &unused, io, 0);
    if (unused.active) rc = -1;
    free(data); return rc;
}
int tls_fixer_config_enable(const TlsFixerConfigIo *io, const char *kernel_path) {
    if (!kernel_path || (strcmp(kernel_path, TLS_FIXER_REMOVABLE_KERNEL_PATH) &&
                        strcmp(kernel_path, "ur0:tai/tls_fixer.skprx"))) return -1;
    if (tls_fixer_config_disable(io) < 0) return -1;
    char *data; size_t size; Slot slot = {.offset = SIZE_MAX};
    if (read_config(io, &data, &size) < 0) { free(data); return -1; }
    int rc = scan(data, size, kernel_path, &slot, io, 0);
    if (rc < 0) { free(data); return -1; }
    if (slot.offset == SIZE_MAX) {
        char block[192];
        int n = snprintf(block, sizeof(block), "\n# TLS_FIXER\n#KERNEL\n#%s\n", kernel_path + 1);
        if (n < 0 || (size_t)n >= sizeof(block) || size > TLS_FIXER_SELF_DISARM_MAX_CONFIG - (size_t)n) {
            free(data); return -1;
        }
        if (io->append(io->context, block, (size_t)n) < 0 || io->sync(io->context) < 0) { free(data); return -1; }
        char *updated; size_t updated_size;
        if (read_config(io, &updated, &updated_size) < 0) { free(updated); free(data); return -1; }
        rc = updated_size == size + (size_t)n && !memcmp(updated, data, size) &&
            !memcmp(updated + size, block, (size_t)n) ? 0 : -1;
        free(updated); free(data); data = NULL;
        if (rc < 0) return -1;
        const char *section = strstr(block, "#KERNEL");
        const char *entry = strstr(section + 1, "\n#");
        size_t section_at = size + (size_t)(section - block);
        if (!entry || io->patch(io->context, section_at, '#', '*') < 0 ||
            io->sync(io->context) < 0) return -1;
        slot = (Slot){.offset = size + (size_t)(entry + 1 - block), .expected = '#', .enabled = kernel_path[0]};
        if (read_config(io, &updated, &updated_size) < 0) { free(updated); return -1; }
        Slot verified = {.offset = SIZE_MAX};
        rc = updated_size == size + (size_t)n && updated[section_at] == '*' ?
            scan(updated, updated_size, kernel_path, &verified, io, 0) : -1;
        free(updated);
        if (rc < 0 || verified.active || verified.offset != slot.offset) return -1;
    }
    free(data);
    if (io->patch(io->context, slot.offset, slot.expected, slot.enabled) < 0 ||
        io->sync(io->context) < 0) return -1;
    if (read_config(io, &data, &size) < 0) { free(data); return -1; }
    slot = (Slot){.offset = SIZE_MAX};
    rc = scan(data, size, kernel_path, &slot, io, 0);
    if (slot.active != 1 || slot.target_active != 1) rc = -1;
    free(data); return rc;
}
int tls_fixer_config_enabled(const TlsFixerConfigIo *io, const char *kernel_path) {
    char *data; size_t size; Slot slot = {.offset = SIZE_MAX};
    if (!kernel_path) return 0;
    if (read_config(io, &data, &size) < 0) { free(data); return 0; }
    int rc = scan(data, size, kernel_path, &slot, io, 0);
    free(data); return rc == 0 && slot.target_active > 0;
}
