#include "self_disarm.h"

#include <psp2kern/io/fcntl.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/kernel/sysmem.h>

#include <stddef.h>
#include <stdint.h>

#define TLS_FIXER_NO_ENTRY ((int32_t)0x80010002)

static TlsFixerDisarmReport last_report;
static int current_config = -1;
static int report_failed;

const TlsFixerDisarmReport *tls_fixer_self_disarm_report(void) {
    return &last_report;
}

static int fail_at(const char *stage, int32_t result) {
    if (!report_failed) {
        last_report.stage = stage;
        last_report.native_result = result;
        last_report.config_index = current_config;
        report_failed = 1;
    }
    return -1;
}

static int space(unsigned char byte) {
    return byte == ' ' || byte == '\t' || byte == '\r' || byte == '\v' || byte == '\f';
}

static int equal_path(const unsigned char *text, size_t length, const char *expected) {
    if (length != strlen(expected)) return 0;
    for (size_t i = 0; i < length; ++i) {
        unsigned char byte = text[i];
        if (byte >= 'A' && byte <= 'Z') byte = (unsigned char)(byte + ('a' - 'A'));
        if (byte != (unsigned char)expected[i]) return 0;
    }
    return 1;
}

static int self_entry(const unsigned char *text, size_t length) {
    static const char *const paths[] = {"ur0:tai/tls_fixer.skprx", "ur0:/tai/tls_fixer.skprx",
        TLS_FIXER_REMOVABLE_KERNEL_PATH, TLS_FIXER_REMOVABLE_KERNEL_PATH_NO_SLASH};
    size_t basename = 0;
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i) {
        if (equal_path(text, length, paths[i])) return 1;
    }
    for (size_t i = 0; i < length; ++i) {
        if (text[i] == '/' || text[i] == ':') basename = i + 1;
    }
    return equal_path(text + basename, length - basename, "tls_fixer.skprx") ? -1 : 0;
}

static int edit_entries(SceUID fd, unsigned char *text, size_t size, int write_changes) {
    size_t cursor = 0;
    int kernel = 0, matches = 0;

    while (cursor < size) {
        size_t begin = cursor, end;
        while (cursor < size && text[cursor] != '\n' && text[cursor] != '\r') ++cursor;
        end = cursor;
        if (cursor < size) ++cursor;
        while (begin < end && space(text[begin])) ++begin;
        while (end > begin && space(text[end - 1])) --end;
        if (begin == end || text[begin] == '#') continue;
        if (text[begin] == '*') {
            ++begin;
            while (begin < end && space(text[begin])) ++begin;
            if (begin < end && text[begin] == '!') ++begin;
            while (begin < end && space(text[begin])) ++begin;
            kernel = end - begin == 6 && memcmp(text + begin, "KERNEL", 6) == 0;
        } else if (kernel) {
            int own = self_entry(text + begin, end - begin);
            if (own < 0) return fail_at("gate.alias", own);
            if (own && write_changes) {
                /* A one-byte comment avoids truncating or replacing the whole taiHEN config. */
                int written = ksceIoPwrite(fd, "#", 1, (SceOff)begin);
                if (written != 1) return fail_at("gate.write", written);
                text[begin] = '#';
                ++last_report.written_entries;
            }
            matches += own;
        }
    }
    return matches;
}

static int read_exact(SceUID fd, unsigned char *text, size_t size) {
    size_t used = 0;
    unsigned char extra;
    while (used < size) {
        int count = ksceIoRead(fd, text + used, (SceSize)(size - used));
        if (count <= 0 || (size_t)count > size - used) return fail_at("gate.read", count);
        used += (size_t)count;
    }
    int tail = ksceIoRead(fd, &extra, 1);
    return tail == 0 ? 0 : fail_at("gate.read_eof", tail);
}

static int verify_file(const char *path, const unsigned char *expected, size_t size) {
    unsigned char buffer[256];
    size_t used = 0;
    SceUID fd = ksceIoOpen(path, SCE_O_RDONLY, 0);
    int result = -1;
    if (fd < 0) return fail_at("gate.verify_open", fd);
    while (used < size) {
        SceSize wanted = size - used > sizeof(buffer) ? sizeof(buffer) : (SceSize)(size - used);
        int count = ksceIoRead(fd, buffer, wanted);
        if (count <= 0 || (unsigned int)count > wanted) {
            (void)fail_at("gate.verify_read", count);
            goto done;
        }
        if (memcmp(buffer, expected + used, (size_t)count) != 0) {
            (void)fail_at("gate.verify_bytes", -1);
            goto done;
        }
        used += (size_t)count;
    }
    int tail = ksceIoRead(fd, buffer, 1);
    if (tail == 0) result = 0;
    else (void)fail_at("gate.verify_eof", tail);
done:
    {
        int closed = ksceIoClose(fd);
        if (closed < 0) result = fail_at("gate.verify_close", closed);
    }
    return result;
}

static int disarm_file(const char *path, const char *mount, int optional, unsigned char *text) {
    SceUID fd = ksceIoOpen(path, SCE_O_RDWR, 0);
    SceOff length;
    int result = -1, matches;

    if (fd < 0) return optional && fd == TLS_FIXER_NO_ENTRY ? 0 : fail_at("gate.open", fd);
    length = ksceIoLseek(fd, 0, SCE_SEEK_END);
    if (length < 0 || length > TLS_FIXER_SELF_DISARM_MAX_CONFIG) {
        (void)fail_at("gate.size", (int32_t)length);
        goto done;
    }
    SceOff seek = ksceIoLseek(fd, 0, SCE_SEEK_SET);
    if (seek != 0) {
        (void)fail_at("gate.seek", (int32_t)seek);
        goto done;
    }
    if (read_exact(fd, text, (size_t)length) != 0) goto done;
    if (memchr(text, 0, (size_t)length) != NULL) {
        (void)fail_at("gate.nul", -1);
        goto done;
    }
    matches = edit_entries(fd, text, (size_t)length, 0);
    if (matches < 0) goto done;
    if (matches == 0) { result = 0; goto done; }
    if (edit_entries(fd, text, (size_t)length, 1) != matches) goto done;
    int synced = ksceIoSync(path, 0);
    if (synced < 0) {
        (void)fail_at("gate.file_sync", synced);
        goto done;
    }
    result = ksceIoClose(fd);
    fd = -1;
    if (result < 0) return fail_at("gate.close", result);
    synced = ksceIoSync(mount, 0);
    if (synced < 0) return fail_at("gate.mount_sync", synced);
    if (verify_file(path, text, (size_t)length) != 0) return -1;
    ++last_report.verified_configs;
    return matches;
done:
    {
        int closed = ksceIoClose(fd);
        if (closed < 0) result = fail_at("gate.close", closed);
    }
    return result;
}

int tls_fixer_self_disarm(void) {
    void *allocation = NULL;
    unsigned char *text;
    int primary, alternate, result = -1;
    memset(&last_report, 0, sizeof(last_report));
    last_report.stage = "gate.complete";
    last_report.config_index = current_config = -1;
    report_failed = 0;
    SceUID memory = ksceKernelAllocMemBlock("tls_fixer self-disarm", SCE_KERNEL_MEMBLOCK_TYPE_KERNEL_RW,
        TLS_FIXER_SELF_DISARM_MAX_CONFIG, NULL);
    if (memory < 0) return fail_at("gate.alloc", memory);
    int base_result = ksceKernelGetMemBlockBase(memory, &allocation);
    if (base_result < 0 || allocation == NULL) {
        (void)fail_at("gate.base", base_result);
        goto done;
    }
    text = allocation;
    current_config = 0;
    primary = disarm_file("ur0:tai/config.txt", "ur0:", 0, text);
    if (primary < 0) goto done;
    current_config = 1;
    alternate = disarm_file("ux0:tai/config.txt", "ux0:", 1, text);
    if (alternate >= 0 && primary + alternate > 0) result = 0;
    else if (alternate >= 0) (void)fail_at("gate.no_entry", -1);
done:
    current_config = -1;
    last_report.cleanup_result = ksceKernelFreeMemBlock(memory);
    if (last_report.cleanup_result < 0) result = fail_at("gate.free", last_report.cleanup_result);
    return result;
}
