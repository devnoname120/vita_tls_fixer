#include "disarm_result.h"

#include <psp2kern/io/fcntl.h>
#include <psp2kern/kernel/sysclib.h>

#include <stddef.h>

static char *hex_field(char *cursor, const char *name, uint32_t value) {
    static const char digits[] = "0123456789abcdef";
    size_t length = strlen(name);
    memcpy(cursor, name, length);
    cursor += length;
    for (unsigned int i = 0; i < 8; ++i) {
        *cursor++ = digits[(value >> (28 - 4 * i)) & 15];
    }
    *cursor++ = '\n';
    return cursor;
}

static int write_record(const char *record, size_t size, SceOff offset) {
    size_t written = 0;
    int result = -1;
    if (offset < 0 || offset > TLS_FIXER_DISARM_RESULT_SIZE ||
        size > TLS_FIXER_DISARM_RESULT_SIZE - (size_t)offset) return -1;
    SceUID fd = ksceIoOpen(TLS_FIXER_DISARM_RESULT_PATH, SCE_O_RDWR, 0);
    if (fd < 0) return fd;
    if (ksceIoLseek(fd, 0, SCE_SEEK_END) != TLS_FIXER_DISARM_RESULT_SIZE) goto done;
    while (written < size) {
        int count = ksceIoPwrite(fd, record + written,
            (SceSize)(size - written), offset + (SceOff)written);
        if (count <= 0 || (size_t)count > size - written) goto done;
        written += (size_t)count;
    }
    result = ksceIoSync(TLS_FIXER_DISARM_RESULT_PATH, 0);
done:
    if (ksceIoClose(fd) < 0) result = -1;
    return result;
}

int tls_fixer_write_trace_setup_result(int outcome) {
    char setup[32];
    memset(setup, ' ', sizeof(setup));
    (void)hex_field(setup, "trace_setup=", (uint32_t)outcome);
    setup[sizeof(setup) - 1] = '\n';
    return write_record(setup, sizeof(setup), 192);
}

#if TLS_FIXER_TRACE_MODULE_PATHS
int tls_fixer_write_trace_runtime_result(const TlsFixerTraceStatus *status, unsigned int monitor) {
    char failure[32], counts[28];
    char *cursor;
    if (status == NULL || (monitor != 1 && monitor != 2)) return -1;
    memset(failure, ' ', sizeof(failure));
    cursor = hex_field(failure, "err=", (uint32_t)status->error);
    (void)hex_field(cursor, "op=", status->operation);
    failure[sizeof(failure) - 1] = '\n';
    memset(counts, ' ', sizeof(counts));
    cursor = hex_field(counts, "a=", status->attempts);
    cursor = hex_field(cursor, "h=", status->loads);
    *cursor++ = 'm';
    *cursor++ = '=';
    *cursor++ = monitor == 1 ? '1' : '2';
    *cursor = '\n';
    counts[sizeof(counts) - 1] = '\n';
    int result = write_record(failure, sizeof(failure), 160);
    return result < 0 ? result : write_record(counts, sizeof(counts), 224);
}
#endif

int tls_fixer_write_disarm_result(int outcome, const TlsFixerDisarmReport *report) {
    static const char heading[] = "TLS_FIXER-DISARM-RESULT v1\n";
    char record[TLS_FIXER_DISARM_RESULT_SIZE];
    char *cursor = record;
    size_t stage_size = 0;

    if (report == NULL || report->stage == NULL) return -1;
    while (stage_size < 32 && report->stage[stage_size] != '\0') {
        unsigned char ch = (unsigned char)report->stage[stage_size];
        if (!((ch >= 'a' && ch <= 'z') || ch == '.' || ch == '_')) return -1;
        ++stage_size;
    }
    if (stage_size == 0 || stage_size == 32) return -1;
    memset(record, ' ', sizeof(record));
    memcpy(cursor, heading, sizeof(heading) - 1);
    cursor += sizeof(heading) - 1;
    cursor = hex_field(cursor, "outcome=", (uint32_t)outcome);
    cursor = hex_field(cursor, "code=", (uint32_t)report->native_result);
    cursor = hex_field(cursor, "config=", (uint32_t)report->config_index);
    cursor = hex_field(cursor, "writes=", report->written_entries);
    cursor = hex_field(cursor, "verified=", report->verified_configs);
    cursor = hex_field(cursor, "cleanup=", (uint32_t)report->cleanup_result);
    memcpy(cursor, "stage=", 6);
    cursor += 6;
    memcpy(cursor, report->stage, stage_size);
    cursor[stage_size] = '\n';
    memcpy(record + sizeof(record) - 4, "END\n", 4);

    return write_record(record, sizeof(record), 0);
}
