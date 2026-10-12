#define _POSIX_C_SOURCE 200809L
#include "trace.h"
#include <vita_mock.h>
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static unsigned int printed;
int sceClibPrintf(const char *format, ...) {
    va_list args;
    const char *line;
    assert(strcmp(format, "%s") == 0);
    va_start(args, format);
    line = va_arg(args, const char *);
    assert(strlen(line) < TLS_FIXER_TRACE_LINE_LIMIT && strstr(line, "tls_fixer:") != NULL);
    va_end(args);
    ++printed;
    return 0;
}

static unsigned int count_lines(const char *path) {
    char line[TLS_FIXER_TRACE_LINE_LIMIT];
    unsigned int lines = 0;
    FILE *file = fopen(path, "rb");
    assert(file != NULL);
    while (fgets(line, sizeof(line), file) != NULL) {
        size_t length = strlen(line);
        assert(length > 0 && line[length - 1] == '\n');
        ++lines;
    }
    assert(fclose(file) == 0);
    return lines;
}

int main(int argc, char **argv) {
    char primary[] = "/tmp/tls_fixer-trace-primary-XXXXXX";
    char fallback[] = "/tmp/tls_fixer-trace-fallback-XXXXXX";
    char message[2048];
    int primary_fd = mkstemp(primary);
    int fallback_fd = mkstemp(fallback);
    assert(argc == 2 && primary_fd >= 0 && fallback_fd >= 0);
    assert(close(primary_fd) == 0 && close(fallback_fd) == 0);
    mock_log_file = primary;
    mock_savedata_log_file = fallback;
    if (strcmp(argv[1], "fallback") == 0) {
        mock_log_primary_failure = 1;
    } else if (strcmp(argv[1], "unavailable") == 0) {
        mock_log_primary_failure = 1;
        mock_log_fallback_failure = 1;
    } else {
        assert(strcmp(argv[1], "primary") == 0);
    }
    memset(message, 'x', sizeof(message)-1);
    message[sizeof(message)-1] = '\0';
    tls_fixer_trace("browser TLS active");
    tls_fixer_trace("%s", message);
    for (unsigned int i = 0; i < TLS_FIXER_TRACE_RECORD_LIMIT + 10; ++i) {
        tls_fixer_trace("event %u", i);
    }
    if (strcmp(argv[1], "primary") == 0) {
        assert(count_lines(primary) == TLS_FIXER_TRACE_RECORD_LIMIT);
        assert(count_lines(fallback) == 0);
    } else if (strcmp(argv[1], "fallback") == 0) {
        assert(count_lines(primary) == 0);
        assert(count_lines(fallback) == TLS_FIXER_TRACE_RECORD_LIMIT);
    } else {
        assert(count_lines(primary) == 0);
        assert(count_lines(fallback) == 0);
    }
    assert(unlink(primary) == 0 && unlink(fallback) == 0);
    assert(printed == TLS_FIXER_TRACE_RECORD_LIMIT);
    printf("bounded per-process browser diagnostics: %s PASS\n", argv[1]);
    return 0;
}
