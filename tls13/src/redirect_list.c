/* SPDX-License-Identifier: 0BSD */
#include "tls_fixer/redirect_list.h"

/* Passes the pair on one line to keep; overflowed says the line was cut at the line limit, which
 * is only safe when the cut fell inside a comment */
static int finish_line(const char *line, size_t length, int overflowed, TlsFixerRedirectListKeep keep,
    void *context) {
    TlsFixerHostRule rule;

    if (overflowed) {
        size_t i = 0;
        while (i < length && line[i] != '#') {
            ++i;
        }
        if (i == length) {
            return 0;
        }
    }
    if (!tls_fixer_host_map_parse_line(line, length, &rule)) {
        return 0;
    }
    return keep(context, &rule);
}

int tls_fixer_redirect_list_read(TlsFixerRedirectListRead read, char *work, TlsFixerRedirectListKeep keep,
    void *context) {
    char *chunk = work, *line = work + TLS_FIXER_REDIRECTS_CHUNK;
    size_t line_length = 0;
    unsigned int offset = 0;
    int overflowed = 0, count, stop = 0;

    while (!stop && (count = read(offset, chunk, TLS_FIXER_REDIRECTS_CHUNK)) > 0) {
        if (count > (int)TLS_FIXER_REDIRECTS_CHUNK || offset > 65536u - (unsigned int)count) return -1;
        offset += (unsigned int)count;
        for (int i = 0; i < count && !stop; ++i) {
            if (chunk[i] == '\n') {
                stop = finish_line(line, line_length, overflowed, keep, context);
                line_length = 0;
                overflowed = 0;
            } else if (line_length < TLS_FIXER_REDIRECT_LIST_LINE_LIMIT) {
                line[line_length++] = chunk[i];
            } else {
                overflowed = 1;
            }
        }
    }
    if (stop) {
        return 0;
    }
    if (count < 0) {
        return count;
    }
    /* The last line need not end with a newline */
    if (line_length > 0 || overflowed) {
        (void)finish_line(line, line_length, overflowed, keep, context);
    }
    return 0;
}
