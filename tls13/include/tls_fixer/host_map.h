#ifndef TLS_FIXER_HOST_MAP_H
#define TLS_FIXER_HOST_MAP_H

#include <stddef.h>

/* Host redirects read from a text file: one "old-host new-host" pair per line, and '#' starts
 * a comment
 * Lines that are not exactly two valid host names are skipped */
#define TLS_FIXER_HOST_MAP_MAX_RULES 32u
#define TLS_FIXER_HOST_MAP_MAX_HOST 253u

typedef struct TlsFixerHostRule {
    const char *from;
    const char *to;
    size_t from_length;
    size_t to_length;
} TlsFixerHostRule;

typedef struct TlsFixerHostMap {
    TlsFixerHostRule rules[TLS_FIXER_HOST_MAP_MAX_RULES];
    size_t count;
} TlsFixerHostMap;

#ifdef __cplusplus
extern "C" {
#endif

/* Finds the pair on one line (without its newline): returns 1 when the line holds exactly two
 * valid host names before any '#', with rule pointing at them inside line (not NUL-terminated),
 * and 0 otherwise */
int tls_fixer_host_map_parse_line(const char *line, size_t length, TlsFixerHostRule *rule);
/* Parses text in place: host names are NUL-terminated inside text, which must outlive map
 * text[length] must be writable (the caller allocates length + 1 bytes)
 * Returns the number of rules */
size_t tls_fixer_host_map_parse(TlsFixerHostMap *map, char *text, size_t length);
/* The rule for host (compared without case), or NULL */
const TlsFixerHostRule *tls_fixer_host_map_find(const TlsFixerHostMap *map, const char *host, size_t length);
/* Rewrites the host of url ("scheme://host[:port][/...]") into output
 * Returns 1 when rewritten, 0 when no rule applies (output untouched), -1 when output is too
 * small; *needed receives the size the rewritten URL needs, including its NUL */
int tls_fixer_host_map_rewrite_url(const TlsFixerHostMap *map, const char *url, char *output, size_t capacity,
    size_t *needed);

#ifdef __cplusplus
}
#endif

#endif
