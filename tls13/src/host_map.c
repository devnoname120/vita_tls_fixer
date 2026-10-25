/* SPDX-License-Identifier: 0BSD */
#include "tls_fixer/host_map.h"

#include <stdint.h>

/* URLs longer than this are left alone */
#define URL_LIMIT 8192u

static int is_space(char c) {
    return c == ' ' || c == '\t' || c == '\r';
}

static char lower(char c) {
    return c >= 'A' && c <= 'Z' ? (char)(c - 'A' + 'a') : c;
}

static int valid_host(const char *host, size_t length) {
    size_t index;

    if (length == 0 || length > TLS_FIXER_HOST_MAP_MAX_HOST || host[0] == '.' || host[0] == '-') {
        return 0;
    }
    for (index = 0; index < length; ++index) {
        char c = lower(host[index]);
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-')) {
            return 0;
        }
    }
    return 1;
}

/* Splits one line into its whitespace-separated words; returns how many there are, at most
 * three (a third word makes the line invalid) */
static size_t split_words(const char *line, size_t length, const char *words[2], size_t lengths[2]) {
    size_t count = 0, index = 0;

    while (index < length) {
        while (index < length && is_space(line[index])) {
            ++index;
        }
        if (index == length) {
            break;
        }
        if (count == 2) {
            return 3;
        }
        words[count] = line + index;
        while (index < length && !is_space(line[index])) {
            ++index;
        }
        lengths[count] = (size_t)(line + index - words[count]);
        ++count;
    }
    return count;
}

int tls_fixer_host_map_parse_line(const char *line, size_t length, TlsFixerHostRule *rule) {
    const char *words[2];
    size_t lengths[2];

    if (line == NULL || rule == NULL) {
        return 0;
    }
    for (size_t index = 0; index < length; ++index) {
        if (line[index] == '#') {
            length = index;
            break;
        }
    }
    if (split_words(line, length, words, lengths) != 2 || !valid_host(words[0], lengths[0]) ||
        !valid_host(words[1], lengths[1])) {
        return 0;
    }
    rule->from = words[0];
    rule->to = words[1];
    rule->from_length = lengths[0];
    rule->to_length = lengths[1];
    return 1;
}

size_t tls_fixer_host_map_parse(TlsFixerHostMap *map, char *text, size_t length) {
    size_t start = 0;

    if (map == NULL) {
        return 0;
    }
    map->count = 0;
    if (text == NULL) {
        return 0;
    }
    while (start < length && map->count < TLS_FIXER_HOST_MAP_MAX_RULES) {
        size_t end = start;

        while (end < length && text[end] != '\n' && text[end] != '\0') {
            ++end;
        }
        const int last = end == length || text[end] == '\0';
        TlsFixerHostRule *rule = &map->rules[map->count];
        if (tls_fixer_host_map_parse_line(text + start, end - start, rule)) {
            /* Each name is followed by a separator or the line end, which becomes its NUL */
            text[rule->from + rule->from_length - text] = '\0';
            text[rule->to + rule->to_length - text] = '\0';
            ++map->count;
        }
        if (last) {
            break;
        }
        start = end + 1;
    }
    return map->count;
}

const TlsFixerHostRule *tls_fixer_host_map_find(const TlsFixerHostMap *map, const char *host, size_t length) {
    size_t rule_index, index;

    if (map == NULL || host == NULL) {
        return NULL;
    }
    for (rule_index = 0; rule_index < map->count; ++rule_index) {
        const TlsFixerHostRule *rule = &map->rules[rule_index];
        if (rule->from_length != length) {
            continue;
        }
        for (index = 0; index < length && lower(host[index]) == lower(rule->from[index]); ++index) {
        }
        if (index == length) {
            return rule;
        }
    }
    return NULL;
}

int tls_fixer_host_map_rewrite_url(const TlsFixerHostMap *map, const char *url, char *output, size_t capacity,
    size_t *needed) {
    size_t scheme_end = 0, host_start, host_end, url_length = 0, index;
    const TlsFixerHostRule *rule;

    if (needed != NULL) {
        *needed = 0;
    }
    if (map == NULL || url == NULL || map->count == 0) {
        return 0;
    }
    while (url_length < URL_LIMIT && url[url_length] != '\0') {
        ++url_length;
    }
    if (url_length == URL_LIMIT) {
        return 0;
    }
    /* scheme: letters, digits, '+', '-' and '.', followed by "://" */
    while (scheme_end < url_length) {
        char c = lower(url[scheme_end]);
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.')) {
            break;
        }
        ++scheme_end;
    }
    if (scheme_end == 0 || url_length - scheme_end < 3 || url[scheme_end] != ':' ||
        url[scheme_end + 1] != '/' || url[scheme_end + 2] != '/') {
        return 0;
    }
    host_start = scheme_end + 3;
    /* A colon can belong to userinfo, not just a port. Inspect the whole
     * authority before interpreting its host. */
    for (size_t i = host_start; i < url_length && url[i] != '/' && url[i] != '?' && url[i] != '#'; ++i)
        if (url[i] == '@') return 0;
    host_end = host_start;
    while (host_end < url_length && url[host_end] != ':' && url[host_end] != '/' &&
           url[host_end] != '?' && url[host_end] != '#') {
        /* URLs carrying credentials are left alone */
        if (url[host_end] == '@') {
            return 0;
        }
        ++host_end;
    }
    rule = tls_fixer_host_map_find(map, url + host_start, host_end - host_start);
    if (rule == NULL) {
        return 0;
    }
    size_t total = url_length - rule->from_length + rule->to_length + 1;
    if (needed != NULL) {
        *needed = total;
    }
    if (output == NULL || capacity < total) {
        return -1;
    }
    for (index = 0; index < host_start; ++index) {
        output[index] = url[index];
    }
    for (index = 0; index < rule->to_length; ++index) {
        output[host_start + index] = rule->to[index];
    }
    for (index = host_end; index <= url_length; ++index) {
        output[host_start + rule->to_length + index - host_end] = url[index];
    }
    return 1;
}
