/* SPDX-License-Identifier: 0BSD */
#include "host_redirect.h"

#include "diagnostics.h"
#include "tls_fixer/host_map.h"
#include "tls_fixer/redirect_list.h"

#include <psp2/types.h>
#include "embedded.h"
#include "optional_syscall.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define TLS_FIXER_SCE_HTTP_LIBRARY_NID UINT32_C(0xE8F15CDE)

enum {
    REDIRECT_CREATE_CONNECTION,
    REDIRECT_CREATE_CONNECTION_WITH_URL,
    REDIRECT_CREATE_REQUEST_WITH_URL,
    REDIRECT_COUNT
};

static TlsFixerHostMap g_map;
/* The kept host names, NUL-terminated, which g_map points into; they live as long as the process */
static char *g_names;
#define REDIRECT_NEXT(index, type) ((type)g_tls_fixer_embedded_bindings.redirects[index])

static size_t host_length(const char *host) {
    size_t length = 0;
    while (length <= TLS_FIXER_HOST_MAP_MAX_HOST && host[length] != '\0') {
        ++length;
    }
    return length;
}

/* The URL to pass on: url itself, or a rewritten copy the caller frees through *owned */
static const char *redirect_url(const char *url, char **owned) {
    size_t needed = 0;

    *owned = NULL;
    if (url == NULL || tls_fixer_host_map_rewrite_url(&g_map, url, NULL, 0, &needed) != -1) {
        return url;
    }
    char *copy = malloc(needed);
    if (copy == NULL || tls_fixer_host_map_rewrite_url(&g_map, url, copy, needed, &needed) != 1) {
        TLS_FIXER_LOG("redirect skipped: no memory for a %u-byte URL", (unsigned int)needed);
        free(copy);
        return url;
    }
    *owned = copy;
    return copy;
}

int tls_fixer_embedded_redirect_connection(int template_id, const char *server_name, const char *scheme,
    unsigned short port, int keep_alive) {
    TLS_FIXER_LOG("event=connection.host template=%08X host=%s scheme=%s port=%u", template_id,
        server_name ? server_name : "(null)", scheme ? scheme : "(null)", port);
    const TlsFixerHostRule *rule = server_name == NULL ? NULL
        : tls_fixer_host_map_find(&g_map, server_name, host_length(server_name));
    if (rule != NULL) {
        TLS_FIXER_LOG("redirect host %s -> %s", rule->from, rule->to);
        server_name = rule->to;
    }
    return REDIRECT_NEXT(REDIRECT_CREATE_CONNECTION, int (*)(int, const char *, const char *, unsigned short, int))(
        template_id, server_name, scheme, port, keep_alive);
}

int tls_fixer_embedded_redirect_connection_url(int template_id, const char *url, int keep_alive) {
    TLS_FIXER_LOG("event=connection.url template=%08X url=%s", template_id, url ? url : "(null)");
    char *owned;
    const char *target = redirect_url(url, &owned);
    if (owned != NULL) {
        TLS_FIXER_LOG("redirect connection %s -> %s", url, target);
    }
    int result = REDIRECT_NEXT(REDIRECT_CREATE_CONNECTION_WITH_URL, int (*)(int, const char *, int))(
        template_id, target, keep_alive);
    free(owned);
    return result;
}

int tls_fixer_embedded_redirect_request_url(int connection_id, int method, const char *url, SceULong64 length) {
    TLS_FIXER_LOG("event=request.url connection=%08X method=%d url=%s", connection_id, method,
        url ? url : "(null)");
    char *owned;
    const char *target = redirect_url(url, &owned);
    if (owned != NULL) {
        TLS_FIXER_LOG("redirect request %s -> %s", url, target);
    }
    int result = REDIRECT_NEXT(REDIRECT_CREATE_REQUEST_WITH_URL, int (*)(int, int, const char *, SceULong64))(
        connection_id, method, target, length);
    free(owned);
    return result;
}

/* Host names collected while reading: each rule's two names are appended to names */
typedef struct ListReader {
    char *names;
    size_t used;
    size_t from[TLS_FIXER_HOST_MAP_MAX_RULES], to[TLS_FIXER_HOST_MAP_MAX_RULES];
    size_t from_length[TLS_FIXER_HOST_MAP_MAX_RULES], to_length[TLS_FIXER_HOST_MAP_MAX_RULES];
    size_t count;
    int failed;
} ListReader;

/* Keeps one pair from the list; stops the reading once the list is full or memory runs out */
static int keep_rule(void *context, const TlsFixerHostRule *rule) {
    ListReader *reader = context;
    char *grown = realloc(reader->names, reader->used + rule->from_length + rule->to_length + 2u);
    if (grown == NULL) {
        reader->failed = 1;
        return 1;
    }
    reader->names = grown;
    reader->from[reader->count] = reader->used;
    reader->from_length[reader->count] = rule->from_length;
    memcpy(grown + reader->used, rule->from, rule->from_length);
    reader->used += rule->from_length;
    grown[reader->used++] = '\0';
    reader->to[reader->count] = reader->used;
    reader->to_length[reader->count] = rule->to_length;
    memcpy(grown + reader->used, rule->to, rule->to_length);
    reader->used += rule->to_length;
    grown[reader->used++] = '\0';
    return ++reader->count == TLS_FIXER_HOST_MAP_MAX_RULES;
}

/* Reads the list into g_map; returns the number of rules, 0 when the list is missing, empty or
 * unreadable (a read error discards the whole list) */
static size_t load_list(void) {
    size_t loaded = 0;

    /* Working memory comes from the provider's heap, not the stack, and is freed after reading */
    ListReader *reader = calloc(1, sizeof(*reader));
    char *work = malloc(TLS_FIXER_REDIRECT_LIST_WORK_SIZE);
    if (reader == NULL || work == NULL) {
        free(reader);
        free(work);
        return 0;
    }
    int result = tls_fixer_redirect_list_read(tls_fixer_redirects_read, work, keep_rule, reader);
    free(work);
    if (result < 0) {
        /* 0x80010002 is a missing list */
        TLS_FIXER_LOG("redirect list not read: rc=%08X path=" TLS_FIXER_REDIRECTS_PATH, (unsigned int)result);
        reader->failed = 1;
    }
    if (!reader->failed && reader->count > 0) {
        for (size_t i = 0; i < reader->count; ++i) {
            g_map.rules[i] = (TlsFixerHostRule){reader->names + reader->from[i], reader->names + reader->to[i],
                reader->from_length[i], reader->to_length[i]};
        }
        g_map.count = reader->count;
        g_names = reader->names;
        loaded = reader->count;
    } else {
        free(reader->names);
    }
    free(reader);
    return loaded;
}

void tls_fixer_embedded_redirect_init(void) {
    const uintptr_t stub = (uintptr_t)tls_fixer_redirects_read;
    int bound = (stub & 3u) == 0 && tls_fixer_syscall_stub_bound((const uint32_t *)stub);
    TLS_FIXER_LOG("event=redirect.bridge bound=%d", bound);
    if (!bound) return;
    if (g_names == NULL) (void)load_list();
}

void tls_fixer_embedded_redirect_destroy(void) {
    free(g_names);
    g_names = NULL;
    memset(&g_map, 0, sizeof(g_map));
}
