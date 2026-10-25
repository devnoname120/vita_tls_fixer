/* SPDX-License-Identifier: 0BSD */
#include "host_redirect.h"

#include "diagnostics.h"
#include "tls_fixer/host_map.h"
#include "tls_fixer/redirect_list.h"

#include <psp2/types.h>
#include <taihen.h>

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
static int g_hook_ids[REDIRECT_COUNT] = {-1, -1, -1};
static tai_hook_ref_t g_hook_refs[REDIRECT_COUNT];

static void *next_hook_function(tai_hook_ref_t reference) {
    struct _tai_hook_user *current = (struct _tai_hook_user *)reference;
    struct _tai_hook_user *next = (struct _tai_hook_user *)current->next;

    return next == NULL ? current->old : next->func;
}
#define REDIRECT_NEXT(index, type) ((type)next_hook_function(g_hook_refs[index]))

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

static int redirect_create_connection(int template_id, const char *server_name, const char *scheme,
    unsigned short port, int keep_alive) {
    const TlsFixerHostRule *rule = server_name == NULL ? NULL
        : tls_fixer_host_map_find(&g_map, server_name, host_length(server_name));
    if (rule != NULL) {
        TLS_FIXER_LOG("redirect host %s -> %s", rule->from, rule->to);
        server_name = rule->to;
    }
    return REDIRECT_NEXT(REDIRECT_CREATE_CONNECTION, int (*)(int, const char *, const char *, unsigned short, int))(
        template_id, server_name, scheme, port, keep_alive);
}

static int redirect_create_connection_with_url(int template_id, const char *url, int keep_alive) {
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

static int redirect_create_request_with_url(int connection_id, int method, const char *url, SceULong64 length) {
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

static const struct {
    uint32_t nid;
    const void *function;
} g_hooks[REDIRECT_COUNT] = {
    [REDIRECT_CREATE_CONNECTION] = {UINT32_C(0xAEB3307E), redirect_create_connection},
    [REDIRECT_CREATE_CONNECTION_WITH_URL] = {UINT32_C(0xC616C200), redirect_create_connection_with_url},
    [REDIRECT_CREATE_REQUEST_WITH_URL] = {UINT32_C(0xBD5DA1D0), redirect_create_request_with_url},
};

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

void tls_fixer_host_redirect_install(void) {
    if (g_names != NULL) return;
    if (load_list() == 0) {
        return;
    }
    TLS_FIXER_LOG("redirects loaded=%u from " TLS_FIXER_REDIRECTS_PATH, (unsigned int)g_map.count);
    for (int i = 0; i < REDIRECT_COUNT; ++i) {
        g_hook_ids[i] = taiHookFunctionExport(&g_hook_refs[i], "SceLibHttp",
            TLS_FIXER_SCE_HTTP_LIBRARY_NID, g_hooks[i].nid, g_hooks[i].function);
        if (g_hook_ids[i] < 0) {
            TLS_FIXER_LOG("redirect hook nid=%08X rc=%08X", g_hooks[i].nid, (unsigned int)g_hook_ids[i]);
            while (i > 0) {
                --i;
                taiHookRelease(g_hook_ids[i], g_hook_refs[i]);
                g_hook_ids[i] = -1;
            }
            memset(&g_map, 0, sizeof(g_map));
            free(g_names);
            g_names = NULL;
            return;
        }
    }
}
