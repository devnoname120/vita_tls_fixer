/* SPDX-License-Identifier: 0BSD */
#include "cover.h"
#include "json_stream.h"
#include <string.h>

static int upper_digit(char c) { return (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'); }
int store_cover_valid_id(const char *id) {
    if (!id) return 0;
    for (size_t i = 0; i < 36; ++i) {
        if (i == 6 || i == 19) { if (id[i] != '-') return 0; }
        else if (i == 16) { if (id[i] != '_') return 0; }
        else if (!upper_digit(id[i]) && id[i] != '_') return 0;
    }
    return id[36] == 0;
}
int store_cover_valid_url(const char *url) {
    static const char *const prefixes[] = {
        "https://apollo2.dl.playstation.net/", "https://image.api.playstation.com/",
        "https://vulcan.dl.playstation.net/"
    };
    if (!url) return 0;
    size_t n = 0;
    while (n < STORE_COVER_URL_SIZE && url[n]) {
        unsigned char c = (unsigned char)url[n++];
        if (c <= 32 || c >= 127 || c == '\\' || c == '#' || c == '"') return 0;
    }
    if (n == STORE_COVER_URL_SIZE) return 0;
    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); ++i) {
        size_t p = strlen(prefixes[i]);
        if (n > p && memcmp(url, prefixes[i], p) == 0) return 1;
    }
    return 0;
}
static int locale_valid(const char *s) {
    return s && s[0] >= 'a' && s[0] <= 'z' && s[1] >= 'a' && s[1] <= 'z' && s[2] == 0;
}
int store_cover_catalog_path(char *out, size_t capacity, const char *country,
                             const char *language, const char *id) {
    static const char prefix[] = "/store/api/chihiro/00_09_000/container/";
    if (!out || !locale_valid(country) || !locale_valid(language) || !store_cover_valid_id(id)) return -1;
    size_t n = sizeof(prefix) - 1;
    if (capacity < n + 6 + 4 + STORE_COVER_ID_SIZE) return -1;
    memcpy(out, prefix, n);
    memcpy(out + n, country, 2); n += 2; out[n++] = '/';
    memcpy(out + n, language, 2); n += 2; out[n++] = '/';
    memcpy(out + n, "999/", 4); n += 4;
    memcpy(out + n, id, STORE_COVER_ID_SIZE);
    return 0;
}

/* Compatibility wrapper for callers holding a complete document. Native
 * retrieval feeds the same parser directly from each TLS read instead. */
int store_cover_parse(const char *json, size_t length, const char *id, char out[STORE_COVER_URL_SIZE]) {
    StoreJsonStream state;
    if (!out) return -1;
    out[0] = 0;
    if (store_json_init(&state, id) < 0 || store_json_feed(&state, json, length) < 0) return -1;
    return store_json_finish(&state, out);
}

int store_cover_fill(StoreCoverCache *cache, int native_result, const char *id,
                     const char **image, uint64_t now, StoreCoverFetch fetch, void *context) {
    if (!cache || native_result < 0 || !image || (*image && **image) || !store_cover_valid_id(id)) return 0;
    for (StoreCoverEntry *entry = cache->entries; entry; entry = entry->next) {
        if (strcmp(id, entry->id)) continue;
        *image = entry->url; return 1;
    }
    for (size_t i = 0; i < STORE_COVER_NEGATIVE_CACHE_SIZE; ++i)
        if (now < cache->misses[i].retry_after && !strcmp(id, cache->misses[i].id)) return 0;
    if (!fetch || !cache->allocate || now < cache->retry_after) return 0;
    char url[STORE_COVER_URL_SIZE] = {0};
    int rc = fetch(context, id, url);
    if (rc < 0 || !store_cover_valid_url(url)) {
        /* Avoid making every missing cover wait when the public service is down.
         * A successful HTTP response with no image (rc=1) is cached per product. */
        if (rc != 1) { cache->retry_after = now + UINT64_C(60000000); return 0; }
        StoreCoverMiss *miss = &cache->misses[cache->next_miss];
        memcpy(miss->id, id, STORE_COVER_ID_SIZE);
        miss->retry_after = now + UINT64_C(60000000);
        cache->next_miss = (cache->next_miss + 1) % STORE_COVER_NEGATIVE_CACHE_SIZE;
        return 0;
    }
    /* The modern catalog's full-size art can be 1024x1024. The Vita Store uses
     * 160px public HTTP thumbnails. Sony's image service serves the same asset
     * at that size. Only artwork is transformed; metadata stays HTTPS. */
    static const struct { const char *source, *display; } routes[] = {
        {"https://apollo2.dl.playstation.net/", "http://image.api.playstation.com/"},
        {"https://image.api.playstation.com/", "http://image.api.playstation.com/"},
        {"https://vulcan.dl.playstation.net/", "http://image.api.playstation.com/vulcan/"}
    };
    /* Store unconditionally appends "?country=...". The final separator keeps
     * that suffix out of the numeric height value without patching its URL code. */
    static const char dimensions[] = "?w=160&h=160&";
    for (size_t i = 0; i < sizeof(routes) / sizeof(routes[0]); ++i) {
        size_t prefix = strlen(routes[i].source);
        if (memcmp(url, routes[i].source, prefix)) continue;
        const char *asset = url + prefix;
        size_t display_length = strlen(routes[i].display);
        size_t n = 0; while (asset[n] && asset[n] != '?') ++n;
        if (display_length + n + sizeof(dimensions) > sizeof(url)) return 0;
        memmove(url + display_length, asset, n);
        memcpy(url, routes[i].display, display_length);
        memcpy(url + display_length + n, dimensions, sizeof(dimensions));
        break;
    }
    size_t size = strlen(url) + 1;
    StoreCoverEntry *entry = cache->allocate(cache->allocation_context, sizeof(*entry) + size);
    if (!entry) { cache->retry_after = now + UINT64_C(60000000); return 0; }
    memcpy(entry->id, id, STORE_COVER_ID_SIZE);
    memcpy(entry->url, url, size);
    entry->next = cache->entries; cache->entries = entry; ++cache->used;
    *image = entry->url;
    return 1;
}
