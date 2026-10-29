/* SPDX-License-Identifier: 0BSD */
#include "cover.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ID "EP0001-CUSA00001_00-ABCDEFGHIJKLMNOP"
#define URL "https://apollo2.dl.playstation.net/cdn/EP0001/CUSA00001_00/cover.png"
#define DISPLAY_URL "http://image.api.playstation.com/cdn/EP0001/CUSA00001_00/cover.png?w=160&h=160&"
#define GOOD "{\"images\":[{\"type\":10,\"url\":\"" URL "\"}],\"id\":\"" ID "\"}"
static unsigned fetches;
static int response;
static const char *fetch_url = URL;
static int fetch(void *context, const char *id, char *out) {
    assert(context == &fetches); assert(store_cover_valid_id(id)); ++fetches;
    if (!response) strcpy(out, fetch_url);
    return response;
}
static void parser_tests(void) {
    char out[STORE_COVER_URL_SIZE];
    assert(store_cover_parse(GOOD, strlen(GOOD), ID, out) == 0 && !strcmp(out, URL));
    /* Every truncated response must fail without publishing a partial URL. */
    for (size_t i = 0; i < strlen(GOOD); ++i) {
        char *exact = malloc(i ? i : 1); memcpy(exact, GOOD, i);
        assert(store_cover_parse(exact, i, ID, out) < 0 && !out[0]); free(exact);
    }
    const char *bad[] = {
        GOOD "x", "{\"id\":\"" ID "\",\"links\":[" GOOD "]}",
        "{\"id\":\"UP0001-CUSA00001_00-ABCDEFGHIJKLMNOP\",\"images\":[{\"type\":10,\"url\":\"" URL "\"}]}",
        "{\"id\":\"" ID "\",\"images\":[{\"type\":11,\"url\":\"" URL "\"}]}",
        "{\"id\":\"" ID "\",\"images\":[{\"type\":10,\"url\":\"http://apollo2.dl.playstation.net/a\"}]}",
        "{\"id\":\"" ID "\",\"id\":\"" ID "\",\"images\":[]}",
        "{\"id\":\"" ID "\",\"images\":[{\"type\":10,\"type\":10,\"url\":\"" URL "\"}]}",
        "{\"id\":\"" ID "\",\"images\":[{\"type\":10,\"url\":\"" URL "\"},]}",
        "{\"id\":\"" ID "\",\"images\":[]}", "{}", "[]", "null", "{\"id\":false}",
        "{\"x\":01}", "{\"x\":1.}", "{\"x\":1e}", "{\"x\":tru}", "{\"x\":\"\\z\"}",
        "{\"x\":\"\n\"}", "{\"images\":null}", "{\"images\":[null]}"
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i)
        assert(store_cover_parse(bad[i], strlen(bad[i]), ID, out) < 0 && !out[0]);
    const char escaped[] = "{\"other\":{\"id\":false,\"n\":-0.2e+2,\"a\":[true,false,null,\"\\u00e9\"]},"
        "\"id\":\"" ID "\",\"images\":[{\"url\":\"https:\\/\\/image.api.playstation.com\\/cdn\\/cover.png\",\"type\":10}]}";
    assert(store_cover_parse(escaped, strlen(escaped), ID, out) == 0);
    assert(!strcmp(out, "https://image.api.playstation.com/cdn/cover.png"));
    const char vulcan[] = "{\"id\":\"" ID "\",\"images\":[{\"type\":10,\"url\":\"https://vulcan.dl.playstation.net/img/cfn/cover.png\"}]}";
    assert(store_cover_parse(vulcan, strlen(vulcan), ID, out) == 0);
    assert(!strcmp(out, "https://vulcan.dl.playstation.net/img/cfn/cover.png"));
    /* A DLC-heavy product response must not be rejected at the old 64KiB limit. */
    size_t large_size = 102011;
    char *large_json = malloc(large_size); assert(large_json);
    memset(large_json, ' ', large_size); memcpy(large_json, GOOD, strlen(GOOD));
    assert(store_cover_parse(large_json, large_size, ID, out) == 0);
    free(large_json);
    char nested[256]; memset(nested, '[', 40); memset(nested + 40, ']', 40); nested[80] = 0;
    assert(store_cover_parse(nested, 80, ID, out) < 0);
    /* Mutations exercise malformed strings, delimiters and primitive values. */
    char mutation[sizeof(GOOD)];
    for (size_t i = 0; i < sizeof(GOOD) - 1; ++i) for (unsigned c = 0; c < 256; ++c) {
        memcpy(mutation, GOOD, sizeof(GOOD)); mutation[i] = (char)c;
        int rc = store_cover_parse(mutation, sizeof(GOOD) - 1, ID, out);
        assert(rc < 0 || store_cover_valid_url(out));
    }
}
static int allocation_fails;
static void *allocate(void *context, size_t size) {
    assert(context == NULL);
    return allocation_fails ? NULL : malloc(size);
}
static void clear_cache(StoreCoverCache *cache) {
    StoreCoverEntry *entry = cache->entries;
    while (entry) { StoreCoverEntry *next = entry->next; free(entry); entry = next; }
    memset(cache, 0, sizeof(*cache)); cache->allocate = allocate;
}
static void cache_tests(void) {
    StoreCoverCache cache = {.allocate = allocate}; const char *image = "";
    fetches = 0; response = 0;
    assert(!store_cover_fill(&cache, -1, ID, &image, 0, fetch, &fetches));
    assert(!store_cover_fill(&cache, 0, "invalid", &image, 0, fetch, &fetches));
    image = "https://existing.example/cover.png"; const char *original = image;
    assert(!store_cover_fill(&cache, 0, ID, &image, 0, fetch, &fetches) && image == original && fetches == 0);
    image = NULL;
    assert(store_cover_fill(&cache, 0x22, ID, &image, 0, fetch, &fetches) && fetches == 1 && !strcmp(image, DISPLAY_URL));
    original = image; image = "";
    char requested[STORE_COVER_URL_SIZE + 32];
    snprintf(requested, sizeof(requested), "%s?country=fr", original);
    assert(strstr(requested, "?w=160&h=160&?country=fr") != NULL);
    assert(store_cover_fill(&cache, 0, ID, &image, 0, fetch, &fetches) && image == original && fetches == 1);
    /* Browse well beyond the former 48 entries. Earlier URL pointers must
     * remain valid, and revisiting an old product must not fetch it again. */
    for (unsigned i = 1; i < 1000; ++i) {
        char id[STORE_COVER_ID_SIZE]; snprintf(id, sizeof(id), "EP0001-CUSA%05u_00-ABCDEFGHIJKLMNOP", i + 1);
        image = ""; assert(store_cover_fill(&cache, 0, id, &image, 0, fetch, &fetches));
    }
    assert(cache.used == 1000 && fetches == 1000 && !strcmp(original, DISPLAY_URL));
    image = ""; assert(store_cover_fill(&cache, 0, ID, &image, 0, fetch, &fetches));
    assert(image == original && fetches == 1000);
    clear_cache(&cache); fetches = 0; response = -1; image = "";
    assert(!store_cover_fill(&cache, 0, ID, &image, 1, fetch, &fetches));
    assert(!store_cover_fill(&cache, 0, ID, &image, 2, fetch, &fetches) && fetches == 1);
    response = 0;
    assert(store_cover_fill(&cache, 0, ID, &image, 60000001, fetch, &fetches) && fetches == 2);
    clear_cache(&cache); fetches = 0; response = 1; image = "";
    /* Missing/retired products cannot consume successful-cover capacity. */
    for (unsigned i = 0; i < 200; ++i) {
        char id[STORE_COVER_ID_SIZE]; snprintf(id, sizeof(id), "EP0001-CUSA%05u_00-ABCDEFGHIJKLMNOP", i + 100);
        assert(!store_cover_fill(&cache, 0, id, &image, 0, fetch, &fetches));
    }
    assert(cache.used == 0 && cache.entries == NULL && fetches == 200);
    assert(!store_cover_fill(&cache, 0, ID, &image, 0, fetch, &fetches));
    assert(!store_cover_fill(&cache, 0, ID, &image, 1, fetch, &fetches) && fetches == 201);
    response = 0;
    assert(store_cover_fill(&cache, 0, ID, &image, 60000001, fetch, &fetches) && fetches == 202);
    clear_cache(&cache); image = ""; allocation_fails = 1;
    assert(!store_cover_fill(&cache, 0, ID, &image, 0, fetch, &fetches));
    assert(image[0] == 0 && cache.used == 0 && cache.entries == NULL);
    allocation_fails = 0;
    assert(store_cover_fill(&cache, 0, ID, &image, 60000001, fetch, &fetches));
    clear_cache(&cache);
    static const char *const sources[] = {
        "https://vulcan.dl.playstation.net/img/cfn/cover.png",
        "https://image.api.playstation.com/vulcan/img/cfn/cover.png?w=1024",
        "https://vulcan.dl.playstation.net/ap/rnd/202001/cover.png"
    };
    static const char *const displayed[] = {
        "http://image.api.playstation.com/vulcan/img/cfn/cover.png?w=160&h=160&",
        "http://image.api.playstation.com/vulcan/img/cfn/cover.png?w=160&h=160&",
        "http://image.api.playstation.com/vulcan/ap/rnd/202001/cover.png?w=160&h=160&"
    };
    for (size_t i = 0; i < sizeof(sources)/sizeof(sources[0]); ++i) {
        fetch_url = sources[i]; image = "";
        assert(store_cover_fill(&cache, 0, ID, &image, 0, fetch, &fetches));
        assert(!strcmp(image, displayed[i]));
        clear_cache(&cache);
    }
    fetch_url = URL;
}

int main(void) {
    char path[160];
    assert(store_cover_valid_id(ID));
    assert(!store_cover_valid_id("EP0001-CUSA00001_00-ABCDEFGHIJKLMNO/"));
    assert(!store_cover_valid_id("EP0001-PCSB00963_00-G000000000000885extra"));
    assert(store_cover_catalog_path(path, sizeof(path), "fr", "fr", ID) == 0);
    assert(!strcmp(path, "/store/api/chihiro/00_09_000/container/fr/fr/999/" ID));
    assert(store_cover_catalog_path(path, 20, "fr", "fr", ID) < 0);
    assert(store_cover_catalog_path(path, sizeof(path), "../", "fr", ID) < 0);
    assert(!store_cover_valid_url("https://apollo2.dl.playstation.net.evil.example/a"));
    assert(!store_cover_valid_url("https://apollo2.dl.playstation.net@evil.example/a"));
    assert(!store_cover_valid_url("https://apollo2.dl.playstation.net/a\r\nCookie:x"));
    assert(!store_cover_valid_url("https://vulcan.dl.playstation.net.evil.example/a"));
    assert(!store_cover_valid_url("https://vulcan.dl.playstation.net@evil.example/a"));
    parser_tests(); cache_tests(); puts("Store artwork contracts passed");
    return 0;
}
