/* SPDX-License-Identifier: 0BSD */
#ifndef TLS_FIXER_STORE_COVER_H
#define TLS_FIXER_STORE_COVER_H
#include <stddef.h>
#include <stdint.h>

#define STORE_COVER_ID_SIZE 37u
#define STORE_COVER_URL_SIZE 384u
#define STORE_COVER_NEGATIVE_CACHE_SIZE 48u

int store_cover_valid_id(const char *id);
int store_cover_valid_url(const char *url);
int store_cover_catalog_path(char *out, size_t capacity, const char *country,
                             const char *language, const char *id);
/* Only the root product's type-10 image is accepted, never a related product. */
int store_cover_parse(const char *json, size_t length, const char *id,
                      char out[STORE_COVER_URL_SIZE]);

typedef struct StoreCoverEntry {
    struct StoreCoverEntry *next;
    char id[STORE_COVER_ID_SIZE];
    char url[];
} StoreCoverEntry;
typedef struct {
    char id[STORE_COVER_ID_SIZE];
    uint64_t retry_after;
} StoreCoverMiss;
typedef struct {
    StoreCoverEntry *entries;
    size_t used;
    uint64_t retry_after;
    StoreCoverMiss misses[STORE_COVER_NEGATIVE_CACHE_SIZE];
    size_t next_miss;
    void *(*allocate)(void *context, size_t size);
    void *allocation_context;
} StoreCoverCache;
typedef int (*StoreCoverFetch)(void *context, const char *id, char *url);
/* Caller serializes access. Published URLs live until process exit and are
 * never evicted, since Commerce outputs contain borrowed string pointers.
 * Successful entries allocate only the space needed for their URL. Failed
 * lookups use a separate rotating cache and cannot exhaust successful entries. */
int store_cover_fill(StoreCoverCache *cache, int native_result, const char *id,
                     const char **image, uint64_t now, StoreCoverFetch fetch, void *context);
#endif
