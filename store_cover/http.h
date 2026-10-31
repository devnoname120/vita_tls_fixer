/* SPDX-License-Identifier: 0BSD */
#ifndef TLS_FIXER_STORE_COVER_HTTP_H
#define TLS_FIXER_STORE_COVER_HTTP_H
#include <stddef.h>
#include <stdint.h>
#include "json_stream.h"
#define STORE_COVER_HEADER_LIMIT (16u * 1024u)
typedef struct {
    uint64_t content_length;
    size_t bytes, line_length;
    unsigned code, have_length, ready, error, first, cr, overflow;
    char line[256];
} StoreHttpHeaders;
void store_http_init(StoreHttpHeaders *state);
/* Consume only headers. Bytes after *consumed belong to the JSON body.
 * HTTP/1.0 may omit Content-Length and delimit its body by connection close. */
int store_http_feed(StoreHttpHeaders *state, const char *data, size_t size, size_t *consumed);
/* Complete-response state without retaining the body. Result is exposed only
 * after a Content-Length boundary or an actual connection close. */
typedef struct {
    StoreHttpHeaders headers;
    StoreJsonStream json;
    uint64_t received;
    unsigned error;
} StoreCoverResponse;
int store_response_init(StoreCoverResponse *state, const char *id);
/* -1: invalid, 0: more input needed, 1: declared body/status complete. */
int store_response_feed(StoreCoverResponse *state, const char *data, size_t size);
/* Call at a declared boundary or EOF. 0: cover, 1: no cover, -1: failure. */
int store_response_finish(StoreCoverResponse *state, char out[STORE_COVER_URL_SIZE]);
#endif
