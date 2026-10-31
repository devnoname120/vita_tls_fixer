/* SPDX-License-Identifier: 0BSD */
#ifndef TLS_FIXER_STORE_JSON_STREAM_H
#define TLS_FIXER_STORE_JSON_STREAM_H
#include "cover.h"
#define STORE_JSON_DEPTH 24u
/* Fixed storage regardless of description, DLC-list or response length. */
typedef struct { unsigned char kind, state, role, key, seen, type10; } StoreJsonFrame;
typedef struct {
    StoreJsonFrame frames[STORE_JSON_DEPTH];
    unsigned depth, lex, escape, unicode_left, unicode_value, number_state;
    unsigned token_length, token_overflow, capture, string_is_key;
    unsigned literal_position, literal_kind, done, error, root_seen;
    char token[STORE_COVER_URL_SIZE];
    char expected[STORE_COVER_ID_SIZE], product[STORE_COVER_ID_SIZE];
    char candidate[STORE_COVER_URL_SIZE], image[STORE_COVER_URL_SIZE];
} StoreJsonStream;
int store_json_init(StoreJsonStream *state, const char *product_id);
int store_json_feed(StoreJsonStream *state, const char *bytes, size_t length);
/* Finish only when HTTP framing confirms the complete body was received. */
int store_json_finish(const StoreJsonStream *state, char out[STORE_COVER_URL_SIZE]);
#endif
