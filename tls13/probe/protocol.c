#include "protocol.h"
#include <stdio.h>
#include <string.h>

static int alnum_ascii(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
}

int tls_fixer_probe_dns_name(const char *name) {
    size_t label = 0, i;
    if (name == NULL || *name == '\0') return 0;
    for (i = 0; i < 254 && name[i] != '\0'; ++i) {
        unsigned char c = (unsigned char)name[i];
        if (c == '.') {
            if (label == 0 || name[i - 1] == '-') return 0;
            label = 0;
        } else {
            if ((!alnum_ascii(c) && c != '-') || (label == 0 && c == '-') || ++label > 63) return 0;
        }
    }
    return i <= 253 && label != 0 && name[i - 1] != '-';
}

int tls_fixer_probe_nonce_valid(const char *nonce) {
    if (nonce == NULL) return 0;
    for (size_t i = 0; i < TLS_FIXER_PROBE_NONCE_SIZE; ++i)
        if (!((nonce[i] >= '0' && nonce[i] <= '9') || (nonce[i] >= 'a' && nonce[i] <= 'f'))) return 0;
    return nonce[TLS_FIXER_PROBE_NONCE_SIZE] == '\0';
}

int tls_fixer_probe_request(const char *name, unsigned int port, const char *nonce, char *output, size_t capacity) {
    if (!tls_fixer_probe_dns_name(name) || !tls_fixer_probe_nonce_valid(nonce) || port == 0 || port > 65535 ||
        output == NULL || capacity == 0 || capacity > TLS_FIXER_PROBE_REQUEST_LIMIT) return -1;
    int length = snprintf(output, capacity,
        "GET /?tls_fixer_probe=%s HTTP/1.1\r\nHost: %s:%u\r\nConnection: close\r\nCache-Control: no-cache\r\n\r\n",
        nonce, name, port);
    if (length <= 0 || (size_t)length >= capacity) { output[0] = '\0'; return -1; }
    return length;
}

static size_t find_crlf(const unsigned char *data, size_t begin, size_t end) {
    for (size_t i = begin; i + 1 < end; ++i)
        if (data[i] == '\r' && data[i + 1] == '\n') return i;
    return end;
}

static int header_equal(const unsigned char *data, size_t size, const char *expected) {
    if (strlen(expected) != size) return 0;
    for (size_t i = 0; i < size; ++i) {
        unsigned char c = data[i];
        if (c >= 'A' && c <= 'Z') c = (unsigned char)(c + ('a' - 'A'));
        if (c != (unsigned char)expected[i]) return 0;
    }
    return 1;
}

int tls_fixer_probe_response(const unsigned char *data, size_t size, const char *nonce, size_t *complete_size) {
    size_t header_end = 0, length = 0, cursor;
    int have_length = 0, have_nonce = 0;
    if (complete_size == NULL || (data == NULL && size != 0) || size > TLS_FIXER_PROBE_RESPONSE_LIMIT ||
        !tls_fixer_probe_nonce_valid(nonce)) return -1;
    *complete_size = 0;
    for (size_t i = 0; i + 3 < size; ++i) {
        if (memcmp(data + i, "\r\n\r\n", 4) == 0) { header_end = i + 4; break; }
    }
    if (header_end == 0) return size == TLS_FIXER_PROBE_RESPONSE_LIMIT ? -1 : 0;
    for (size_t i = 0; i < header_end; ++i) {
        unsigned char c = data[i];
        if (c == '\r' && (i + 1 == header_end || data[i + 1] != '\n')) return -1;
        if (c == '\n' && (i == 0 || data[i - 1] != '\r')) return -1;
        if (c != '\r' && c != '\n' && c != '\t' && (c < 32 || c > 126)) return -1;
    }
    cursor = find_crlf(data, 0, header_end);
    if (cursor < 12 || cursor == header_end || memcmp(data, "HTTP/1.1 200 ", 12) != 0) return -1;
    cursor += 2;
    while (cursor < header_end - 2) {
        size_t end = find_crlf(data, cursor, header_end), colon = cursor;
        if (end == header_end) return -1;
        while (colon < end && data[colon] != ':') {
            if (!alnum_ascii(data[colon]) && data[colon] != '-') return -1;
            ++colon;
        }
        if (colon == cursor || colon == end) return -1;
        size_t value = colon + 1, value_end = end;
        while (value < end && (data[value] == ' ' || data[value] == '\t')) ++value;
        while (value_end > value && (data[value_end - 1] == ' ' || data[value_end - 1] == '\t')) --value_end;
        if (header_equal(data + cursor, colon - cursor, "transfer-encoding")) return -1;
        if (header_equal(data + cursor, colon - cursor, "content-length")) {
            if (have_length++ || value == value_end) return -1;
            for (size_t i = value; i < value_end; ++i) {
                if (data[i] < '0' || data[i] > '9' || length > TLS_FIXER_PROBE_RESPONSE_LIMIT / 10) return -1;
                length = length * 10 + (size_t)(data[i] - '0');
                if (length > TLS_FIXER_PROBE_RESPONSE_LIMIT) return -1;
            }
        }
        if (header_equal(data + cursor, colon - cursor, "x-tls-fixer-probe-nonce")) {
            if (have_nonce++ || value_end - value != TLS_FIXER_PROBE_NONCE_SIZE ||
                memcmp(data + value, nonce, TLS_FIXER_PROBE_NONCE_SIZE) != 0) return -1;
        }
        cursor = end + 2;
    }
    if (!have_length || !have_nonce || length > TLS_FIXER_PROBE_RESPONSE_LIMIT - header_end) return -1;
    *complete_size = header_end + length;
    return size > *complete_size ? -1 : size == *complete_size ? 1 : 0;
}
