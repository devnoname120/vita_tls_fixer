/* SPDX-License-Identifier: 0BSD */
#include "http.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define ID "EP0001-CUSA00001_00-ABCDEFGHIJKLMNOP"
#define URL "https://apollo2.dl.playstation.net/cdn/EP0001/cover.png"
#define BODY "{\"id\":\"" ID "\",\"images\":[{\"url\":\"" URL "\",\"type\":10}]}"

static int parse(const char *data, size_t size, size_t chunk, char *out) {
    StoreCoverResponse response;
    assert(store_response_init(&response, ID) == 0);
    out[0] = 0;
    for (size_t at = 0; at < size;) {
        size_t n = size - at < chunk ? size - at : chunk;
        if (store_response_feed(&response, data + at, n) < 0) return -1;
        at += n;
    }
    /* Simulate EOF. This must not bless a partial body. */
    return store_response_finish(&response, out);
}
static void header_tests(void) {
    const char header[] = "HTTP/1.0 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\r\n";
    StoreHttpHeaders s;
    size_t used;
    store_http_init(&s);
    for (size_t i = 0; i < strlen(header); ++i) {
        int rc = store_http_feed(&s, header + i, 1, &used);
        assert(used == 1 && rc == (i + 1 == strlen(header) ? 1 : 0));
    }
    assert(s.code == 200 && s.have_length && s.content_length == 2);
    assert(store_http_feed(&s, "{}", 2, &used) == 1 && used == 0);
    const char *bad[] = {
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551616\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: \r\n\r\n",
        "HTTP/2.0 200 OK\r\n\r\n",
        "HTTP/1.1 20a OK\r\n\r\n",
        "HTTP/1.1 200 OK\r\nX: y\n\r\n",
        "HTTP/1.1 200 OK\r\nX: y\rz\r\n\r\n",
        "HTTP/1.1 200 OK\r\n folded: y\r\n\r\n",
        "HTTP/1.1 200 OK\r\ninvalid\r\n\r\n"
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        store_http_init(&s);
        assert(store_http_feed(&s, bad[i], strlen(bad[i]), &used) < 0);
    }
    /* Ignore a long CDN cookie without retaining it or rejecting later fields. */
    store_http_init(&s);
    const char first[] = "HTTP/1.0 200 OK\r\nSet-Cookie: ";
    assert(store_http_feed(&s, first, strlen(first), &used) == 0);
    for (size_t i = 0; i < 3000; ++i) assert(store_http_feed(&s, "x", 1, &used) == 0);
    const char end[] = "\r\ncOnTeNt-LeNgTh:\t2 \t\r\nContent-Encoding: identity\r\n\r\n{}";
    assert(store_http_feed(&s, end, strlen(end), &used) == 1);
    assert(used == strlen(end) - 2 && s.have_length && s.content_length == 2);
    store_http_init(&s);
    char *large = malloc(STORE_COVER_HEADER_LIMIT);
    assert(large); memset(large, 'x', STORE_COVER_HEADER_LIMIT);
    assert(store_http_feed(&s, large, STORE_COVER_HEADER_LIMIT, &used) < 0);
    free(large);
}
static void body_tests(void) {
    char data[1024], out[STORE_COVER_URL_SIZE];
    int n = snprintf(data, sizeof(data), "HTTP/1.0 200 OK\r\nContent-Length: %zu\r\n\r\n%s", strlen(BODY), BODY);
    assert(n > 0 && (size_t)n < sizeof(data));
    for (size_t chunk = 1; chunk <= (size_t)n; ++chunk)
        assert(parse(data, (size_t)n, chunk, out) == 0 && !strcmp(out, URL));
    for (size_t i = 0; i < (size_t)n; ++i) assert(parse(data, i, 1, out) < 0 && !out[0]);
    data[n] = 'x';
    assert(parse(data, (size_t)n + 1, 1, out) < 0);
    /* HTTP/1.0 without Content-Length completes at EOF, independently of size. */
    const char closed[] = "HTTP/1.0 200 OK\r\nConnection: close\r\n\r\n" BODY;
    for (size_t chunk = 1; chunk <= strlen(closed); ++chunk)
        assert(parse(closed, strlen(closed), chunk, out) == 0 && !strcmp(out, URL));
    for (size_t i = 0; i < strlen(closed); ++i) assert(parse(closed, i, 1, out) < 0);
    const char *missing[] = {
        "HTTP/1.0 404 Not Found\r\nContent-Length: 400\r\n\r\n",
        "HTTP/1.0 410 Gone\r\n\r\n",
        "HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\n{}"
    };
    for (size_t i = 0; i < sizeof(missing) / sizeof(missing[0]); ++i)
        assert(parse(missing[i], strlen(missing[i]), 1, out) == 1 && !out[0]);
    const char *bad[] = {
        "HTTP/1.0 302 Found\r\nLocation: https://example.test/\r\n\r\n",
        "HTTP/1.0 503 Unavailable\r\n\r\n",
        "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.0 200 OK\r\nContent-Length: 999999999999999999\r\n\r\n" BODY,
        "HTTP/1.0 200 OK\r\n\r\n" BODY "x"
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i)
        assert(parse(bad[i], strlen(bad[i]), 1, out) < 0 && !out[0]);
    /* Every mutated byte has the same outcome in a single read and byte reads. */
    n = snprintf(data, sizeof(data), "HTTP/1.0 200 OK\r\nContent-Length: %zu\r\n\r\n%s", strlen(BODY), BODY);
    for (size_t i = 0; i < (size_t)n; ++i) for (unsigned c = 0; c < 256; ++c) {
        char mutation[1024], other[STORE_COVER_URL_SIZE];
        memcpy(mutation, data, (size_t)n); mutation[i] = (char)c;
        int a = parse(mutation, (size_t)n, 1, out);
        int b = parse(mutation, (size_t)n, (size_t)n, other);
        assert(a == b && !strcmp(out, other));
    }
    /* No response-sized allocation, even beyond the previous 256KiB ceiling. */
    for (unsigned length_header = 0; length_header < 2; ++length_header) {
        StoreCoverResponse response;
        assert(store_response_init(&response, ID) == 0);
        size_t total = strlen(BODY) + 4 * 1024 * 1024;
        n = length_header ? snprintf(data, sizeof(data), "HTTP/1.0 200 OK\r\nContent-Length: %zu\r\n\r\n", total)
                          : snprintf(data, sizeof(data), "HTTP/1.0 200 OK\r\n\r\n");
        assert(store_response_feed(&response, data, (size_t)n) == 0);
        assert(store_response_feed(&response, BODY, strlen(BODY)) == 0);
        memset(data, ' ', sizeof(data));
        for (unsigned i = 0; i < 4096; ++i)
            assert(store_response_feed(&response, data, sizeof(data)) == (length_header && i == 4095 ? 1 : 0));
        assert(response.received == total && store_response_finish(&response, out) == 0 && !strcmp(out, URL));
    }
}
int main(int argc, char **argv) {
    header_tests(); body_tests();
    if (argc == 3) {
        StoreCoverResponse response; char buffer[4096], url[STORE_COVER_URL_SIZE];
        FILE *f = fopen(argv[1], "rb"); assert(f);
        assert(store_response_init(&response, argv[2]) == 0);
        size_t n;
        while ((n = fread(buffer, 1, sizeof(buffer), f))) assert(store_response_feed(&response, buffer, n) >= 0);
        assert(!ferror(f)); fclose(f);
        assert(store_response_finish(&response, url) == 0); puts(url);
    }
    printf("Store streaming HTTP/JSON contracts passed; response state=%zu bytes\n", sizeof(StoreCoverResponse));
    return 0;
}
