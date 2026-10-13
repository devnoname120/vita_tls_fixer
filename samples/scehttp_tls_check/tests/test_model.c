#include "model.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static const char json[] =
    "{\"tls\":{\"selected_version\":{\"id\":772,\"name\":\"TLS "
    "1.3\"},\"record_version\":{\"id\":769,\"name\":\"TLS "
    "1.0\"},\"handshake_version\":{\"id\":771,\"name\":\"TLS "
    "1.2\"},\"cipher_suite\":{\"id\":4865,\"name\":\"TLS_AES_128_GCM_SHA256\"},\"cipher_suites\":[{"
    "\"id\":4866,\"name\":\"TLS_AES_256_GCM_SHA384\"}],\"extensions\":[{\"id\":10,\"name\":"
    "\"supported_groups\",\"data\":{\"named_group_list\":[{\"id\":29,\"name\":\"x25519\"}]}}]},"
    "\"ja3_hash\":\"example\"}";
int main(int argc, char **argv) {
    CheckHandshake h;
    assert(check_parse_browserleaks(json, strlen(json), &h) == 0);
    assert(h.version.id == 772 && h.cipher.id == 4865 && h.ciphers[0].id == 4866);
    assert(h.group_count == 1 && h.groups[0].id == 29 && h.extension_count == 1);
    assert(!strcmp(h.ja3, "example"));
    /* Record/ClientHello legacy_version are not the negotiated TLS version. */
    const char *bad[] = {
        "{}",
        "{\"tls\":null}",
        "{\"tls\":{\"selected_version\":{\"id\":772,\"id\":769,\"name\":\"TLS 1.3\"}}}",
        "{\"bad\": [1,]}",
        "{\"bad\":01}",
        "{\"bad\":trueX}",
        "{\"bad\":\"\\uZZZZ\"}"};
    for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i)
        assert(check_parse_browserleaks(bad[i], strlen(bad[i]), &h) < 0);
    for (size_t n = 0; n < strlen(json); ++n)
        assert(check_parse_browserleaks(json, n, &h) < 0);
    char copy[sizeof(json) + 20];
    snprintf(copy, sizeof(copy), "%s trailing", json);
    assert(check_parse_browserleaks(copy, strlen(copy), &h) < 0);
    memcpy(copy, json, sizeof(json));
    copy[15] = 0;
    assert(check_parse_browserleaks(copy, strlen(json), &h) < 0);
    assert(check_protocol_body(0, "TLS 1.0", 7));
    assert(check_protocol_body(3, "TLS 1.3\r\n", 9));
    assert(!check_protocol_body(3, "TLS 1.2", 7));
    assert(!check_protocol_body(1, "<html>login</html>", 18));
    assert(!check_protocol_body(1, "TLS 1.1junk", 11));
    assert(!check_image_body((const unsigned char *)"<html>portal</html>", 19));
    const unsigned char png[33] = {137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13,
                                   73,  72, 68, 82, 0,  0,  0,  1,  0, 0, 0, 1};
    assert(check_image_body(png, sizeof(png)));
    const char *html = "<table>Cipher Suites (in order of preference)<td>TLS_AES_128_GCM_SHA256 "
                       "(<code>0x1301</code>)</td><td>TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 "
                       "(<code>0xc02f</code>)</td></table><p>TLS_FAKE (<code>0xffff</code>)</p>";
    assert(check_parse_ssllabs(html, strlen(html), &h) == 0 && h.cipher_count == 2 &&
           h.tls13_offered);
    assert(h.ciphers[0].id == 0x1301 && h.ciphers[1].id == 0xc02f && h.version.id == 0 &&
           h.cipher.id == 0);
    assert(check_parse_ssllabs("<html>maintenance</html>", 24, &h) < 0);
    assert(check_endpoint(1, 3) == NULL);
    assert(check_endpoint(-1, 0) == NULL);
    assert(check_endpoint(0, 5) == NULL);
    assert(
        !strcmp(check_error_name((int)0x80431075, (int)0x80435060, 0x20), "Certificate rejected"));
    assert(!strcmp(check_error_name((int)0x80431075, (int)0x80435062, 4), "TLS request failed"));
    assert(!strcmp(check_error_name((int)0x80436007, 0, 0), "DNS lookup failed"));
    if (argc == 3) {
        FILE *f = fopen(argv[1], "rb");
        assert(f);
        char *body = calloc(1, CHECK_BODY_MAX + 1);
        assert(body);
        size_t n = fread(body, 1, CHECK_BODY_MAX, f);
        fclose(f);
        assert(check_parse_browserleaks(body, n, &h) == 0 && h.cipher_count > 0);
        free(body);
        f = fopen(argv[2], "rb");
        assert(f);
        body = calloc(1, CHECK_BODY_MAX + 1);
        assert(body);
        n = fread(body, 1, CHECK_BODY_MAX, f);
        fclose(f);
        assert(check_parse_ssllabs(body, n, &h) == 0 && h.cipher_count > 0);
        free(body);
    }
    puts("Protocol evidence, distinct selected/offered versions and ciphers, malformed/truncated "
         "reports, and errors: PASS");
    return 0;
}
