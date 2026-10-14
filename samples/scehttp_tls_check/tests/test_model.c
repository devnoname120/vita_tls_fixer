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
    assert(check_endpoint(5) == NULL);
    assert(!strcmp(check_endpoint(0), "https://tls10.browserleaks.com/"));
    assert(!strcmp(check_endpoint(4), "https://tls.browserleaks.com/tls?minify=1"));
    for (unsigned version = 0; version < 4; ++version) {
        CheckProtocolDisplay pass = check_protocol_display(version, CHECK_PASS);
        CheckProtocolDisplay fail = check_protocol_display(version, CHECK_FAIL);
        if (version < 2) {
            assert(pass.style == CHECK_WARNING && !strcmp(pass.label, "Insecure") &&
                   !strcmp(pass.qualifier, "vulnerable") && pass.detail_style == CHECK_FAIL);
            assert(fail.style == CHECK_PASS && !strcmp(fail.label, "Blocked") &&
                   !strcmp(fail.qualifier, "secure") && fail.detail_style == CHECK_PASS);
        } else {
            assert(pass.style == CHECK_PASS && !strcmp(pass.label, "Connected") &&
                   !strcmp(pass.qualifier, "secure"));
            assert(fail.style == CHECK_FAIL && !strcmp(fail.label, "Failed") && !fail.qualifier);
        }
        CheckProtocolDisplay waiting = check_protocol_display(version, CHECK_WAIT);
        assert(waiting.style == CHECK_WAIT && !strcmp(waiting.label, "Waiting") && !waiting.qualifier);
        assert(check_protocol_display(version, CHECK_RUNNING).style == CHECK_RUNNING);
        assert(check_protocol_display(version, CHECK_INFO).style == CHECK_INFO);
        CheckResult result = {.state = CHECK_FAIL, .error = (int)0x80431075};
        strcpy(result.message, "TLS handshake failed");
        char detail[128];
        check_protocol_detail(version, &result, detail, sizeof(detail));
        assert(!strcmp(detail, version < 2 ? "Disabled (secure)" : "TLS handshake failed"));
        assert(result.error == (int)0x80431075 && result.state == CHECK_FAIL);
        if (version < 2) {
            result.state = CHECK_PASS;
            check_protocol_detail(version, &result, detail, sizeof(detail));
            assert(strstr(detail, "endpoint (vulnerable)") != NULL);
        }
    }
    assert(check_provider_module_active("tls_fixer_http", 6));
    assert(!check_provider_module_active("tls_fixer_http", 5));
    assert(!check_provider_module_active("tls_fixer_http_extra", 6));
    assert(!check_provider_module_active("tls_fixer", 6));
    assert(!check_provider_module_active("SceLibHttp", 6));
    assert(!check_provider_module_active(NULL, 6));
    assert(
        !strcmp(check_error_name((int)0x80431075, (int)0x80435060, 0x20), "Certificate rejected"));
    assert(!strcmp(check_error_name((int)0x80431075, (int)0x80435062, 4), "TLS request failed"));
    assert(!strcmp(check_error_name((int)0x80436007, 0, 0), "DNS lookup failed"));
    if (argc == 2) {
        FILE *f = fopen(argv[1], "rb");
        assert(f);
        char *body = calloc(1, CHECK_BODY_MAX + 1);
        assert(body);
        size_t n = fread(body, 1, CHECK_BODY_MAX, f);
        fclose(f);
        assert(check_parse_browserleaks(body, n, &h) == 0 && h.cipher_count > 0);
        free(body);

    }
    puts("Protocol evidence, distinct selected/offered versions and ciphers, malformed/truncated "
         "reports, and errors: PASS");
    return 0;
}
