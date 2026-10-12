#include "protocol.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static const char nonce[] = "0123456789abcdef0123456789abcdef";

static void response_cases(void) {
    char response[TLS_FIXER_PROBE_RESPONSE_LIMIT + 1];
    size_t complete = 0;
    int length = snprintf(response, sizeof(response),
        "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nX-TLS-Fixer-Probe-Nonce: %s\r\n\r\nabc", nonce);
    assert(length > 0);
    for (int i = 0; i < length; ++i)
        assert(tls_fixer_probe_response((unsigned char *)response, (size_t)i, nonce, &complete) == 0);
    assert(tls_fixer_probe_response((unsigned char *)response, (size_t)length, nonce, &complete) == 1);
    assert(complete == (size_t)length);
    response[length] = 'x';
    assert(tls_fixer_probe_response((unsigned char *)response, (size_t)length + 1, nonce, &complete) < 0);
    const char *const invalid[] = {
        "HTTP/1.1 500 Error\r\nContent-Length: 0\r\n",
        "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n",
        "HTTP/1.1 200 OK\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 9999999999999999999999999\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n folded: yes\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length : 0\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nBadHeader\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nOther: bare\nnewline\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nOther: bare\rcarriage\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-TLS-Fixer-Probe-Nonce: bad\r\n"
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        length = snprintf(response, sizeof(response), "%sX-TLS-Fixer-Probe-Nonce: %s\r\n\r\n", invalid[i], nonce);
        assert(tls_fixer_probe_response((unsigned char *)response, (size_t)length, nonce, &complete) < 0);
    }
    length = snprintf(response, sizeof(response),
        "HTTP/1.1 200 OK\r\ncontent-length: 0\r\nx-tls-fixer-probe-nonce: %s\r\n\r\n", nonce);
    assert(tls_fixer_probe_response((unsigned char *)response, (size_t)length, nonce, &complete) == 1);
    response[10] = '\0';
    assert(tls_fixer_probe_response((unsigned char *)response, (size_t)length, nonce, &complete) < 0);
    memset(response, 'a', sizeof(response));
    assert(tls_fixer_probe_response((unsigned char *)response, sizeof(response), nonce, &complete) < 0);
    assert(tls_fixer_probe_response((unsigned char *)response, TLS_FIXER_PROBE_RESPONSE_LIMIT, nonce, &complete) < 0);
    assert(tls_fixer_probe_response(NULL, 1, nonce, &complete) < 0);
    assert(tls_fixer_probe_response((unsigned char *)response, 1, NULL, &complete) < 0);
}

int main(void) {
    char request[TLS_FIXER_PROBE_REQUEST_LIMIT];
    assert(tls_fixer_probe_dns_name("probe.test"));
    assert(tls_fixer_probe_dns_name("localhost"));
    const char *const bad_names[] = {NULL, "", "-bad.test", "bad-.test", ".bad", "bad.", "bad..test", "bad\r\nX:1", "bad/test"};
    for (size_t i = 0; i < sizeof(bad_names) / sizeof(bad_names[0]); ++i)
        assert(!tls_fixer_probe_dns_name(bad_names[i]));
    assert(tls_fixer_probe_nonce_valid(nonce));
    assert(!tls_fixer_probe_nonce_valid("000"));
    assert(!tls_fixer_probe_nonce_valid("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
    int count = tls_fixer_probe_request("probe.test", 8443, nonce, request, sizeof(request));
    assert(count > 0 && (size_t)count == strlen(request));
    assert(strstr(request, "GET /?tls_fixer_probe=0123456789abcdef0123456789abcdef HTTP/1.1\r\n"));
    assert(strstr(request, "Host: probe.test:8443\r\n"));
    assert(tls_fixer_probe_request("bad\r\n", 8443, nonce, request, sizeof(request)) < 0);
    assert(tls_fixer_probe_request("probe.test", 0, nonce, request, sizeof(request)) < 0);
    assert(tls_fixer_probe_request("probe.test", 8443, nonce, request, 4) < 0);
    response_cases();
    puts("probe protocol: bounded framing, nonce correlation and request validation PASS");
    return 0;
}
