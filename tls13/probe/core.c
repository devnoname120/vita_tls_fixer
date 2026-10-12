#include "core.h"
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct ProbeWorkspace {
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config config;
    char request[TLS_FIXER_PROBE_REQUEST_LIMIT];
    unsigned char response[TLS_FIXER_PROBE_RESPONSE_LIMIT];
} ProbeWorkspace;

static int remaining(const TlsFixerProbeIo *io, uint64_t started) {
    uint64_t now = io->now_ms(io->context);
    if (now < started || now == UINT64_MAX) return TLS_FIXER_PROBE_CLOCK;
    if (now - started >= TLS_FIXER_PROBE_DEADLINE_MS) return MBEDTLS_ERR_SSL_TIMEOUT;
    return (int)(TLS_FIXER_PROBE_DEADLINE_MS - (now - started));
}

static int retry(const TlsFixerProbeIo *io, int error, uint64_t started) {
    if (error != MBEDTLS_ERR_SSL_WANT_READ && error != MBEDTLS_ERR_SSL_WANT_WRITE) return error;
    int budget = remaining(io, started);
    return budget < 0 ? budget : io->wait(io->context, error, (unsigned int)budget);
}

int tls_fixer_probe_run(const TlsFixerProbeIo *io, mbedtls_x509_crt *ca, const char *address,
    const char *name, unsigned int port, unsigned int version, const char *nonce,
    TlsFixerProbeResult *result) {
    ProbeWorkspace *workspace;
    uint64_t started;
    size_t sent = 0, received = 0, complete_size = 0;
    int rc = TLS_FIXER_PROBE_INVALID, socket_started = 0;
    unsigned int tickets = 0;
    if (result == NULL) return rc;
    memset(result, 0, sizeof(*result));
    result->requested_version = version;
    result->stage = "arguments";
    result->verify_flags = UINT32_MAX;
    result->error = rc;
    if (io == NULL || io->start == NULL || io->finish_connect == NULL || io->send == NULL ||
        io->recv == NULL || io->wait == NULL || io->close == NULL || io->native_error == NULL || io->now_ms == NULL ||
        ca == NULL || ca->raw.p == NULL || address == NULL || !tls_fixer_probe_dns_name(name) ||
        !tls_fixer_probe_nonce_valid(nonce) || port == 0 || port > 65535 ||
        (version != MBEDTLS_SSL_VERSION_TLS1_3 && version != MBEDTLS_SSL_VERSION_TLS1_2)) return rc;
    started = io->now_ms(io->context);
    if (started == UINT64_MAX) { result->error = TLS_FIXER_PROBE_CLOCK; return result->error; }
    result->stage = "allocate";
    workspace = calloc(1, sizeof(*workspace));
    if (workspace == NULL) { result->error = MBEDTLS_ERR_SSL_ALLOC_FAILED; return result->error; }
    mbedtls_ssl_init(&workspace->ssl);
    mbedtls_ssl_config_init(&workspace->config);
    int request_size = tls_fixer_probe_request(name, port, nonce, workspace->request, sizeof(workspace->request));
    if (request_size < 0) goto cleanup;
    result->stage = "configure";
    rc = mbedtls_ssl_config_defaults(&workspace->config, MBEDTLS_SSL_IS_CLIENT,
        MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (rc != 0) goto cleanup;
    mbedtls_ssl_conf_min_tls_version(&workspace->config, version);
    mbedtls_ssl_conf_max_tls_version(&workspace->config, version);
    mbedtls_ssl_conf_authmode(&workspace->config, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&workspace->config, ca, NULL);
    rc = mbedtls_ssl_setup(&workspace->ssl, &workspace->config);
    if (rc != 0) goto cleanup;
    rc = mbedtls_ssl_set_hostname(&workspace->ssl, name);
    if (rc != 0) goto cleanup;
    mbedtls_ssl_set_bio(&workspace->ssl, io->context, io->send, io->recv, NULL);

    result->stage = "connect";
    rc = remaining(io, started);
    if (rc < 0) goto cleanup;
    socket_started = 1;
    rc = io->start(io->context, address, port);
    while (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) {
        rc = retry(io, rc, started);
        if (rc != 0) goto cleanup;
        rc = io->finish_connect(io->context);
    }
    if (rc != 0) goto cleanup;

    result->stage = "handshake";
    for (;;) {
        rc = remaining(io, started);
        if (rc < 0) goto cleanup;
        rc = mbedtls_ssl_handshake(&workspace->ssl);
        result->verify_flags = mbedtls_ssl_get_verify_result(&workspace->ssl);
        if (rc == 0) break;
        rc = retry(io, rc, started);
        if (rc != 0) goto cleanup;
    }
    result->handshake_complete = 1;
    result->stage = "verify";
    result->peer_verified = result->verify_flags == 0;
    const char *negotiated = mbedtls_ssl_get_version(&workspace->ssl);
    const char *cipher = mbedtls_ssl_get_ciphersuite(&workspace->ssl);
    if (negotiated == NULL || cipher == NULL) { rc = TLS_FIXER_PROBE_INVALID; goto cleanup; }
    (void)snprintf(result->negotiated, sizeof(result->negotiated), "%s", negotiated);
    (void)snprintf(result->cipher, sizeof(result->cipher), "%s", cipher);
    if (!result->peer_verified || strcmp(negotiated, version == MBEDTLS_SSL_VERSION_TLS1_3 ? "TLSv1.3" : "TLSv1.2") != 0) {
        rc = TLS_FIXER_PROBE_INVALID;
        goto cleanup;
    }
    result->stage = "request";
    while (sent < (size_t)request_size) {
        rc = remaining(io, started);
        if (rc < 0) goto cleanup;
        rc = mbedtls_ssl_write(&workspace->ssl, (unsigned char *)workspace->request + sent, (size_t)request_size - sent);
        if (rc > 0) {
            if ((size_t)rc > (size_t)request_size - sent) { rc = TLS_FIXER_PROBE_INVALID; goto cleanup; }
            sent += (size_t)rc;
        } else {
            if (rc == 0) { rc = TLS_FIXER_PROBE_EOF; goto cleanup; }
            rc = retry(io, rc, started);
            if (rc != 0) goto cleanup;
        }
    }
    result->stage = "response";
    for (;;) {
        rc = tls_fixer_probe_response(workspace->response, received, nonce, &complete_size);
        if (rc == 1) { result->exchange_complete = 1; rc = 0; result->stage = "complete"; break; }
        if (rc < 0 || received == sizeof(workspace->response)) { rc = TLS_FIXER_PROBE_FRAMING; goto cleanup; }
        rc = remaining(io, started);
        if (rc < 0) goto cleanup;
        rc = mbedtls_ssl_read(&workspace->ssl, workspace->response + received, sizeof(workspace->response) - received);
        if (rc == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) {
            if (++tickets > 16) { rc = TLS_FIXER_PROBE_INVALID; goto cleanup; }
            continue;
        }
        if (rc > 0) {
            if ((size_t)rc > sizeof(workspace->response) - received) { rc = TLS_FIXER_PROBE_INVALID; goto cleanup; }
            received += (size_t)rc;
        } else {
            if (rc == 0 || rc == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) { rc = TLS_FIXER_PROBE_EOF; goto cleanup; }
            rc = retry(io, rc, started);
            if (rc != 0) goto cleanup;
        }
    }
cleanup:
    result->native_error = rc != 0 ? io->native_error(io->context) : 0;
    mbedtls_ssl_free(&workspace->ssl);
    mbedtls_ssl_config_free(&workspace->config);
    free(workspace);
    if (socket_started) result->cleanup_error = io->close(io->context);
    if (rc == 0 && result->cleanup_error != 0) { rc = result->cleanup_error; result->stage = "close"; }
    uint64_t ended = io->now_ms(io->context);
    if (ended >= started && ended != UINT64_MAX) {
        result->elapsed_ms = ended - started;
        if (rc == 0 && result->elapsed_ms >= TLS_FIXER_PROBE_DEADLINE_MS) {
            rc = MBEDTLS_ERR_SSL_TIMEOUT;
            result->stage = "deadline";
        }
    } else if (rc == 0) { rc = TLS_FIXER_PROBE_CLOCK; result->stage = "clock"; }
    result->error = rc;
    return rc;
}
