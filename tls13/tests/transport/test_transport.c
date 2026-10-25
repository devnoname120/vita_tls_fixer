#define _GNU_SOURCE
#include <vita_mock.h>
#include "provider.h"
#include "transport.h"
#include "cert_hooks.h"
#include <psp2/libssl.h>
#include <psp2/net/http.h>
#ifdef TLS_FIXER_HTTP_MEMORY_TEST
#include "memory_tracker.h"
#endif

#include <assert.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

TlsFixerProviderGlobal g_tls_fixer_http;
static int reentrant_callback;
static unsigned int callbacks;
static uint32_t callback_detail;
static int allow_override;
static int callback_result;
static SceSslCert *last_certificate;
static SceSslCertName *retained_name;

typedef int (*SerialFunction)(SceSslCert *, const char **, unsigned int *);
typedef SceSslCertName *(*NameFunction)(SceSslCert *);
typedef int (*CountFunction)(SceSslCertName *);
typedef int (*FreeFunction)(SceSslCertName *);
typedef int (*TimeFunction)(SceSslCert *, SceRtcTick *);
typedef int (*InfoFunction)(SceSslCertName *, int, char *, unsigned int,
                            char *, unsigned int, unsigned int *);

static int policy_game(void) { return 0; }
static int policy_system(void *address) { (void)address; return 1; }
static uint32_t policy_sdk(void) { return 0x03600000; }
static int policy_parameter(int selector, int *value) {
    assert(selector == 0x00563bfe);
    *value = allow_override;
    return 0;
}

static int application_certificate_callback(
    unsigned int detail, void *const certificates[], int count, void *sony) {
    SerialFunction serial = (SerialFunction)mock_hook_by_nid(0x901c5c15);
    NameFunction subject = (NameFunction)mock_hook_by_nid(0x9b2f1bc1);
    NameFunction issuer = (NameFunction)mock_hook_by_nid(0x412711e5);
    CountFunction entries = (CountFunction)mock_hook_by_nid(0x95e14ca6);
    FreeFunction release = (FreeFunction)mock_hook_by_nid(0xc73687e4);
    InfoFunction info = (InfoFunction)mock_hook_by_nid(0x2a857867);
    TimeFunction before = (TimeFunction)mock_hook_by_nid(0x70dea174);
    TimeFunction after = (TimeFunction)mock_hook_by_nid(0xf5ed7b68);
    const char *serial_bytes = NULL;
    unsigned int serial_size = 0, value_length = 0;
    SceRtcTick not_before, not_after;
    char oid[64], value[64];
    SceSslCertName *issuer_name;

    assert(count > 0 && certificates != NULL);
    last_certificate = certificates[0];
    assert(serial(last_certificate, &serial_bytes, &serial_size) == 0);
    assert(serial_bytes != NULL && serial_size > 0);
    assert(serial((SceSslCert *)(uintptr_t)0x1234, &serial_bytes, &serial_size) == -271);
    assert(serial(last_certificate, NULL, &serial_size) == TLS_FIXER_SCE_SSL_ERROR_INVALID_VALUE);
    assert(before(last_certificate, &not_before) == 0 && after(last_certificate, &not_after) == 0);
    assert(not_after.tick > not_before.tick);
    retained_name = subject(last_certificate);
    issuer_name = issuer(last_certificate);
    assert(retained_name != NULL && issuer_name != NULL);
    assert(entries(retained_name) == 1 && entries(issuer_name) == 1);
    memset(value, 0xa5, sizeof(value));
    assert(info(retained_name, 0, oid, sizeof(oid), value, sizeof(value), &value_length) == 0);
    assert(strcmp(oid, "commonName") == 0 && value_length == 9);
    assert(memcmp(value, "localhost", 9) == 0 && (unsigned char)value[9] == 0xa5);
    memset(value, 0xa5, sizeof(value));
    assert(info(retained_name, 0, oid, 2, value, 2, &value_length) == 0);
    assert(strcmp(oid, "c") == 0 && memcmp(value, "lo", 2) == 0 && value_length == 9);
    assert((unsigned char)value[2] == 0xa5);
    assert(info(retained_name, -1, oid, sizeof(oid), value, sizeof(value), &value_length) < 0);
    assert(release(issuer_name) == 0 && release(issuer_name) < 0);
    ++callbacks;
    callback_detail = detail;
    if (reentrant_callback) {
        unsigned char byte;
        int handled = 0;
        int result = tls_fixer_transport_read(sony, &byte, 1, &handled);
        assert(handled && result == TLS_FIXER_SCE_HTTP_ERROR_EAGAIN);
    }
    return callback_result;
}

static int wait_handshake(void *request) {
    uint64_t deadline = sceKernelGetSystemTimeWide() + UINT64_C(10000000);
    int result;
    int handled;
    do {
        handled = 0;
        result = tls_fixer_transport_connect(request, &handled);
        assert(handled);
        if (result != TLS_FIXER_SCE_HTTP_ERROR_EAGAIN) return result;
        usleep(1000);
    } while (sceKernelGetSystemTimeWide() < deadline);
    fprintf(stderr, "handshake deadline exceeded\n");
    abort();
}

int main(int argc, char **argv) {
    struct sockaddr_in address = { .sin_family = AF_INET };
    const char *scenario;
    unsigned char *arena;
    unsigned char *request;
    unsigned char *sony;
    char *hostname;
    uint32_t *global_options;
    unsigned char response[16384];
    size_t used = 0;
    const char query[] = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    size_t sent = 0;
    int handled;
    int result;
    int socket_id;

    assert(argc == 5 || argc == 6);
    scenario = argv[3];
    mock_ca_file = argv[1];
    reentrant_callback = strcmp(scenario, "reentrant") == 0;
    allow_override = strcmp(scenario, "override-allowed") == 0;
    callback_result = strcmp(scenario, "callback-reject") == 0 ? -1 : 0;
    arena = mmap((void *)(uintptr_t)UINT32_C(0x21000000), 4096, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    assert(arena != MAP_FAILED && (uintptr_t)arena <= UINT32_MAX);
    request = arena;
    sony = arena + 0x200;
    hostname = (char *)arena + 0x400;
    global_options = (uint32_t *)(arena + 0x800);
    strcpy(hostname, strcmp(scenario, "wrong-host") == 0 || strcmp(scenario, "sha1-wrong-host") == 0
        ? "wrong.invalid" : "localhost");
    if (strcmp(scenario, "ipv4-host") == 0) strcpy(hostname, "127.0.0.1");
    if (strcmp(scenario, "ipv6-host") == 0) strcpy(hostname, "::1");
    if (strcmp(scenario, "wrong-ip") == 0) strcpy(hostname, "127.0.0.2");
    if (allow_override) strcpy(hostname, "wrong.invalid");
    *global_options = 0x3f;
    tls_fixer_write_u32(request, TLS_FIXER_REQUEST_PRIMARY_CONNECTION_OFFSET, (uint32_t)(uintptr_t)sony);
    tls_fixer_write_u32(request, 0x8c, 1);
    tls_fixer_write_u32(sony, TLS_FIXER_CONNECTION_HOSTNAME_OFFSET, (uint32_t)(uintptr_t)hostname);
    assert((uintptr_t)application_certificate_callback <= UINT32_MAX);
    tls_fixer_write_u32(sony, TLS_FIXER_CONNECTION_CALLBACK_OFFSET, (uint32_t)(uintptr_t)application_certificate_callback);
    tls_fixer_write_u32(sony, TLS_FIXER_CONNECTION_CALLBACK_ARG_OFFSET, (uint32_t)(uintptr_t)sony);
    g_tls_fixer_http.global_https_options_address = (uintptr_t)global_options;
    g_tls_fixer_http.cert_policy = (TlsFixerCertPolicy){policy_game, policy_system, policy_sdk, policy_parameter};
#ifdef TLS_FIXER_HTTP_MEMORY_TEST
    tls_fixer_memory_tracker_reset();
#endif
    assert(tls_fixer_transport_global_init() == 0);
#ifdef TLS_FIXER_HTTP_MEMORY_TEST
    TlsFixerMemoryStats initialized = tls_fixer_memory_tracker_snapshot();
#endif
    for (mock_hook_fail_index = 0; mock_hook_fail_index < 2; ++mock_hook_fail_index) {
        assert(tls_fixer_cert_hooks_install() < 0);
        assert(mock_hooks_active() == 0 && !tls_fixer_cert_hooks_active());
    }
    mock_hook_fail_index = -1;
    assert(tls_fixer_cert_hooks_install() == 0 && mock_hooks_active() == 2);
    assert(!tls_fixer_cert_hooks_active());
    mock_ssl_shared = 1;
    assert(tls_fixer_cert_hooks_ensure_ssl() < 0);
    assert(mock_hooks_active() == 2 && !tls_fixer_cert_hooks_active());
    mock_ssl_shared = 0;
    for (mock_hook_fail_index = 2; mock_hook_fail_index < 10; ++mock_hook_fail_index) {
        assert(tls_fixer_cert_hooks_ensure_ssl() < 0);
        assert(mock_hooks_active() == 2 && !tls_fixer_cert_hooks_active());
    }
    mock_hook_fail_index = -1;
    assert(tls_fixer_cert_hooks_ensure_ssl() == 0 && mock_hooks_active() == 10);
    assert(tls_fixer_cert_hooks_ensure_ssl() == 0 && mock_hooks_active() == 10);
    if (argc == 6) {
        FILE *file = fopen(argv[5], "rb");
        assert(file != NULL && fseek(file, 0, SEEK_END) == 0);
        long bytes = ftell(file);
        assert(bytes > 0 && fseek(file, 0, SEEK_SET) == 0);
        unsigned char *pem = malloc((size_t)bytes);
        assert(pem != NULL && fread(pem, 1, (size_t)bytes, file) == (size_t)bytes);
        fclose(file);
        SceHttpsData data = {pem, (unsigned)bytes};
        const SceHttpsData *certificates[] = {&data};
        typedef int (*LoadCert)(int, const SceHttpsData **, const SceHttpsData *, const SceHttpsData *);
        LoadCert load = (LoadCert)mock_hook_by_nid(0xae8d7c33);
        assert(load(1, certificates, NULL, NULL) == 0 && !tls_fixer_legacy_certificates_loaded());
        free(pem); /* The application's source buffer need not survive the load. */
    }
    g_tls_fixer_http.state = TLS_FIXER_PROVIDER_ACTIVE;

    socket_id = socket(AF_INET, SOCK_STREAM, 0);
    assert(socket_id >= 0);
    address.sin_port = htons((uint16_t)strtoul(argv[2], NULL, 10));
    assert(inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1);
    assert(connect(socket_id, (struct sockaddr *)&address, sizeof(address)) == 0);
    assert(fcntl(socket_id, F_SETFL, O_NONBLOCK) == 0);
    assert(tls_fixer_transport_create(request, socket_id, &handled) == 0 && handled);
    mock_send_eagain = 2;
    mock_recv_eagain = 2;
    result = wait_handshake(request);

    if (strcmp(scenario, "wrong-host") == 0 || strcmp(scenario, "untrusted") == 0 ||
        strcmp(scenario, "wrong-ip") == 0 || strcmp(scenario, "callback-reject") == 0 ||
        strcmp(scenario, "sha1-wrong-host") == 0 || strcmp(scenario, "sha1-untrusted") == 0 ||
        strcmp(scenario, "sha1-expired") == 0) {
        assert(result == TLS_FIXER_SCE_HTTP_ERROR_SSL);
        assert(tls_fixer_read_i32(sony, TLS_FIXER_CONNECTION_SSL_ERROR_OFFSET) == TLS_FIXER_SCE_HTTPS_ERROR_CERT);
        assert(callbacks == 1);
        assert((callback_detail == 0) == (callback_result < 0));
        if (strcmp(scenario, "sha1-wrong-host") == 0)
            assert(callback_detail & TLS_FIXER_SCE_HTTPS_DETAIL_CN_CHECK);
        if (strcmp(scenario, "sha1-untrusted") == 0)
            assert(callback_detail & TLS_FIXER_SCE_HTTPS_DETAIL_UNKNOWN_CA);
        if (strcmp(scenario, "sha1-expired") == 0)
            assert(callback_detail & TLS_FIXER_SCE_HTTPS_DETAIL_NOT_AFTER);
        goto cleanup;
    }
    if (strcmp(scenario, "bad-record") == 0) {
        assert(result == TLS_FIXER_SCE_HTTP_ERROR_SSL);
        assert(tls_fixer_read_i32(sony, TLS_FIXER_CONNECTION_SSL_ERROR_OFFSET) == TLS_FIXER_SCE_HTTPS_ERROR_HANDSHAKE);
        goto cleanup;
    }
    assert(result == 0 && callbacks == 1 && ((callback_detail == 0) == !allow_override));
    {
        TlsFixerRegistryHandle handle;
        assert(tls_fixer_registry_acquire(&g_tls_fixer_http.registry, (uintptr_t)sony, &handle) == 0);
        TlsFixerConnection *connection = handle.payload;
        assert(strcmp(mbedtls_ssl_get_version(&connection->ssl), argv[4]) == 0);
        assert(tls_fixer_registry_release(&g_tls_fixer_http.registry, &handle) == 0);
    }

    if (strcmp(scenario, "recreate-invalid") == 0) {
        tls_fixer_write_u32(sony, TLS_FIXER_CONNECTION_HOSTNAME_OFFSET, 0);
        result = tls_fixer_transport_create(request, socket_id, &handled);
        assert(handled && result < 0);
        tls_fixer_write_u32(sony, TLS_FIXER_CONNECTION_HOSTNAME_OFFSET, (uint32_t)(uintptr_t)hostname);
    }

    if (strcmp(scenario, "write-retry") == 0 || strcmp(scenario, "changed-write-retry") == 0) {
        char retry[sizeof(query)];
        mock_send_eagain = 1;
        assert(tls_fixer_transport_write(sony, query, sizeof(query) - 1, &handled) ==
               TLS_FIXER_SCE_HTTP_ERROR_EAGAIN && handled);
        memcpy(retry, query, sizeof(query));
        if (strcmp(scenario, "changed-write-retry") == 0) retry[0] = 'P';
        result = tls_fixer_transport_write(sony, retry, sizeof(retry) - 1, &handled);
        assert(handled);
        if (strcmp(scenario, "changed-write-retry") == 0) {
            assert(result == TLS_FIXER_SCE_HTTP_ERROR_SSL);
            goto cleanup;
        }
        assert(result == (int)sizeof(query) - 1);
        sent = (size_t)result;
    }

    while (sent < sizeof(query) - 1) {
        result = tls_fixer_transport_write(sony, query + sent, (unsigned int)(sizeof(query) - 1 - sent), &handled);
        assert(handled);
        if (result == TLS_FIXER_SCE_HTTP_ERROR_EAGAIN) { usleep(1000); continue; }
        assert(result > 0);
        sent += (size_t)result;
    }
    for (;;) {
        result = tls_fixer_transport_read(sony, response + used, (unsigned int)(sizeof(response) - used), &handled);
        assert(handled);
        if (result == TLS_FIXER_SCE_HTTP_ERROR_EAGAIN) { usleep(1000); continue; }
        if (result <= 0) break;
        assert(result <= 1500);
        used += (size_t)result;
        assert(used < sizeof(response));
    }
    fprintf(stderr, "receive terminal: result=0x%08x detail=0x%08x bytes=%zu\n",
            (unsigned int)result, tls_fixer_read_u32(sony, TLS_FIXER_CONNECTION_SSL_DETAIL_OFFSET), used);
    if (strcmp(scenario, "abrupt") == 0) {
        assert(result == TLS_FIXER_SCE_HTTP_ERROR_SSL);
        assert(tls_fixer_read_i32(sony, TLS_FIXER_CONNECTION_SSL_ERROR_OFFSET) == TLS_FIXER_SCE_HTTPS_ERROR_IO);
    } else {
        assert(result == 0);
    }
    assert(used == 5000);
    for (size_t i = 0; i < used; ++i) assert(response[i] == (unsigned char)(i % 251));

cleanup:
    assert(tls_fixer_transport_shutdown(sony, &handled) == 0 && handled);
    close(socket_id);
    if (retained_name != NULL) {
        CountFunction entries = (CountFunction)mock_hook_by_nid(0x95e14ca6);
        FreeFunction release = (FreeFunction)mock_hook_by_nid(0xc73687e4);
        SerialFunction serial = (SerialFunction)mock_hook_by_nid(0x901c5c15);
        const char *unused_serial;
        unsigned int unused_length;
        assert(serial(last_certificate, &unused_serial, &unused_length) < 0);
        assert(entries(retained_name) == 1);
        assert(release(retained_name) == 0 && release(retained_name) < 0);
    }
    tls_fixer_cert_hooks_release();
    assert(mock_hooks_active() == 0);
    assert(tls_fixer_registry_count(&g_tls_fixer_http.registry) == 0);
    assert(tls_fixer_transport_global_destroy() == 0);
#ifdef TLS_FIXER_HTTP_MEMORY_TEST
    TlsFixerMemoryStats final = tls_fixer_memory_tracker_snapshot();
    printf("HTTP heap: initialized=%zu peak=%zu remaining=%zu\n", initialized.current_bytes, final.peak_bytes, final.current_bytes);
    assert(!final.overflow && final.current_bytes == 0 && final.live_allocations == 0);
    assert(final.peak_bytes < 128u * 1024u);
#endif
    munmap(arena, 4096);
    printf("real transport: %s %s PASS\n", scenario, argv[4]);
    return 0;
}
