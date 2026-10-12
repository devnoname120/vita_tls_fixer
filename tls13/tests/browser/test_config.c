#define _GNU_SOURCE
#include "tls_fixer/browser_abi.h"
#include "tls_fixer/sony_abi.h"

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#if TLS_FIXER_TEST_CONFIG_DIAGNOSTICS
static unsigned int diagnostic_calls, diagnostic_offset;
static uint32_t diagnostic_value;
void tls_fixer_trace(const char *format, ...) {
    va_list args;
    assert(strcmp(format, "browser legacy option: offset=%u value=0x%08X") == 0);
    va_start(args, format);
    diagnostic_offset = va_arg(args, unsigned int);
    diagnostic_value = va_arg(args, unsigned int);
    va_end(args);
    ++diagnostic_calls;
}
static void expect_diagnostic(size_t offset, int32_t value) {
    assert(diagnostic_calls == 1);
    assert(diagnostic_offset == (unsigned int)offset);
    assert(diagnostic_value == (uint32_t)value);
    diagnostic_calls = 0;
}
static void expect_diagnostic_quiet(void) { assert(diagnostic_calls == 0); }
#else
static void expect_diagnostic(size_t offset, int32_t value) { (void)offset; (void)value; }
static void expect_diagnostic_quiet(void) {}
#endif

#if TLS_FIXER_TEST_CONFIG_RUNTIME
static unsigned int stages[2], events;
static int32_t values[2];
static int32_t callback_policy = -1;
void tls_fixer_runtime_mark(unsigned int stage, int32_t value) {
    if (stage == 38) { callback_policy = value; return; }
    assert(events < 2);
    stages[events] = stage;
    values[events++] = value;
}
static void expect_legacy(size_t offset, int32_t value) {
    assert(events == 2 && stages[0] == 35 && stages[1] == 36);
    assert(values[0] == (int32_t)offset && values[1] == value);
    events = 0;
    expect_diagnostic(offset, value);
}
static void expect_callback_policy(int32_t value) {
    assert(callback_policy == value);
    callback_policy = -1;
}
static void expect_quiet(void) { assert(events == 0 && callback_policy == -1); expect_diagnostic_quiet(); }
#else
static void expect_legacy(size_t offset, int32_t value) { expect_diagnostic(offset, value); }
static void expect_callback_policy(int32_t value) { (void)value; }
static void expect_quiet(void) { expect_diagnostic_quiet(); }
#endif

static const void *accepted_callback;
static const void *accepted_userdata;
static unsigned int validator_calls;

static int validate_default_callback(const void *callback, const void *userdata) {
    ++validator_calls;
    return callback == accepted_callback && userdata == accepted_userdata;
}

int main(void) {
    unsigned char *arena = mmap((void *)(uintptr_t)0x23000000, 65536,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    unsigned char *connection = arena;
    unsigned char *easy = arena + 4096;
    char *host = (char *)arena + 49152;
    char *cipher = host + 1024;
    char *ca_file = cipher + 2048;
    TlsFixerBrowserOptions options;
    const size_t legacy_offsets[] = {816, 820, 824, 828, 896, 920, 924};
    size_t i;

    assert(arena != MAP_FAILED);
    strcpy(host, "example.test");
    strcpy(cipher, "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384");
    tls_fixer_write_u32(connection, 0, (uint32_t)(uintptr_t)easy);
    tls_fixer_write_u32(connection, 136, (uint32_t)(uintptr_t)host);
    tls_fixer_write_u32(connection, 320, 99);
    tls_fixer_write_u32(connection, 324, 101);
    tls_fixer_write_u32(easy, 636, 1);
    easy[644] = 1;
    easy[645] = 1;
    assert(tls_fixer_browser_read_options(connection, 0, "known default",
        validate_default_callback, &options) == 0);
    assert(options.easy == easy && options.socket == 99 && options.hostname == host);
    assert(options.verify_peer && options.verify_host && options.tls12_suites == 15);
    assert(validator_calls == 0);
    assert(tls_fixer_browser_read_options(connection, 1, "known default",
        validate_default_callback, &options) == 0);
    assert(options.socket == 101);
    assert(tls_fixer_browser_read_options(connection, 2, "known default",
        validate_default_callback, &options) < 0);
    assert(tls_fixer_browser_read_options(NULL, 0, "known default",
        validate_default_callback, &options) < 0);
    expect_quiet();
    for (i = 0; i < sizeof(legacy_offsets)/sizeof(legacy_offsets[0]); ++i) {
        tls_fixer_write_u32(easy, legacy_offsets[i], UINT32_C(0xdeadbeef));
        assert(tls_fixer_browser_read_options(connection, 0, "known default",
            validate_default_callback, &options) == 1);
        expect_legacy(legacy_offsets[i], 1);
        assert(tls_fixer_read_u32(easy, legacy_offsets[i]) == UINT32_C(0xdeadbeef));
        tls_fixer_write_u32(easy, legacy_offsets[i], 0);
    }
    easy[689] = 1;
    assert(tls_fixer_browser_read_options(connection, 0, "known default",
        validate_default_callback, &options) == 1);
    expect_legacy(689, 1);
    easy[689] = 0;
    tls_fixer_write_u32(easy, 636, 6);
    assert(tls_fixer_browser_read_options(connection, 0, "known default",
        validate_default_callback, &options) == 1);
    expect_legacy(636, 6);
    tls_fixer_write_u32(easy, 636, UINT32_MAX);
    tls_fixer_write_u32(easy, 680, 1);
    assert(tls_fixer_browser_read_options(connection, 0, "known default",
        validate_default_callback, &options) == 1);
    expect_legacy(636, -1);
    tls_fixer_write_u32(easy, 680, 0);
    tls_fixer_write_u32(easy, 636, 1);
    accepted_callback = easy + 2048;
    accepted_userdata = easy + 3072;
    tls_fixer_write_u32(easy, TLS_FIXER_CURL_CTX_CALLBACK_OFFSET,
        (uint32_t)(uintptr_t)accepted_callback);
    tls_fixer_write_u32(easy, TLS_FIXER_CURL_CTX_CALLBACK_DATA_OFFSET,
        (uint32_t)(uintptr_t)accepted_userdata);
    assert(tls_fixer_browser_read_options(connection, 0, "known default",
        validate_default_callback, &options) == 0);
    assert(validator_calls == 1);
    easy[TLS_FIXER_CURL_VERIFY_PEER_OFFSET] = 0;
    assert(tls_fixer_browser_read_options(connection, 0, "known default",
        validate_default_callback, &options) == 1);
    expect_legacy(TLS_FIXER_CURL_CTX_CALLBACK_OFFSET, 1);
    expect_callback_policy(4);
    easy[TLS_FIXER_CURL_VERIFY_PEER_OFFSET] = 1;
    easy[TLS_FIXER_CURL_VERIFY_HOST_OFFSET] = 0;
    assert(tls_fixer_browser_read_options(connection, 0, "known default",
        validate_default_callback, &options) == 1);
    expect_legacy(TLS_FIXER_CURL_CTX_CALLBACK_OFFSET, 1);
    expect_callback_policy(8);
    easy[TLS_FIXER_CURL_VERIFY_HOST_OFFSET] = 1;
    strcpy(ca_file, "/custom/ca.pem");
    tls_fixer_write_u32(easy, TLS_FIXER_CURL_CAFILE_OFFSET, (uint32_t)(uintptr_t)ca_file);
    assert(tls_fixer_browser_read_options(connection, 0, "known default",
        validate_default_callback, &options) == 1);
    expect_legacy(TLS_FIXER_CURL_CTX_CALLBACK_OFFSET, 1);
    expect_callback_policy(16);
    tls_fixer_write_u32(easy, TLS_FIXER_CURL_CAFILE_OFFSET, 0);
    tls_fixer_write_u32(easy, TLS_FIXER_CURL_CTX_CALLBACK_DATA_OFFSET, 0);
    assert(tls_fixer_browser_read_options(connection, 0, "known default",
        validate_default_callback, &options) == 1);
    expect_legacy(TLS_FIXER_CURL_CTX_CALLBACK_OFFSET, 1);
    expect_callback_policy(1);
    assert(validator_calls == 1);
    tls_fixer_write_u32(easy, TLS_FIXER_CURL_CTX_CALLBACK_DATA_OFFSET,
        (uint32_t)(uintptr_t)accepted_userdata);
    tls_fixer_write_u32(easy, TLS_FIXER_CURL_CTX_CALLBACK_OFFSET,
        (uint32_t)(uintptr_t)accepted_callback + 2);
    assert(tls_fixer_browser_read_options(connection, 0, "known default",
        validate_default_callback, &options) == 1);
    expect_legacy(TLS_FIXER_CURL_CTX_CALLBACK_OFFSET, 1);
    assert(validator_calls == 2);
    tls_fixer_write_u32(easy, TLS_FIXER_CURL_CTX_CALLBACK_OFFSET,
        (uint32_t)(uintptr_t)accepted_callback);
    assert(tls_fixer_browser_read_options(connection, 0, "known default", NULL, &options) == 1);
    expect_legacy(TLS_FIXER_CURL_CTX_CALLBACK_OFFSET, 1);
    expect_callback_policy(2);
    assert(validator_calls == 2);
    tls_fixer_write_u32(easy, TLS_FIXER_CURL_CTX_CALLBACK_OFFSET, 0);
    assert(tls_fixer_browser_read_options(connection, 0, "known default",
        validate_default_callback, &options) == 1);
    expect_legacy(TLS_FIXER_CURL_CTX_CALLBACK_DATA_OFFSET, 1);
    assert(validator_calls == 2);
    tls_fixer_write_u32(easy, TLS_FIXER_CURL_CTX_CALLBACK_DATA_OFFSET, 0);
    tls_fixer_write_u32(easy, 904, (uint32_t)(uintptr_t)cipher);
    assert(tls_fixer_browser_read_options(connection, 0, "known default",
        validate_default_callback, &options) == 0);
    assert(options.tls12_suites == (TLS_FIXER_BROWSER_RSA_GCM128 | TLS_FIXER_BROWSER_ECDSA_GCM256));
    strcpy(cipher, "known default");
    assert(tls_fixer_browser_read_options(connection, 0, "known default",
        validate_default_callback, &options) == 0);
    assert(options.tls12_suites == (TLS_FIXER_BROWSER_RSA_GCM128 | TLS_FIXER_BROWSER_ECDSA_GCM128));
    expect_quiet();
    strcpy(cipher, "ECDHE-RSA-AES128-GCM-SHA256:!ECDHE-RSA");
    assert(tls_fixer_browser_read_options(connection, 0, "known default",
        validate_default_callback, &options) == 1);
    expect_legacy(904, 1);
    memset(cipher, 'x', 1024);
    assert(tls_fixer_browser_read_options(connection, 0, "known default",
        validate_default_callback, &options) < 0);
    expect_quiet();
    assert(munmap(arena, 65536) == 0);
    puts("browser configuration contract: PASS");
    return 0;
}
