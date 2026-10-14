#ifndef VITA_TLS_CHECK_MODEL_H
#define VITA_TLS_CHECK_MODEL_H
#include <stddef.h>
#include <stdint.h>
#define CHECK_BODY_MAX (96u * 1024u)
#define CHECK_LIST_MAX 64
#define CHECK_NAME_MAX 96

enum CheckState { CHECK_WAIT, CHECK_RUNNING, CHECK_PASS, CHECK_FAIL, CHECK_INFO, CHECK_WARNING };
typedef struct {
    enum CheckState style;
    const char *label, *qualifier;
    enum CheckState detail_style;
} CheckProtocolDisplay;
typedef struct {
    enum CheckState state;
    int http_code, error, ssl_error;
    unsigned ssl_detail, elapsed_ms;
    char message[128];
} CheckResult;
typedef struct {
    unsigned id;
    char name[CHECK_NAME_MAX];
} CheckNamed;
typedef struct {
    int valid;
    CheckNamed version, cipher, group, signature;
    CheckNamed ciphers[CHECK_LIST_MAX], groups[CHECK_LIST_MAX], extensions[CHECK_LIST_MAX];
    unsigned cipher_count, group_count, extension_count;
    char ja3[65], ja4[129], alpn[96];
} CheckHandshake;
typedef struct {
    CheckResult protocols[4], connection;
    CheckHandshake handshake;
    int started, complete;
    int tls_fixer_enabled; /* -1 before runtime detection, then 0 or 1. */
    char report[160];
} CheckService;
const char *check_endpoint(unsigned test);
CheckProtocolDisplay check_protocol_display(unsigned version, enum CheckState state);
void check_protocol_detail(unsigned version, const CheckResult *result, char *text, size_t capacity);
int check_provider_module_active(const char *name, unsigned state);
int check_protocol_body(unsigned version, const char *body, size_t size);
int check_parse_browserleaks(const char *body, size_t size, CheckHandshake *out);
const char *check_error_name(int error, int ssl_error, unsigned detail);
#endif
