#include "model.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *check_endpoint(unsigned test) {
    static const char *urls[] = {
        "https://tls10.browserleaks.com/", "https://tls11.browserleaks.com/",
        "https://tls12.browserleaks.com/", "https://tls13.browserleaks.com/",
        "https://tls.browserleaks.com/tls?minify=1",
        "https://native-vita.np.ac.playstation.net/"};
    return test < CHECK_TEST_COUNT ? urls[test] : NULL;
}
static int certificate_error(const CheckResult *r) {
    return (uint32_t)r->error == 0x80431075 && (uint32_t)r->ssl_error == 0x80435060;
}
static int unreachable(const CheckResult *r) {
    return (uint32_t)r->error == 0x80431068 || (uint32_t)r->error == 0x80431063 ||
           ((uint32_t)r->error >= 0x80436000 && (uint32_t)r->error <= 0x804360ff);
}
int check_expected_legacy_block(unsigned version, const CheckResult *r) {
    /* The active tls_fixer provider has a TLS 1.2 minimum. Its peer-alert and
     * out-of-range-version results arrive through sceHttpsGetSslError detail.
     * This is a known provider-policy annotation, not a claim that every peer
     * alert means protocol_version. Stock detail=0 and transport/certificate
     * failures must not acquire a green tick just because a module is loaded.
     * No provider API or TLS library is called by this tester. */
    return version < 2 && r->tls_fixer_active == 1 && r->state == CHECK_FAIL &&
           !r->http_code && !r->protocol_confirmed && !r->restore_error &&
           !r->verification_disabled && !r->retry.protocol_confirmed &&
           !r->retry.http_code && (uint32_t)r->retry.ssl_error != 0x80435060 &&
           (uint32_t)r->error == 0x80431075 && (uint32_t)r->ssl_error == 0x80435061 &&
           (r->ssl_detail == 0xffff8880u || r->ssl_detail == 0xffff9180u);
}
CheckProtocolDisplay check_protocol_display(unsigned version, const CheckResult *r) {
    if (check_expected_legacy_block(version, r))
        return (CheckProtocolDisplay){CHECK_PASS, "Blocked", "secure", CHECK_PASS};
    enum CheckState state = r->state;
    CheckProtocolDisplay display = {state, "Waiting", NULL, state};
    switch (state) {
    case CHECK_PASS: display.label = "Connected"; display.qualifier = "secure"; break;
    case CHECK_FAIL: display.label = "Failed"; break;
    case CHECK_RUNNING: display.label = "Checking..."; break;
    case CHECK_INFO: display.label = "Not tested"; break;
    default: break;
    }
    if (version < 2 && state == CHECK_PASS) {
        display.style = CHECK_WARNING;
        display.detail_style = CHECK_FAIL;
        display.label = "Insecure";
        display.qualifier = "vulnerable";
    }
    if (state == CHECK_FAIL || state == CHECK_WARNING) {
        display.qualifier = NULL;
        if (r->restore_error) {
            display.style = display.detail_style = CHECK_FAIL;
            display.label = "Check error";
        } else if (certificate_error(r)) {
            display.style = display.detail_style = CHECK_WARNING;
            display.label = "Cert error";
        } else if (r->retry.protocol_confirmed) {
            display.style = display.detail_style = CHECK_WARNING;
            display.label = "Unverified";
        } else if (unreachable(r)) {
            display.style = display.detail_style = CHECK_INFO;
            display.label = "Unreachable";
        } else if ((uint32_t)r->error == 0x80431075) {
            display.style = display.detail_style = CHECK_FAIL;
            display.label = "TLS error";
        }
    }
    return display;
}
void check_protocol_detail(unsigned version, const CheckResult *result, char *text, size_t capacity) {
    if (check_expected_legacy_block(version, result))
        snprintf(text, capacity, "Disabled by tls_fixer (secure)");
    else if (result->restore_error)
        snprintf(text, capacity, "Could not restore certificate checks");
    else if (result->retry.attempted && !result->retry.verification_disabled)
        snprintf(text, capacity, "%s; cert retry unavailable", certificate_error(result)
                 ? "Certificate rejected" : "TLS failed");
    else if (result->retry.protocol_confirmed)
        snprintf(text, capacity, "%s", certificate_error(result)
                 ? "TLS works; certificate rejected" : "Connected with certificate checks off");
    else if (certificate_error(result))
        snprintf(text, capacity, "%s%s", check_error_name(result->error, result->ssl_error,
                 result->ssl_detail), result->retry.attempted ? "; retry failed" : "");
    else if (version < 2 && result->state == CHECK_PASS)
        snprintf(text, capacity, "Connected to TLS 1.%u endpoint (vulnerable)", version);
    else
        snprintf(text, capacity, "%s", result->message[0] ? result->message : "Waiting");
}
int check_should_retry_unverified(unsigned test, const CheckResult *r) {
    /* A TLS failure may hide a trust failure in the native stack. Never retry
     * network/HTTP/body failures, cancellation, PSN or the detailed TLS report. */
    return test < 4 && r->state == CHECK_FAIL && r->http_code == 0 &&
           (uint32_t)r->error == 0x80431075 && !r->restore_error && !r->retry.attempted &&
           !check_expected_legacy_block(test, r);
}
void check_protocol_response(unsigned version, const char *body, size_t size, CheckResult *r) {
    if (version >= 4 || r->state != CHECK_PASS)
        return;
    if (check_protocol_body(version, body, size)) {
        r->protocol_confirmed = 1;
        snprintf(r->message, sizeof(r->message), "Connected to TLS 1.%u endpoint", version);
    } else {
        r->state = CHECK_FAIL;
        r->error = -1;
        snprintf(r->message, sizeof(r->message), "Unexpected response; protocol not confirmed");
    }
}
void check_record_retry(CheckResult *r, const CheckResult *retry) {
    r->retry = (CheckRetry){.attempted = 1, .verification_disabled = retry->verification_disabled,
        .protocol_confirmed = retry->verification_disabled && retry->protocol_confirmed,
        .http_code = retry->http_code, .error = retry->error, .ssl_error = retry->ssl_error,
        .restore_error = retry->restore_error, .ssl_detail = retry->ssl_detail,
        .elapsed_ms = retry->elapsed_ms};
    r->restore_error = retry->restore_error;
    if (r->retry.protocol_confirmed && !retry->restore_error)
        r->state = CHECK_WARNING;
    /* Keep the verified attempt's errors, HTTP result and message intact. */
}
int check_provider_module_active(const char *name, unsigned state) {
    /* Sony reports STARTED=6. Presence alone does not establish activation. */
    static const char provider[] = "tls_fixer_http";
    return name && state == 6 && strncmp(name, provider, sizeof(provider)) == 0;
}
int check_protocol_body(unsigned version, const char *b, size_t n) {
    char expected[16];
    if (b == NULL || version > 3)
        return 0;
    while (n && isspace((unsigned char)b[n - 1]))
        --n;
    snprintf(expected, sizeof(expected), "TLS 1.%u", version);
    return n == strlen(expected) && memcmp(b, expected, n) == 0;
}
const char *check_error_name(int e, int ssl, unsigned detail) {
    /* Detail bits alone are not a certificate diagnosis (I/O/abort can carry them too). */
    if ((uint32_t)e == 0x80431075 && (uint32_t)ssl == 0x80435060) {
        if (detail & 0x08) return "Certificate expired";
        if (detail & 0x10) return "Certificate not yet valid";
        if (detail & 0x04) return "Certificate hostname mismatch";
        if (detail & 0x20) return "Untrusted certificate chain";
        return "Certificate rejected";
    }
    if ((uint32_t)e == 0x80431075 && (uint32_t)ssl == 0x80435061)
        return "TLS handshake failed";
    if ((uint32_t)e >= 0x80436000 && (uint32_t)e <= 0x804360ff)
        return "DNS lookup failed";
    switch ((uint32_t)e) {
    case 0x80431068:
        return "Request timed out";
    case 0x80431080:
        return "Request cancelled";
    case 0x80431075:
        return "TLS request failed";
    case 0x80431063:
        return "Network failure";
    case 0x8043506b:
        return "Certificate override denied by system";
    default:
        return "Request failed";
    }
}

/* Bounded JSON reader: no allocation, no dependence on any TLS implementation. */
typedef struct {
    int start, end, next;
    char kind;
} Token;
typedef struct {
    const char *s;
    size_t n, pos;
    Token *t;
    int count;
} Json;
#define TOKEN_MAX 2048
static void ws(Json *j) {
    while (j->pos < j->n && strchr(" \r\n\t", j->s[j->pos]))
        ++j->pos;
}
static int value(Json *j, unsigned depth);
static int string(Json *j) {
    if (j->pos == j->n || j->s[j->pos++] != '"')
        return -1;
    while (j->pos < j->n) {
        unsigned char c = (unsigned char)j->s[j->pos++];
        if (c == '"')
            return 0;
        if (c < 32)
            return -1;
        if (c == '\\') {
            if (j->pos == j->n)
                return -1;
            c = (unsigned char)j->s[j->pos++];
            if (c == 'u') {
                for (int x = 0; x < 4; ++x)
                    if (j->pos == j->n || !isxdigit((unsigned char)j->s[j->pos++]))
                        return -1;
            } else if (!strchr("\"\\/bfnrt", c))
                return -1;
        }
    }
    return -1;
}
static int value(Json *j, unsigned depth) {
    ws(j);
    if (depth > 32 || j->count == TOKEN_MAX || j->pos == j->n)
        return -1;
    int id = j->count++;
    Token *t = &j->t[id];
    t->start = (int)j->pos;
    t->kind = j->s[j->pos];
    if (t->kind == '"') {
        if (string(j))
            return -1;
    } else if (t->kind == '{' || t->kind == '[') {
        char end = t->kind == '{' ? '}' : ']';
        ++j->pos;
        ws(j);
        if (j->pos < j->n && j->s[j->pos] == end)
            ++j->pos;
        else
            for (;;) {
                if (t->kind == '{') {
                    ws(j);
                    if (j->pos == j->n || j->s[j->pos] != '"' || value(j, depth + 1) < 0)
                        return -1;
                    ws(j);
                    if (j->pos == j->n || j->s[j->pos++] != ':')
                        return -1;
                }
                if (value(j, depth + 1) < 0)
                    return -1;
                ws(j);
                if (j->pos == j->n)
                    return -1;
                char c = j->s[j->pos++];
                if (c == end)
                    break;
                if (c != ',')
                    return -1;
            }
    } else if (strchr("tfn", t->kind)) {
        const char *word = t->kind == 't' ? "true" : t->kind == 'f' ? "false" : "null";
        size_t z = strlen(word);
        if (j->n - j->pos < z || memcmp(j->s + j->pos, word, z))
            return -1;
        j->pos += z;
    } else {
        if (j->s[j->pos] == '-')
            ++j->pos;
        if (j->pos == j->n || !isdigit((unsigned char)j->s[j->pos]))
            return -1;
        if (j->s[j->pos] == '0')
            ++j->pos;
        else
            while (j->pos < j->n && isdigit((unsigned char)j->s[j->pos]))
                ++j->pos;
        if (j->pos < j->n && j->s[j->pos] == '.') {
            ++j->pos;
            size_t begin = j->pos;
            while (j->pos < j->n && isdigit((unsigned char)j->s[j->pos]))
                ++j->pos;
            if (j->pos == begin)
                return -1;
        }
        if (j->pos < j->n && strchr("eE", j->s[j->pos])) {
            ++j->pos;
            if (j->pos < j->n && strchr("+-", j->s[j->pos]))
                ++j->pos;
            size_t begin = j->pos;
            while (j->pos < j->n && isdigit((unsigned char)j->s[j->pos]))
                ++j->pos;
            if (j->pos == begin)
                return -1;
        }
    }
    t->end = (int)j->pos;
    t->next = j->count;
    return id;
}
static int text(const Json *j, int i, char *out, size_t cap) {
    if (i < 0 || j->t[i].kind != '"' || cap == 0)
        return -1;
    size_t n = 0;
    for (int p = j->t[i].start + 1; p < j->t[i].end - 1; ++p) {
        unsigned char c = (unsigned char)j->s[p];
        if (c == '\\') {
            c = (unsigned char)j->s[++p];
            if (c == 'u') {
                p += 4;
                c = '?';
            } else if (strchr("bfnrt", c))
                c = ' ';
        }
        if (n + 1 >= cap)
            return -1;
        out[n++] = (char)(c >= 32 && c <= 126 ? c : '?');
    }
    out[n] = '\0';
    return 0;
}
static int field(const Json *j, int obj, const char *key) {
    if (obj < 0 || j->t[obj].kind != '{')
        return -1;
    int found = -1;
    for (int i = obj + 1; i < j->t[obj].next;) {
        char name[96];
        int v = i + 1;
        if (!text(j, i, name, sizeof(name)) && !strcmp(name, key)) {
            if (found >= 0)
                return -1; /* Reject ambiguous duplicate fields. */
            found = v;
        }
        i = j->t[v].next;
    }
    return found;
}
static int number(const Json *j, int i, unsigned *out) {
    if (i < 0 || j->t[i].kind < '0' || j->t[i].kind > '9')
        return -1;
    unsigned n = 0;
    for (int p = j->t[i].start; p < j->t[i].end; ++p) {
        char c = j->s[p];
        if (c < '0' || c > '9' || n > 6553)
            return -1;
        n = n * 10 + (unsigned)(c - '0');
        if (n > 65535)
            return -1;
    }
    *out = n;
    return 0;
}
static int named(const Json *j, int i, CheckNamed *out) {
    return number(j, field(j, i, "id"), &out->id) ||
           text(j, field(j, i, "name"), out->name, sizeof(out->name));
}
static void list(const Json *j, int i, CheckNamed *out, unsigned *count) {
    if (i < 0 || j->t[i].kind != '[')
        return;
    for (int x = i + 1; x < j->t[i].next && *count < CHECK_LIST_MAX; x = j->t[x].next)
        if (!named(j, x, &out[*count]))
            ++*count;
}
int check_parse_browserleaks(const char *b, size_t n, CheckHandshake *out) {
    if (!b || !out || !n || n > CHECK_BODY_MAX || memchr(b, 0, n))
        return -1;
    /* The caller's worker has a dedicated stack; this parser is also tested natively. */
    Token tokens[TOKEN_MAX];
    Json j = {b, n, 0, tokens, 0};
    memset(out, 0, sizeof(*out));
    if (value(&j, 0) != 0)
        return -1;
    ws(&j);
    if (j.pos != n || tokens[0].kind != '{')
        return -1;
    int tls = field(&j, 0, "tls");
    if (named(&j, field(&j, tls, "selected_version"), &out->version) || out->version.id < 0x301 ||
        out->version.id > 0x304 || named(&j, field(&j, tls, "cipher_suite"), &out->cipher))
        return -1;
    (void)named(&j, field(&j, tls, "key_exchange"), &out->group);
    (void)named(&j, field(&j, tls, "signature_scheme"), &out->signature);
    list(&j, field(&j, tls, "cipher_suites"), out->ciphers, &out->cipher_count);
    list(&j, field(&j, tls, "extensions"), out->extensions, &out->extension_count);
    (void)text(&j, field(&j, 0, "ja3_hash"), out->ja3, sizeof(out->ja3));
    (void)text(&j, field(&j, 0, "ja4"), out->ja4, sizeof(out->ja4));
    int ext = field(&j, tls, "extensions");
    if (ext >= 0 && j.t[ext].kind == '[')
        for (int x = ext + 1; x < j.t[ext].next; x = j.t[x].next) {
            unsigned id;
            if (number(&j, field(&j, x, "id"), &id))
                continue;
            int data = field(&j, x, "data");
            if (id == 10)
                list(&j, field(&j, data, "named_group_list"), out->groups, &out->group_count);
            if (id == 16) {
                int a = field(&j, data, "protocol_name_list");
                if (a >= 0 && j.t[a].kind == '[' && j.t[a].next > a + 1)
                    (void)text(&j, a + 1, out->alpn, sizeof(out->alpn));
            }
        }
    out->valid = 1;
    return 0;
}
