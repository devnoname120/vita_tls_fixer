#include "model.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *check_service_name(int s) { return s == 0 ? "BrowserLeaks" : "SSL Labs"; }
const char *check_endpoint(int s, unsigned test) {
    static const char *urls[2][5] = {
        {"https://tls10.browserleaks.com/", "https://tls11.browserleaks.com/",
         "https://tls12.browserleaks.com/", "https://tls13.browserleaks.com/",
         "https://tls.browserleaks.com/tls?minify=1"},
        {"https://www.ssllabs.com:10301/1x1-transparent.png",
         "https://www.ssllabs.com:10302/1x1-transparent.png",
         "https://www.ssllabs.com:10303/1x1-transparent.png", NULL,
         "https://clienttest.ssllabs.com:8443/ssltest/viewMyClient.html"}};
    return s >= 0 && s < 2 && test < 5 ? urls[s][test] : NULL;
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
int check_image_body(const unsigned char *b, size_t n) {
    /* Require the 1x1 PNG header, not a captive portal's HTTP 200. */
    static const unsigned char prefix[] = {137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13,
                                           73,  72, 68, 82, 0,  0,  0,  1,  0, 0, 0, 1};
    return b && n >= 33 && memcmp(b, prefix, sizeof(prefix)) == 0;
}
const char *check_error_name(int e, int ssl, unsigned detail) {
    /* Detail bits alone are not a certificate diagnosis (I/O/abort can carry them too). */
    (void)detail;
    if ((uint32_t)ssl == 0x80435060)
        return "Certificate rejected";
    if ((uint32_t)ssl == 0x80435061)
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
int check_parse_ssllabs(const char *b, size_t n, CheckHandshake *out) {
    if (!b || !out || !n || n > CHECK_BODY_MAX || memchr(b, 0, n))
        return -1;
    memset(out, 0, sizeof(*out));
    /* The HTTP reader supplies a trailing NUL. Search only within an owned copy. */
    char *copy = malloc(n + 1);
    if (!copy)
        return -1;
    memcpy(copy, b, n);
    copy[n] = 0;
    char *start = strstr(copy, "Cipher Suites (in order of preference)"),
         *end = start ? strstr(start, "</table>") : NULL;
    if (!end) {
        free(copy);
        return -1;
    }
    *end = 0;
    for (char *p = start; (p = strstr(p, "TLS_")) != NULL && out->cipher_count < CHECK_LIST_MAX;) {
        CheckNamed item = {0};
        size_t k = 0;
        while ((isalnum((unsigned char)p[k]) || p[k] == '_') && k + 1 < sizeof(item.name)) {
            item.name[k] = p[k];
            ++k;
        }
        item.name[k] = 0;
        char *code = strstr(p + k, "<code>0x");
        if (!code || code - (p + k) > 32 || k == 0)
            break;
        char *tail = NULL;
        unsigned long id = strtoul(code + 8, &tail, 16);
        if (id > 65535 || tail == code + 8 || strncmp(tail, "</code>", 7))
            break;
        item.id = (unsigned)id;
        out->ciphers[out->cipher_count++] = item;
        p = tail + 7;
    }
    /* SSL Labs reports a client capability, not a selected TLS 1.3 connection. */
    for (unsigned i = 0; i < out->cipher_count; ++i)
        if (out->ciphers[i].id >= 0x1301 && out->ciphers[i].id <= 0x1305)
            out->tls13_offered = 1;
    free(copy);
    out->valid = out->cipher_count > 0;
    return out->valid ? 0 : -1;
}
