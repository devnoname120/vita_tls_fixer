#include "native_cert.h"
#include "cert_facade.h"
#include <psp2/libssl.h>
#include <psp2/rtc.h>
#include <taihen.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (*Record)(const char *, ...);
static Record g_record;
static TlsFixerNativeCertApi g_native;

static int trace_crypto(void **out) {
    g_record("cert.crypto.enter\n");
    int rc = g_native.get_crypto_context(out);
    g_record("cert.crypto.return rc=%08X object=%08X\n", rc, (unsigned int)(uintptr_t)*out);
    return rc;
}
static const void *trace_method(void) {
    g_record("cert.method.enter\n");
    const void *out = g_native.client_method();
    g_record("cert.method.return object=%08X\n", (unsigned int)(uintptr_t)out);
    return out;
}
static void *trace_context(void *crypto, const void *method) {
    g_record("cert.context.enter\n");
    void *out = g_native.context_create(crypto, method);
    g_record("cert.context.return object=%08X\n", (unsigned int)(uintptr_t)out);
    return out;
}
static void *trace_connection(void *context) {
    g_record("cert.connection.enter\n");
    void *out = g_native.connection_create(context);
    g_record("cert.connection.return object=%08X\n", (unsigned int)(uintptr_t)out);
    return out;
}
static int trace_property(void *connection, int key, void *out) {
    g_record("cert.property.enter key=%d\n", key);
    int rc = g_native.connection_property(connection, key, out);
    g_record("cert.property.return rc=%08X object=%08X\n", rc, (unsigned int)(uintptr_t)*(void **)out);
    return rc;
}
static int trace_parse(void *factory, int flags, int type, unsigned int length, const void *der,
                       unsigned int *consumed, void **out) {
    g_record("cert.parse.enter length=%u\n", length);
    int rc = g_native.certificate_parse(factory, flags, type, length, der, consumed, out);
    g_record("cert.parse.return rc=%08X consumed=%u object=%08X\n", rc, *consumed, (unsigned int)(uintptr_t)*out);
    return rc;
}
static int trace_cert_free(void *cert) {
    g_record("cert.free.enter\n");
    int rc = g_native.certificate_free(cert);
    g_record("cert.free.return rc=%08X\n", rc);
    return rc;
}
static void trace_connection_free(void *connection) {
    g_record("cert.connection_free.enter\n");
    g_native.connection_free(connection);
    g_record("cert.connection_free.return\n");
}
static void trace_context_free(void *context) {
    g_record("cert.context_free.enter\n");
    g_native.context_free(context);
    g_record("cert.context_free.return\n");
}
static int trace_integer_decode(void *integer, int format, const void *data, unsigned int length) {
    g_record("cert.integer_decode.enter format=%d length=%u\n", format, length);
    int rc = g_native.integer_decode(integer, format, data, length);
    g_record("cert.integer_decode.return rc=%08X\n", rc);
    return rc;
}

#if TLS_FIXER_AUGMENT_CERT_FACADE_CHECK
static int read_view(unsigned char *bytes, size_t length, TlsFixerCertView *view) {
    uint32_t serial_length, issuer_length, subject_length;
    if (length < 48 || memcmp(bytes, "TCV1", 4) != 0) return -1;
    memcpy(&serial_length, bytes + 36, 4);
    memcpy(&issuer_length, bytes + 40, 4);
    memcpy(&subject_length, bytes + 44, 4);
    if (serial_length > length - 48 || issuer_length > length - 48 - serial_length ||
        subject_length != length - 48 - serial_length - issuer_length) return -1;
    memset(view, 0, sizeof(*view));
    memcpy(view->not_before, bytes + 4, 16);
    memcpy(view->not_after, bytes + 20, 16);
    view->serial = (TlsFixerNativeCertDer){bytes + 48, serial_length};
    view->issuer = (TlsFixerNativeCertDer){bytes + 48 + serial_length, issuer_length};
    view->subject = (TlsFixerNativeCertDer){bytes + 48 + serial_length + issuer_length, subject_length};
    return 0;
}
#endif

static uintptr_t resolve(Record log, uint32_t library, uint32_t nid) {
    uintptr_t address = 0;
    int rc = taiGetModuleExportFunc("SceLibSsl", library, nid, &address);
    log("cert.resolve library=%08X nid=%08X rc=%08X address=%08X\n", library, nid, rc, (unsigned int)address);
    return rc < 0 ? 0 : address;
}

static void hex(char *out, const unsigned char *bytes, size_t length) {
    static const char alphabet[] = "0123456789abcdef";
    for (size_t i = 0; i < length; ++i) {
        out[i * 2] = alphabet[bytes[i] >> 4];
        out[i * 2 + 1] = alphabet[bytes[i] & 15];
    }
    out[length * 2] = 0;
}

int tls_fixer_native_cert_check(Record log) {
    const char *const names[] = {"rsa-sha256", "ec-sha384", "rsa-pss", "ed25519"};
    g_record = log;
    g_native = (TlsFixerNativeCertApi){
        .get_crypto_context = (void *)resolve(log, 0x68d6c3ff, 0x2185bb05),
        .client_method = (void *)resolve(log, 0x68d6c3ff, 0xa374cd7b),
        .context_create = (void *)resolve(log, 0x68d6c3ff, 0xe746465e),
        .connection_create = (void *)resolve(log, 0x68d6c3ff, 0xd28834e6),
        .connection_property = (void *)resolve(log, 0x68d6c3ff, 0x24c6257f),
        .certificate_parse = (void *)resolve(log, 0x68d6c3ff, 0x29aac768),
        .certificate_free = (void *)resolve(log, 0x68d6c3ff, 0x144fa354),
        .connection_free = (void *)resolve(log, 0x68d6c3ff, 0x19b2bb58),
        .context_free = (void *)resolve(log, 0x68d6c3ff, 0xef9ebac7),
        .integer_decode = (void *)resolve(log, 0x68d6c3ff, 0x88391e03)
    };
    if (!g_native.get_crypto_context || !g_native.client_method || !g_native.context_create ||
        !g_native.connection_create || !g_native.connection_property || !g_native.certificate_parse ||
        !g_native.certificate_free || !g_native.connection_free || !g_native.context_free ||
        !g_native.integer_decode) return -1;
    const TlsFixerNativeCertApi api = {trace_crypto, trace_method, trace_context, trace_connection,
        trace_property, trace_parse, trace_cert_free, trace_connection_free, trace_context_free, trace_integer_decode};
    int (*initialize)(unsigned int) = (void *)resolve(log, 0xcaf5f2e9, 0x3c733316);
    int (*terminate)(void) = (void *)resolve(log, 0xcaf5f2e9, 0x03ce6e3a);
    int (*serial)(void *, const char **, unsigned int *) = (void *)resolve(log, 0xcaf5f2e9, 0x901c5c15);
    void *(*subject)(void *) = (void *)resolve(log, 0xcaf5f2e9, 0x9b2f1bc1);
    void *(*issuer)(void *) = (void *)resolve(log, 0xcaf5f2e9, 0x412711e5);
    int (*free_name)(void *) = (void *)resolve(log, 0xcaf5f2e9, 0xc73687e4);
    int (*before)(void *, SceRtcTick *) = (void *)resolve(log, 0xcaf5f2e9, 0x70dea174);
    int (*after)(void *, SceRtcTick *) = (void *)resolve(log, 0xcaf5f2e9, 0xf5ed7b68);
    int (*name_count)(void *) = (void *)resolve(log, 0xcaf5f2e9, 0x95e14ca6);
    int (*name_info)(void *, int, char *, unsigned int, char *, unsigned int, unsigned int *) =
        (void *)resolve(log, 0xcaf5f2e9, 0x2a857867);
    int (*pool_stats)(SceSslMemoryPoolStats *) = (void *)resolve(log, 0xcaf5f2e9, 0xbd203262);
    if (!initialize || !terminate || !serial || !subject || !issuer || !free_name || !before || !after ||
        !name_count || !name_info || !pool_stats) return -1;
    int rc = initialize(512 * 1024), failed = 0;
    if (log("cert.ssl.init=%08X\n", rc) < 0 || rc < 0) return -1;
    SceSslMemoryPoolStats stats = {0};
    pool_stats(&stats);
    log("cert.pool.initial=%u\n", stats.currentInuseSize);
    for (unsigned int round = 0; round < 2; ++round) {
        for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
            char path[160], encoded[513];
            unsigned char der[4096];
            snprintf(path, sizeof(path), "ux0:/data/tls_fixer-augment/certs/%s.%s", names[i],
                     TLS_FIXER_AUGMENT_CERT_FACADE_CHECK ? "view" : "der");
            FILE *file = fopen(path, "rb");
            if (file == NULL) { failed = 1; break; }
            size_t length = fread(der, 1, sizeof(der), file);
            int extra = fgetc(file);
            fclose(file);
            if (length == 0 || extra != EOF) { failed = 1; break; }
            TlsFixerNativeCertChain chain;
            log("cert.begin fixture=%s round=%u length=%u\n", names[i], round, (unsigned int)length);
#if TLS_FIXER_AUGMENT_CERT_FACADE_CHECK
            TlsFixerCertView view;
            TlsFixerCertFacade facade;
            if (read_view(der, length, &view) != 0) { failed = 1; continue; }
            rc = tls_fixer_native_cert_open_factory(&api, &chain);
            if (rc == 0) rc = tls_fixer_cert_facade_init(&facade, &api, chain.factory, &view);
            void *certificate = rc == 0 ? &facade : NULL;
            log("cert.convert=%08X count=%u facade=1\n", rc, certificate != NULL);
            if (rc != 0) { tls_fixer_native_cert_end(&chain); failed = 1; continue; }
#else
            TlsFixerNativeCertDer input = {der, length};
            rc = tls_fixer_native_cert_begin(&api, &input, 1, &chain);
            log("cert.convert=%08X count=%u\n", rc, (unsigned int)chain.count);
            if (rc != 0) { failed = 1; continue; }
            void *certificate = chain.certificates[0];
#endif
            const char *bytes = NULL;
            unsigned int bytes_length = 0;
            rc = serial(certificate, &bytes, &bytes_length);
            if (rc != 0 || bytes == NULL || bytes_length > 256) failed = 1;
            else { hex(encoded, (const unsigned char *)bytes, bytes_length); log("cert.serial=%s\n", encoded); }
            SceRtcTick first = {0}, last = {0};
            int first_rc = before(certificate, &first);
            int last_rc = after(certificate, &last);
            log("cert.time before=%llu after=%llu rc_before=%08X rc_after=%08X\n",
                (unsigned long long)first.tick, (unsigned long long)last.tick, first_rc, last_rc);
            if (first_rc != 0 || last_rc != 0) failed = 1;
            void *objects[] = {subject(certificate), issuer(certificate)};
#if TLS_FIXER_AUGMENT_CERT_FACADE_CHECK
            tls_fixer_cert_facade_end(&facade);
#endif
            tls_fixer_native_cert_end(&chain);
            memset(der, 0xa5, sizeof(der));
            /* Names must remain usable after both DER and temporary cert/context
             * have gone away, matching the public Sony ownership contract. */
            for (unsigned int name_index = 0; name_index < 2; ++name_index) {
                if (objects[name_index] == NULL) { failed = 1; continue; }
                int count = name_count(objects[name_index]);
                log("cert.name kind=%u count=%d after_release=1\n", name_index, count);
                if (count <= 0 || count > 32) failed = 1;
                else for (int entry = 0; entry < count; ++entry) {
                    char oid[64] = {0}, value[256] = {0};
                    unsigned int value_length = 0;
                    rc = name_info(objects[name_index], entry, oid, sizeof(oid), value, sizeof(value), &value_length);
                    if (rc != 0 || value_length > sizeof(value)) { failed = 1; break; }
                    static const char *const expected_oids[] = {"commonName", "organizationName", "organizationalUnitName"};
                    static const char *const expected_values[] = {"tls_fixer native certificate test", "TLS Check", "Café"};
                    if (count != 3 || entry >= 3 || strcmp(oid, expected_oids[entry]) != 0 ||
                        value_length != strlen(expected_values[entry]) ||
                        memcmp(value, expected_values[entry], value_length) != 0) failed = 1;
                    hex(encoded, (const unsigned char *)value, value_length);
                    log("cert.name.entry kind=%u index=%d oid=%.64s value=%s\n", name_index, entry, oid, encoded);
                }
                rc = free_name(objects[name_index]);
                if (rc != 0) failed = 1;
            }
            pool_stats(&stats);
            log("cert.pool round=%u fixture=%s current=%u peak=%u\n",
                round, names[i], stats.currentInuseSize, stats.maxInuseSize);
        }
    }
    rc = terminate();
    log("cert.ssl.term=%08X passed=%d\n", rc, !failed);
    return failed || rc < 0 ? -1 : 0;
}
