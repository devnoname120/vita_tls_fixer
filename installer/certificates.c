#include "certificates.h"

#include <curl/curl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CERTIFICATE_LIMIT 512

typedef struct Download {
    unsigned char *data;
    size_t size;
    STACK_OF(X509) *trust;
    int trust_installed;
} Download;

static void free_chain(STACK_OF(X509) *chain) {
    sk_X509_pop_free(chain, X509_free);
}

static int read_file(const char *path, unsigned char **data, size_t *size) {
    FILE *file = fopen(path, "rb");
    long length;
    int result = -1;
    *data = NULL;
    *size = 0;
    if (file == NULL) return -1;
    if (fseek(file, 0, SEEK_END) != 0 || (length = ftell(file)) <= 0 ||
        (unsigned long)length > TLS_FIXER_CA_BUNDLE_LIMIT || fseek(file, 0, SEEK_SET) != 0) goto done;
    *data = malloc((size_t)length + 1);
    if (*data == NULL) goto done;
    if (fread(*data, 1, (size_t)length, file) != (size_t)length || ferror(file)) goto done;
    (*data)[length] = 0;
    *size = (size_t)length;
    result = 0;
done:
    if (fclose(file) != 0) result = -1;
    if (result != 0) { free(*data); *data = NULL; *size = 0; }
    return result;
}

/* Reject partial parses, private-key blocks, non-CA certificates and embedded NULs. */
static STACK_OF(X509) *parse_bundle(const unsigned char *data, size_t size) {
    static const char begin[] = "-----BEGIN CERTIFICATE-----";
    static const char end[] = "-----END CERTIFICATE-----";
    STACK_OF(X509) *chain = NULL;
    const char *cursor = (const char *)data;
    if (data == NULL || size == 0 || size > TLS_FIXER_CA_BUNDLE_LIMIT ||
        memchr(data, 0, size) != NULL) return NULL;
    chain = sk_X509_new_null();
    if (chain == NULL) return NULL;
    for (;;) {
        const char *first = strstr(cursor, "-----BEGIN");
        if (first == NULL) break;
        if (strncmp(first, begin, sizeof(begin) - 1) != 0 ||
            sk_X509_num(chain) >= CERTIFICATE_LIMIT) goto failed;
        const char *last = strstr(first + sizeof(begin) - 1, end);
        if (last == NULL) goto failed;
        size_t length = (size_t)(last - first) + sizeof(end) - 1;
        BIO *bio = BIO_new_mem_buf(first, (int)length);
        if (bio == NULL) goto failed;
        X509 *certificate = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        BIO_free(bio);
        if (certificate == NULL) goto failed;
        if (X509_check_ca(certificate) <= 0 || !sk_X509_push(chain, certificate)) {
            X509_free(certificate);
            goto failed;
        }
        cursor = last + sizeof(end) - 1;
    }
    if (sk_X509_num(chain) == 0) goto failed;
    return chain;
failed:
    free_chain(chain);
    ERR_clear_error();
    return NULL;
}

static size_t receive_bundle(char *bytes, size_t size, size_t count, void *opaque) {
    Download *download = opaque;
    if (size != 0 && count > SIZE_MAX / size) return 0;
    size_t length = size * count;
    if (length > TLS_FIXER_CA_BUNDLE_LIMIT - download->size) return 0;
    unsigned char *data = realloc(download->data, download->size + length + 1);
    if (data == NULL) return 0;
    download->data = data;
    memcpy(data + download->size, bytes, length);
    download->size += length;
    data[download->size] = 0;
    return length;
}

static CURLcode authoritative_trust(CURL *curl, void *ssl_context, void *opaque) {
    Download *download = opaque;
    X509_STORE *store = X509_STORE_new();
    (void)curl;
    if (store == NULL) return CURLE_OUT_OF_MEMORY;
    for (int i = 0; i < sk_X509_num(download->trust); ++i) {
        if (!X509_STORE_add_cert(store, sk_X509_value(download->trust, i))) {
            unsigned long error = ERR_peek_last_error();
            if (ERR_GET_REASON(error) != X509_R_CERT_ALREADY_IN_HASH_TABLE) {
                X509_STORE_free(store);
                ERR_clear_error();
                return CURLE_SSL_CACERT_BADFILE;
            }
            ERR_clear_error();
        }
    }
    /* Replace, rather than augment, curl/OpenSSL's default or cached trust store. */
    SSL_CTX_set_cert_store((SSL_CTX *)ssl_context, store);
    download->trust_installed = 1;
    return CURLE_OK;
}

static STACK_OF(X509) *fetch_bundle(const char *url, const char *mozilla_path,
    long timeout, STACK_OF(X509) *embedded, TlsFixerCertificateBundle *result) {
    Download download = {.trust = embedded};
    STACK_OF(X509) *chain = NULL;
    CURL *curl = NULL;
    CURLcode error = CURLE_FAILED_INIT;
    int initialized = 0;
    if (url == NULL) { result->download_error = CURLE_COULDNT_CONNECT; return NULL; }
    CURLsslset backend = curl_global_sslset(CURLSSLBACKEND_OPENSSL, NULL, NULL);
    if (backend != CURLSSLSET_OK && backend != CURLSSLSET_TOO_LATE) goto done;
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) goto done;
    initialized = 1;
    const curl_version_info_data *version = curl_version_info(CURLVERSION_NOW);
    if (version == NULL || version->ssl_version == NULL ||
        strncmp(version->ssl_version, "OpenSSL/", 8) != 0) goto done;
    curl = curl_easy_init();
    if (curl == NULL) goto done;
#define SET(option, value) do { error = curl_easy_setopt(curl, option, value); if (error != CURLE_OK) goto done; } while (0)
    SET(CURLOPT_URL, url);
    SET(CURLOPT_PROTOCOLS_STR, "https");
    SET(CURLOPT_FOLLOWLOCATION, 0L);
    SET(CURLOPT_FAILONERROR, 1L);
    SET(CURLOPT_PROXY, "");
    SET(CURLOPT_NETRC, CURL_NETRC_IGNORED);
    SET(CURLOPT_SSL_VERIFYPEER, 1L);
    SET(CURLOPT_SSL_VERIFYHOST, 2L);
    SET(CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
    SET(CURLOPT_CAINFO, mozilla_path);
    SET(CURLOPT_CAPATH, NULL);
    SET(CURLOPT_SSL_OPTIONS, 0L);
    SET(CURLOPT_SSL_CTX_FUNCTION, authoritative_trust);
    SET(CURLOPT_SSL_CTX_DATA, &download);
    SET(CURLOPT_SSL_SESSIONID_CACHE, 0L);
    SET(CURLOPT_CA_CACHE_TIMEOUT, 0L);
    SET(CURLOPT_FRESH_CONNECT, 1L);
    SET(CURLOPT_FORBID_REUSE, 1L);
    SET(CURLOPT_CONNECTTIMEOUT, timeout < 10 ? timeout : 10L);
    SET(CURLOPT_TIMEOUT, timeout);
    SET(CURLOPT_NOSIGNAL, 1L);
    SET(CURLOPT_USERAGENT, "tls_fixer-certificate-updater");
    SET(CURLOPT_WRITEFUNCTION, receive_bundle);
    SET(CURLOPT_WRITEDATA, &download);
    error = curl_easy_perform(curl);
    (void)curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &result->http_status);
    if (error == CURLE_OK && result->http_status == 200 && download.trust_installed) {
        chain = parse_bundle(download.data, download.size);
        if (chain == NULL) error = CURLE_SSL_CACERT_BADFILE;
    } else if (error == CURLE_OK) error = CURLE_HTTP_RETURNED_ERROR;
#undef SET
done:
    result->download_error = (int)error;
    if (curl != NULL) curl_easy_cleanup(curl);
    if (initialized) curl_global_cleanup();
    free(download.data);
    return chain;
}

static int append_unique(STACK_OF(X509) *combined, STACK_OF(X509) *source) {
    for (int i = 0; i < sk_X509_num(source); ++i) {
        X509 *certificate = sk_X509_value(source, i);
        int duplicate = 0;
        for (int j = 0; j < sk_X509_num(combined); ++j) {
            if (X509_cmp(certificate, sk_X509_value(combined, j)) == 0) { duplicate = 1; break; }
        }
        if (duplicate) continue;
        if (sk_X509_num(combined) >= CERTIFICATE_LIMIT || !X509_up_ref(certificate)) return -1;
        if (!sk_X509_push(combined, certificate)) { X509_free(certificate); return -1; }
    }
    return 0;
}

int tls_fixer_prepare_certificates(const char *sony_path, const char *mozilla_path,
    const char *url, long timeout_seconds, TlsFixerCertificateBundle *bundle) {
    unsigned char *sony_data = NULL, *mozilla_data = NULL;
    size_t sony_size = 0, mozilla_size = 0;
    STACK_OF(X509) *sony = NULL, *embedded = NULL, *downloaded = NULL, *combined = NULL;
    BIO *output = NULL;
    int result = -1;
    if (bundle == NULL) return -1;
    memset(bundle, 0, sizeof(*bundle));
    if (sony_path == NULL || mozilla_path == NULL || timeout_seconds < 1 || timeout_seconds > 60) return -1;
    if (read_file(sony_path, &sony_data, &sony_size) != 0 ||
        read_file(mozilla_path, &mozilla_data, &mozilla_size) != 0) goto done;
    sony = parse_bundle(sony_data, sony_size);
    embedded = parse_bundle(mozilla_data, mozilla_size);
    if (sony == NULL || embedded == NULL) goto done;
    bundle->sony_count = (size_t)sk_X509_num(sony);
    downloaded = fetch_bundle(url, mozilla_path, timeout_seconds, embedded, bundle);
    STACK_OF(X509) *selected = downloaded == NULL ? embedded : downloaded;
    bundle->downloaded = downloaded != NULL;
    bundle->mozilla_count = (size_t)sk_X509_num(selected);
    combined = sk_X509_new_null();
    if (combined == NULL || append_unique(combined, sony) != 0 || append_unique(combined, selected) != 0) goto done;
    output = BIO_new(BIO_s_mem());
    if (output == NULL || BIO_puts(output, "# tls_fixer: authoritative Sony + curl/Mozilla CA bundle\n") <= 0) goto done;
    for (int i = 0; i < sk_X509_num(combined); ++i) {
        if (!PEM_write_bio_X509(output, sk_X509_value(combined, i))) goto done;
    }
    char *bytes = NULL;
    long size = BIO_get_mem_data(output, &bytes);
    if (size <= 0 || (unsigned long)size > TLS_FIXER_CA_BUNDLE_LIMIT) goto done;
    bundle->data = malloc((size_t)size + 1);
    if (bundle->data == NULL) goto done;
    memcpy(bundle->data, bytes, (size_t)size);
    bundle->data[size] = 0;
    bundle->size = (size_t)size;
    bundle->combined_count = (size_t)sk_X509_num(combined);
    result = 0;
done:
    BIO_free(output);
    free_chain(combined);
    free_chain(downloaded);
    free_chain(embedded);
    free_chain(sony);
    free(sony_data);
    free(mozilla_data);
    if (result != 0) tls_fixer_free_certificates(bundle);
    return result;
}

void tls_fixer_free_certificates(TlsFixerCertificateBundle *bundle) {
    if (bundle == NULL) return;
    free(bundle->data);
    memset(bundle, 0, sizeof(*bundle));
}
