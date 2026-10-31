#ifndef TLS_FIXER_PATH_H
#define TLS_FIXER_PATH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int tls_fixer_path_equals(const char *path, const char *expected, size_t maximum);
int tls_fixer_path_has_suffix(const char *path, const char *suffix, size_t maximum);
typedef enum TlsFixerTransportLibrary {
    TLS_FIXER_LIBRARY_NONE = 0,
    TLS_FIXER_LIBRARY_HTTP,
    TLS_FIXER_LIBRARY_SSL
} TlsFixerTransportLibrary;
/* Exact input aliases used by the native loader and older TLS plugins.
 * This selects our installed payload; it does not approve the input binary. */
TlsFixerTransportLibrary tls_fixer_transport_library(const char *path, size_t maximum);
/* Sony NP networking clients and their static importers, loaded after HTTP. */
int tls_fixer_np_http_client_path(const char *path, size_t maximum);
/* 1: direct HTTP/SSL user; 2: a transitive client; 0: unrelated. */
int tls_fixer_http_client_kind(const char *path, size_t maximum);
int tls_fixer_library_uses_http(uint32_t library);
int tls_fixer_browser_replacement_path(const char *path, char *output, size_t capacity);
int tls_fixer_browser_provider_path(const char *replacement, char *output, size_t capacity);
int tls_fixer_browser_module_path(const char *provider, char *output, size_t capacity);
int tls_fixer_browser_ca_path(const char *replacement, char *output, size_t capacity);

#ifdef __cplusplus
}
#endif

#endif
