#ifndef TLS_FIXER_PATH_H
#define TLS_FIXER_PATH_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int tls_fixer_path_equals(const char *path, const char *expected, size_t maximum);
int tls_fixer_path_has_suffix(const char *path, const char *suffix, size_t maximum);
int tls_fixer_browser_replacement_path(const char *path, char *output, size_t capacity);
int tls_fixer_browser_provider_path(const char *replacement, char *output, size_t capacity);
int tls_fixer_browser_module_path(const char *provider, char *output, size_t capacity);
int tls_fixer_browser_ca_path(const char *replacement, char *output, size_t capacity);

#ifdef __cplusplus
}
#endif

#endif
