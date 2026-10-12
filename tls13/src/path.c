#include "tls_fixer/path.h"
#include "tls_fixer/browser_start_diagnostics.h"

#include <stdint.h>

static size_t bounded_length(const char *string, size_t maximum) {
    size_t length = 0;

    if (string == NULL) {
        return SIZE_MAX;
    }
    while (length < maximum && string[length] != '\0') {
        ++length;
    }
    return length == maximum ? SIZE_MAX : length;
}

static int bytes_equal(const char *left, const char *right, size_t length) {
    size_t index;

    for (index = 0; index < length; ++index) {
        if (left[index] != right[index]) {
            return 0;
        }
    }
    return 1;
}

int tls_fixer_path_equals(const char *path, const char *expected, size_t maximum) {
    size_t path_length = bounded_length(path, maximum);
    size_t expected_length = bounded_length(expected, maximum);

    if (path_length == SIZE_MAX || expected_length == SIZE_MAX ||
        path_length != expected_length) {
        return 0;
    }
    return bytes_equal(path, expected, path_length);
}

int tls_fixer_path_has_suffix(const char *path, const char *suffix, size_t maximum) {
    size_t path_length = bounded_length(path, maximum);
    size_t suffix_length = bounded_length(suffix, maximum);

    if (path_length == SIZE_MAX || suffix_length == SIZE_MAX ||
        suffix_length > path_length) {
        return 0;
    }
    return bytes_equal(path + path_length - suffix_length, suffix, suffix_length);
}

static int replace_suffix(const char *path, const char *suffix, size_t suffix_size,
    const char *replacement, size_t replacement_size, char *output, size_t capacity) {
    size_t length = bounded_length(path, 1024);
    size_t prefix;
    size_t colon;

    if (length == SIZE_MAX || length < suffix_size || output == NULL ||
        !bytes_equal(path + length - suffix_size, suffix, suffix_size)) return 0;
    prefix = length - suffix_size;
    if (prefix == 0 || (path[prefix - 1] != '/' && path[prefix - 1] != ':')) return 0;
    for (colon = 0; colon < prefix && path[colon] != ':'; ++colon) {}
    if (colon == 0 || colon == prefix || prefix > capacity || replacement_size > capacity - prefix) return 0;
    for (size_t i = 0; i < prefix; ++i) output[i] = path[i];
    for (size_t i = 0; i < replacement_size; ++i) output[prefix + i] = replacement[i];
    return 1;
}

int tls_fixer_browser_replacement_path(const char *path, char *output, size_t capacity) {
    static const char suffix[] = "webcore/ScePsp2Compat.suprx";
    static const char replacement[] = "tls_fixer/ScePsp2Compat.suprx";
    return replace_suffix(path, suffix, sizeof(suffix) - 1,
        replacement, sizeof(replacement), output, capacity);
}

int tls_fixer_browser_provider_path(const char *replacement, char *output, size_t capacity) {
    static const char suffix[] = "tls_fixer/ScePsp2Compat.suprx";
    static const char provider[] = "tls_fixer/" TLS_FIXER_BROWSER_PROVIDER_FILENAME;
    return replace_suffix(replacement, suffix, sizeof(suffix) - 1,
        provider, sizeof(provider), output, capacity);
}

int tls_fixer_browser_ca_path(const char *replacement, char *output, size_t capacity) {
    static const char suffix[] = "tls_fixer/ScePsp2Compat.suprx";
    static const char ca[] = "cert/CA_LIST.cer";
    return replace_suffix(replacement, suffix, sizeof(suffix) - 1,
        ca, sizeof(ca), output, capacity);
}

int tls_fixer_browser_module_path(const char *provider, char *output, size_t capacity) {
    static const char suffix[] = "tls_fixer/" TLS_FIXER_BROWSER_PROVIDER_FILENAME;
    static const char module[] = "tls_fixer/ScePsp2Compat.suprx";
    return replace_suffix(provider, suffix, sizeof(suffix) - 1,
        module, sizeof(module), output, capacity);
}
