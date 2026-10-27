#include "tls_fixer/path.h"

TlsFixerTransportLibrary tls_fixer_transport_library(const char *path, size_t maximum) {
    static const struct {
        const char *path;
        TlsFixerTransportLibrary library;
    } aliases[] = {
        {"vs0:sys/external/libhttp.suprx", TLS_FIXER_LIBRARY_HTTP},
        {"vs0:/sys/external/libhttp.suprx", TLS_FIXER_LIBRARY_HTTP},
        {"ur0:data/reAuth/libhttp.suprx", TLS_FIXER_LIBRARY_HTTP},
        {"ur0:/data/reAuth/libhttp.suprx", TLS_FIXER_LIBRARY_HTTP},
        {"vs0:data/external/itls/libhttp.suprx", TLS_FIXER_LIBRARY_HTTP},
        {"vs0:/data/external/itls/libhttp.suprx", TLS_FIXER_LIBRARY_HTTP},
        {"vs0:sys/external/libssl.suprx", TLS_FIXER_LIBRARY_SSL},
        {"vs0:/sys/external/libssl.suprx", TLS_FIXER_LIBRARY_SSL},
        {"ur0:data/reAuth/libssl.suprx", TLS_FIXER_LIBRARY_SSL},
        {"ur0:/data/reAuth/libssl.suprx", TLS_FIXER_LIBRARY_SSL},
        {"vs0:data/external/itls/libssl.suprx", TLS_FIXER_LIBRARY_SSL},
        {"vs0:/data/external/itls/libssl.suprx", TLS_FIXER_LIBRARY_SSL}
    };
    /* reAuth rewrites paths in SceSysmodule, before the module-loader hook;
     * another loader hook may also have selected a legacy replacement path.
     * Match only these known aliases, never an arbitrary filename suffix. */
    for (size_t i = 0; i < sizeof(aliases) / sizeof(aliases[0]); ++i) {
        if (tls_fixer_path_equals(path, aliases[i].path, maximum)) return aliases[i].library;
    }
    return TLS_FIXER_LIBRARY_NONE;
}
