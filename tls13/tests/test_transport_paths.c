#include "tls_fixer/path.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    const char *directories[] = {
        "vs0:sys/external/", "vs0:/sys/external/",
        "ur0:data/reAuth/", "ur0:/data/reAuth/",
        "vs0:data/external/itls/", "vs0:/data/external/itls/"
    };
    const char *names[] = {"libhttp.suprx", "libssl.suprx"};
    const TlsFixerTransportLibrary kinds[] = {TLS_FIXER_LIBRARY_HTTP, TLS_FIXER_LIBRARY_SSL};
    char path[128], before[128];
    for (unsigned i = 0; i < sizeof(directories) / sizeof(directories[0]); ++i) {
        for (unsigned n = 0; n < 2; ++n) {
            snprintf(path, sizeof(path), "%s%s", directories[i], names[n]);
            strcpy(before, path);
            size_t length = strlen(path);
            assert(tls_fixer_transport_library(path, length + 1) == kinds[n]);
            assert(strcmp(path, before) == 0);
            assert(tls_fixer_transport_library(path, length) == TLS_FIXER_LIBRARY_NONE);
            assert(tls_fixer_transport_library(path, 0) == TLS_FIXER_LIBRARY_NONE);
            strcat(path, ".bak");
            assert(tls_fixer_transport_library(path, sizeof(path)) == TLS_FIXER_LIBRARY_NONE);
        }
    }
    const char *unrelated[] = {
        NULL, "", "libhttp.suprx", "libssl.suprx", "app0:/libhttp.suprx",
        "ux0:/data/reAuth/libhttp.suprx", "ur0:data/notreAuth/libssl.suprx",
        "ur0:data/reAuth/nested/libhttp.suprx", "ur0:data/reAuth/reAuth.suprx",
        "ur0:data/reAuth/libhttp.suprx/child", "vs0:sys/external/libhttp.suprx.bak",
        "vs0:sys/external/notlibssl.suprx", "vs0:data/external/notitls/libhttp.suprx",
        "vs0:/data/external/tls_fixer/native/tls_fixer_http.suprx",
        "wb0:/webcore/ScePsp2Compat.suprx", "vs0:/sys/external/np_commerce2.suprx"
    };
    for (unsigned i = 0; i < sizeof(unrelated) / sizeof(unrelated[0]); ++i)
        assert(tls_fixer_transport_library(unrelated[i], 1024) == TLS_FIXER_LIBRARY_NONE);
    char unterminated[1024]; memset(unterminated, 'x', sizeof(unterminated));
    assert(tls_fixer_transport_library(unterminated, sizeof(unterminated)) == TLS_FIXER_LIBRARY_NONE);
    const char *clients[] = {"vs0:sys/external/np_utility.suprx",
        "vs0:/sys/external/np_matching2.suprx", "vs0:sys/external/np_message.suprx",
        "vs0:/sys/external/libcdlg_game_custom_data_impl.suprx"};
    for (unsigned i = 0; i < sizeof(clients) / sizeof(clients[0]); ++i) {
        assert(tls_fixer_np_http_client_path(clients[i], strlen(clients[i]) + 1) == 1);
        assert(tls_fixer_np_http_client_path(clients[i], strlen(clients[i])) == 0);
    }
    const char *not_clients[] = {NULL, "", "np_utility.suprx",
        "app0:/sce_module/np_utility.suprx", "ur0:sys/external/np_utility.suprx",
        "vs0:sys/external/np_utility.suprx.bak", "vs0:sys/external/nested/np_utility.suprx",
        "vs0:/sys/external/libpaf.suprx", "vs0:sys/external/libcdlg.suprx",
        "vs0:/data/external/tls_fixer/libhttp.suprx"};
    for (unsigned i = 0; i < sizeof(not_clients) / sizeof(not_clients[0]); ++i)
        assert(tls_fixer_np_http_client_path(not_clients[i], 1024) == 0);
    assert(tls_fixer_np_http_client_path(unterminated, sizeof(unterminated)) == 0);
    puts("transport paths: native/legacy aliases, exact matching, bounds and unrelated paths PASS");
    return 0;
}
