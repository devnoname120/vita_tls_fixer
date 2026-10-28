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

int tls_fixer_np_http_client_path(const char *path, size_t maximum) {
    /* This dependency set agrees across all 31 available 3.60-3.74 images.
     * NP clients can arrive after private HTTP was initialized. Their shared
     * import stubs still point at the shared HTTP copy, so keep these clients
     * and their static importers in the same process-local namespace. */
#define NP_CLIENT(name) "vs0:sys/external/" name ".suprx", "vs0:/sys/external/" name ".suprx"
    static const char *const paths[] = {
        NP_CLIENT("activity_db"), NP_CLIENT("friend_select"),
        NP_CLIENT("libcdlg_calendar_review"), NP_CLIENT("libcdlg_friendlist"),
        NP_CLIENT("libcdlg_friendlist2"), NP_CLIENT("libcdlg_game_custom_data"),
        NP_CLIENT("libcdlg_game_custom_data_impl"), NP_CLIENT("libcdlg_invitation"),
        NP_CLIENT("libcdlg_invitation_impl"), NP_CLIENT("libcdlg_msg"),
        NP_CLIENT("libcdlg_netcheck"), NP_CLIENT("libcdlg_np_message"),
        NP_CLIENT("libcdlg_npprofile2"), NP_CLIENT("libmlndownloader"),
        NP_CLIENT("np_activity"), NP_CLIENT("np_commerce2"),
        NP_CLIENT("np_common_ps4"), NP_CLIENT("np_friend_privacylevel"),
        NP_CLIENT("np_kdc"), NP_CLIENT("np_matching2"),
        NP_CLIENT("np_message"), NP_CLIENT("np_message_contacts"),
        NP_CLIENT("np_message_dialog_impl"), NP_CLIENT("np_utility"),
        NP_CLIENT("np_webapi"), NP_CLIENT("party_member_list"),
        NP_CLIENT("signin_ext"), NP_CLIENT("store_checkout_plugin")
    };
#undef NP_CLIENT
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i)
        if (tls_fixer_path_equals(path, paths[i], maximum)) return 1;
    return 0;
}
