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

/* Experimental GUI closure, including variable-only import libraries. */
int tls_fixer_http_client_kind(const char *path, size_t maximum) {
#define CLIENT(name, kind) {"vs0:sys/external/" name ".suprx", kind}, {"vs0:/sys/external/" name ".suprx", kind}
    static const struct { const char *path; int kind; } clients[] = {
        CLIENT("friend_select", 1),
        CLIENT("libSceDtcpIp", 1),
        CLIENT("libcdlg_calendar_review", 1),
        CLIENT("libcdlg_friendlist", 1),
        CLIENT("libcdlg_friendlist2", 1),
        CLIENT("libcdlg_game_custom_data", 1),
        CLIENT("libcdlg_invitation", 1),
        CLIENT("libcdlg_netcheck", 1),
        CLIENT("libcdlg_np_message", 1),
        CLIENT("libcdlg_npeula", 1),
        CLIENT("libcdlg_npprofile2", 1),
        CLIENT("libcdlg_tw_login", 1),
        CLIENT("libcdlg_twitter", 1),
        CLIENT("libgameupdate", 1),
        CLIENT("libmlndownloader", 1),
        CLIENT("libpaf", 1),
        CLIENT("np_activity", 1),
        CLIENT("np_commerce2", 1),
        CLIENT("np_common_ps4", 1),
        CLIENT("np_friend_privacylevel", 1),
        CLIENT("np_kdc", 1),
        CLIENT("np_matching2", 1),
        CLIENT("np_message_contacts", 1),
        CLIENT("np_utility", 1),
        CLIENT("np_webapi", 1),
        CLIENT("psmkdc", 1),
        CLIENT("signin_ext", 1),
        CLIENT("store_checkout_plugin", 1),
        CLIENT("activity_db", 2),
        CLIENT("bXCe", 2),
        CLIENT("common_gui_dialog", 2),
        CLIENT("dbrecovery_utility", 2),
        CLIENT("dbutil", 2),
        CLIENT("ini_file_processor", 2),
        CLIENT("libSceNearDialogUtil", 2),
        CLIENT("libScePromoterUtil", 2),
        CLIENT("libcdlg", 2),
        CLIENT("libcdlg_cameraimport", 2),
        CLIENT("libcdlg_checkout", 2),
        CLIENT("libcdlg_companion", 2),
        CLIENT("libcdlg_compat", 2),
        CLIENT("libcdlg_cross_controller", 2),
        CLIENT("libcdlg_game_custom_data_impl", 2),
        CLIENT("libcdlg_ime", 2),
        CLIENT("libcdlg_invitation_impl", 2),
        CLIENT("libcdlg_main", 2),
        CLIENT("libcdlg_msg", 2),
        CLIENT("libcdlg_near", 2),
        CLIENT("libcdlg_np_sns_fb", 2),
        CLIENT("libcdlg_np_trophy_setup", 2),
        CLIENT("libcdlg_photoimport", 2),
        CLIENT("libcdlg_photoreview", 2),
        CLIENT("libcdlg_pocketstation", 2),
        CLIENT("libcdlg_remote_osk", 2),
        CLIENT("libcdlg_savedata", 2),
        CLIENT("libcdlg_videoimport", 2),
        CLIENT("libpaf_web_map_view", 2),
        CLIENT("near_profile", 2),
        CLIENT("np_message", 2),
        CLIENT("np_message_dialog_impl", 2),
        CLIENT("party_member_list", 2),
        CLIENT("sqlite", 2),
        CLIENT("web_ui_plugin", 2),
    };
#undef CLIENT
    for (size_t i = 0; i < sizeof(clients)/sizeof(clients[0]); ++i)
        if (tls_fixer_path_equals(path, clients[i].path, maximum)) return clients[i].kind;
    return 0;
}

int tls_fixer_library_uses_http(uint32_t library) {
    static const uint32_t libraries[] = {
        UINT32_C(0x4fa0166),
        UINT32_C(0x68cd5db),
        UINT32_C(0x73f8c68),
        UINT32_C(0xdfb9161),
        UINT32_C(0x16a586f4),
        UINT32_C(0x2342266a),
        UINT32_C(0x25e4bae2),
        UINT32_C(0x2836dc9b),
        UINT32_C(0x2dd9a62d),
        UINT32_C(0x31f237b6),
        UINT32_C(0x340dc02e),
        UINT32_C(0x36707edd),
        UINT32_C(0x36f82e95),
        UINT32_C(0x379ff482),
        UINT32_C(0x3c1965cd),
        UINT32_C(0x3d643ce8),
        UINT32_C(0x40120dc3),
        UINT32_C(0x4943bf26),
        UINT32_C(0x4b4aae97),
        UINT32_C(0x4d9a9dd0),
        UINT32_C(0x52115cc3),
        UINT32_C(0x523e1ff8),
        UINT32_C(0x54276d19),
        UINT32_C(0x5ee28724),
        UINT32_C(0x65408075),
        UINT32_C(0x68d6c3ff),
        UINT32_C(0x7106f303),
        UINT32_C(0x7b47d9cf),
        UINT32_C(0x7e103235),
        UINT32_C(0x8134120b),
        UINT32_C(0x83d6c628),
        UINT32_C(0x883cfd5c),
        UINT32_C(0xa070d6a7),
        UINT32_C(0xa7d28dae),
        UINT32_C(0xb30bce77),
        UINT32_C(0xbcab200b),
        UINT32_C(0xc503bd7c),
        UINT32_C(0xcaf5f2e9),
        UINT32_C(0xd407b964),
        UINT32_C(0xdcf776d9),
        UINT32_C(0xe1af627c),
        UINT32_C(0xe537816c),
        UINT32_C(0xe8f15cde),
        UINT32_C(0xe9b9c06b),
        UINT32_C(0xf9a3ed9d),
    };
    for (size_t i = 0; i < sizeof(libraries)/sizeof(libraries[0]); ++i)
        if (libraries[i] == library) return 1;
    return 0;
}
