#define main unused_route_suite
#include "test_route.c"
#undef main

static void check(const char *path, int mapping, int allowed, unsigned expected) {
    reset(); current_pid = 23; http_mapping_private = mapping; http_process_allowed = allowed;
    int options = 4;
    assert(load_for_pid_patched(0, path, 0x08008001, &options) == 88);
    assert(seen_flags == expected && seen_pid == 0 && seen_options == &options);
    assert(strcmp(selected_path, path) == 0 && injections == 0 && dns_loads == 0);
}
int main(void) {
    /* MotorStorm loads CommonDialog before HTTP; its later shared PAF call
     * cannot bind private HTTP. Both ends must be private from first load. */
    check("vs0:sys/external/libcdlg.suprx", 0, 1, 0x8000);
    /* Native preload table uses8000, then shared wrapper adds bit1. */
    reset(); current_pid = 99; http_process_allowed = 1;
    assert(load_for_pid_patched(23,"vs0:sys/external/libcdlg.suprx",0x8001,NULL)==88);
    assert(seen_flags==0x8000 && seen_pid==23 && pid_queries==0);
    check("vs0:/sys/external/libpaf.suprx", 1, 1, 0x8000);
    check("vs0:sys/external/common_gui_dialog.suprx", 1, 1, 0x8000);
    check("vs0:sys/external/libcdlg_main.suprx", 1, 1, 0x8000);
    check("vs0:sys/external/libcdlg_npeula.suprx", 1, 1, 0x8000);
    /* A direct client loaded before HTTP keeps the normal Sony route. */
    check("vs0:sys/external/libpaf.suprx", 0, 1, 0x08008001);
    check("vs0:sys/external/np_utility.suprx", 0, 1, 0x08008001);
    check("vs0:sys/external/libcdlg.suprx", 2, 1, 0x08008001);
    check("vs0:sys/external/libpaf.suprx", 2, 1, 0x08008001);
    check("vs0:sys/external/libcdlg.suprx", 0, 0, 0x08008001);
    check("vs0:sys/external/libpaf.suprx", 1, 0, 0x08008001);
    check("app0:/libpaf.suprx", 1, 1, 0x08008001);
    check("vs0:sys/external/libpaf.suprx.bak", 1, 1, 0x08008001);
    reset(); current_pid = 23; http_mapping_private = 1;
    assert(load_for_pid_patched(0,"vs0:sys/external/libcdlg_npeula.suprx",0x08008012,NULL)==88);
    assert(seen_flags==0x8002+0x10);
    reset(); current_pid = 23; http_mapping_private = -19;
    assert(load_for_pid_patched(0,"vs0:sys/external/libpaf.suprx",0x08008001,NULL)==-19);
    assert(selected_path[0]=='\0');
    reset(); current_pid = 23; http_process_allowed = -20;
    assert(load_for_pid_patched(0,"vs0:sys/external/libcdlg.suprx",0x08008001,NULL)==-20);
    assert(selected_path[0]=='\0');
    reset(); current_pid = 99; http_process_allowed = 1; http_mapping_private = 1;
    assert(load_for_pid_patched(0,"vs0:sys/external/libpaf.suprx",0x08008001,NULL)==88);
    assert(seen_flags==0x08008001 && http_mapping_queries==0);
    /* A mapping failure in a different title must never block its GUI load. */
    const char *excluded[] = {"PCSA00028", "NPXS10002", "NPXS10003", "NPXS10083", "PCSA00027X"};
    for (size_t i = 0; i < sizeof(excluded)/sizeof(excluded[0]); ++i) {
        reset(); current_pid = 23; gui_title = excluded[i]; http_mapping_private = -19;
        assert(load_for_pid_patched(0,"vs0:sys/external/libpaf.suprx",0x08008001,NULL)==88);
        assert(seen_flags==0x08008001 && http_mapping_queries==0 && gui_title_queries==1);
    }
    reset(); current_pid = 23; gui_title_result = -20; http_mapping_private = -19;
    assert(load_for_pid_patched(0,"vs0:sys/external/libpaf.suprx",0x08008001,NULL)==88);
    assert(seen_flags==0x08008001 && http_mapping_queries==0);
    /* Existing HELLDIVERS/NP routing still applies outside the experiment. */
    reset(); current_pid = 23; gui_title = "PCSA00028"; http_mapping_private = 1;
    assert(load_for_pid_patched(0,"vs0:sys/external/np_utility.suprx",0x08008001,NULL)==88);
    assert(seen_flags==0x8000 && http_mapping_queries==1);
    reset(); current_pid = 23; http_mapping_private = 1; g_replace_iap = 0;
    assert(load_for_pid_patched(0,"vs0:sys/external/libpaf.suprx",0x08008001,NULL)==88);
    assert(seen_flags==0x08008001 && http_mapping_queries==0);
    puts("Early dialog and late PAF/EULA routes: PASS");
    return 0;
}
