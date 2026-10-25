/* Host test of tls_fixer-reauth: which module it hooks, the rules it reads from the host redirect
 * list (through a stand-in for the kernel plugin's system call), and the PSN rule it always keeps */
#include "../../../psn_redirect/main.c"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#define TAI_NOT_FOUND ((int)0x90010002)
#define LIST_NOT_FOUND ((int)0x80010002)
#define ORIGINAL_RESULT 0x5150
#define PSN_OLD "native.np.ac.playstation.net"
#define PSN_NEW "native-vita.np.ac.playstation.net"

/* ---- The list, as the kernel plugin returns it ---- */
static const char *list_text;
static int read_error_at, reads;

int tls_fixer_redirects_read(unsigned int offset, void *buffer, unsigned int size)
{
    assert(buffer != NULL && size == TLS_FIXER_REDIRECTS_CHUNK);
    if (list_text == NULL)
        return LIST_NOT_FOUND;
    if (++reads == read_error_at)
        return (int)0x80010005;
    size_t length = strlen(list_text);
    if (offset >= length)
        return 0;
    size_t count = length - offset;
    if (count > size)
        count = size;
    memcpy(buffer, list_text + offset, count);
    return (int)count;
}

static int shell_present, store_present, hook_result;
static int hooks, releases, calls;
static char hooked_module[32];
static uint32_t hooked_library, hooked_function;
static const void *hook_function;

/* What Sony's sceHttpCreateConnection received */
static struct {
    int template_id, keep_alive;
    const char *server_name, *scheme;
    unsigned short port;
} seen;

static int original_create_connection(int template_id, const char *server_name, const char *scheme,
                                      unsigned short port, int keep_alive)
{
    ++calls;
    seen.template_id = template_id;
    seen.server_name = server_name;
    seen.scheme = scheme;
    seen.port = port;
    seen.keep_alive = keep_alive;
    return ORIGINAL_RESULT;
}

int taiGetModuleInfo(const char *module, tai_module_info_t *info)
{
    assert(info->size == sizeof(*info));
    if (strcmp(module, "SceShell") == 0)
        return shell_present ? 0 : TAI_NOT_FOUND;
    assert(strcmp(module, "SceNpCommerce2") == 0);
    return store_present ? 0 : TAI_NOT_FOUND;
}

SceUID taiHookFunctionImport(tai_hook_ref_t *reference, const char *module, uint32_t library_nid,
                             uint32_t function_nid, const void *function)
{
    ++hooks;
    snprintf(hooked_module, sizeof(hooked_module), "%s", module);
    hooked_library = library_nid;
    hooked_function = function_nid;
    hook_function = function;
    *reference = (tai_hook_ref_t)original_create_connection;
    return hook_result;
}

int taiHookRelease(SceUID hook_id, tai_hook_ref_t reference)
{
    assert(hook_id == hook_result && hook_id >= 0);
    assert(reference == (tai_hook_ref_t)original_create_connection);
    ++releases;
    return 0;
}

static int start(int shell, int store, int result)
{
    shell_present = shell;
    store_present = store;
    hook_result = result;
    hooks = releases = 0;
    hooked_module[0] = '\0';
    return module_start(0, NULL);
}

/* Starts in an app with the given list (NULL for none) */
static void start_with_list(const char *text)
{
    list_text = text;
    reads = read_error_at = 0;
    assert(start(0, 1, 34) == SCE_KERNEL_START_SUCCESS);
}

/* Calls the installed hook as libhttp's callers would */
static int call_hook(const char *server_name)
{
    typedef int (*CreateConnection)(int, const char *, const char *, unsigned short, int);
    memset(&seen, 0, sizeof(seen));
    calls = 0;
    int result = ((CreateConnection)hook_function)(7, server_name, "https", 443, 1);
    assert(calls == 1 && result == ORIGINAL_RESULT);
    assert(seen.template_id == 7 && strcmp(seen.scheme, "https") == 0 && seen.port == 443 && seen.keep_alive == 1);
    return result;
}

/* The host the connection for host reaches */
static const char *reached(const char *host)
{
    call_hook(host);
    return seen.server_name;
}

/* Without a usable list, the PSN rule still applies */
static void test_psn_rule_without_a_list(void)
{
    const char *lists[] = {NULL, "", "# only comments\n\nnot a pair\n"};
    for (unsigned i = 0; i < sizeof(lists) / sizeof(lists[0]); ++i)
    {
        start_with_list(lists[i]);
        assert(g_map.count == 1 && strcmp(reached(PSN_OLD), PSN_NEW) == 0);
        assert(strcmp(reached("old.example"), "old.example") == 0);
    }
}

/* The list's rules apply alongside the PSN rule, which the list can replace but not lose */
static void test_list_rules(void)
{
    start_with_list("soundshapes.psvita.online.scea.com sound.ture.fish\n");
    assert(g_map.count == 2);
    assert(strcmp(reached("soundshapes.psvita.online.scea.com"), "sound.ture.fish") == 0);
    assert(strcmp(reached(PSN_OLD), PSN_NEW) == 0);

    /* The list's own PSN rule wins, and the built-in one is not added */
    start_with_list("native.np.ac.playstation.net psn.example.org\nold.example new.example");
    assert(g_map.count == 2);
    assert(strcmp(reached(PSN_OLD), "psn.example.org") == 0);
    assert(strcmp(reached("old.example"), "new.example") == 0);

    /* Each start reads the list again, so nothing from the last one remains */
    start_with_list(NULL);
    assert(g_map.count == 1 && strcmp(reached("old.example"), "old.example") == 0);
}

/* A list that fails partway is left out entirely; the PSN rule stays */
static void test_read_errors(void)
{
    static char list[1024];
    list[0] = '\0';
    for (int i = 0; i < 20; ++i)
    {
        char rule[64];
        snprintf(rule, sizeof(rule), "old%d.example new%d.example\n", i, i);
        strcat(list, rule);
    }
    list_text = list;
    reads = 0;
    read_error_at = 2;
    assert(start(0, 1, 34) == SCE_KERNEL_START_SUCCESS);
    assert(g_map.count == 1 && strcmp(reached("old0.example"), "old0.example") == 0);
    assert(strcmp(reached(PSN_OLD), PSN_NEW) == 0);
}

/* At most 31 rules come from the list, so the PSN rule always has a place */
static void test_full_list(void)
{
    static char list[4096];
    list[0] = '\0';
    for (int i = 0; i < 40; ++i)
    {
        char rule[64];
        snprintf(rule, sizeof(rule), "o%d.example n%d.example\n", i, i);
        strcat(list, rule);
    }
    start_with_list(list);
    assert(g_map.count == TLS_FIXER_HOST_MAP_MAX_RULES);
    assert(strcmp(reached("o30.example"), "n30.example") == 0);
    assert(strcmp(reached("o31.example"), "o31.example") == 0);
    assert(strcmp(reached(PSN_OLD), PSN_NEW) == 0);
}

/* Pairs whose names no longer fit the module's space are skipped; later shorter ones still fit */
static void test_long_names(void)
{
    static char list[8192];
    char name[201];
    memset(name, 'a', 196);
    strcpy(name + 196, ".com");
    list[0] = '\0';
    /* Each pair takes 2 x 200 + 2 bytes, so five fit in 2048 bytes */
    for (int i = 0; i < 6; ++i)
    {
        name[0] = (char)('a' + i);
        strcat(list, name);
        strcat(list, " ");
        strcat(list, name);
        strcat(list, "\n");
    }
    strcat(list, "short.example new.example\n");
    start_with_list(list);
    assert(g_map.count == 7 && g_names_used <= NAMES_SIZE);
    assert(strcmp(reached("short.example"), "new.example") == 0);
    name[0] = 'f';
    assert(strcmp(reached(name), name) == 0);
    assert(strcmp(reached(PSN_OLD), PSN_NEW) == 0);
}

int main(void)
{
    /* Neither module present: nothing is hooked and the module unloads itself */
    assert(start(0, 0, 33) == SCE_KERNEL_START_NO_RESIDENT && hooks == 0);
    assert(module_stop(0, NULL) == SCE_KERNEL_STOP_SUCCESS && releases == 0);

    /* The shell is hooked when present, even if the Store library is loaded too */
    assert(start(1, 1, 33) == SCE_KERNEL_START_SUCCESS && hooks == 1);
    assert(strcmp(hooked_module, "SceShell") == 0);
    assert(hooked_library == 0xE8F15CDE && hooked_function == 0xAEB3307E);
    assert(module_stop(0, NULL) == SCE_KERNEL_STOP_SUCCESS && releases == 1);
    assert(module_stop(0, NULL) == SCE_KERNEL_STOP_SUCCESS && releases == 1);

    /* In an app, the Store library is hooked */
    assert(start(0, 1, 34) == SCE_KERNEL_START_SUCCESS && hooks == 1);
    assert(strcmp(hooked_module, "SceNpCommerce2") == 0);

    /* Only the old host goes to the new one (host names ignore case); everything else reaches
     * Sony unchanged */
    call_hook("native.np.ac.playstation.net");
    assert(strcmp(seen.server_name, "native-vita.np.ac.playstation.net") == 0);
    call_hook("NATIVE.np.ac.playstation.net");
    assert(strcmp(seen.server_name, "native-vita.np.ac.playstation.net") == 0);
    const char *unchanged[] = {
        "native-vita.np.ac.playstation.net",
        "native.np.ac.playstation.net.example.com",
        "native.np.ac.playstation.ne",
        "native.np.ac.playstation.net ",
        "sound.ture.fish",
        "",
    };
    for (unsigned i = 0; i < sizeof(unchanged) / sizeof(unchanged[0]); ++i)
    {
        call_hook(unchanged[i]);
        assert(seen.server_name == unchanged[i]);
    }
    call_hook(NULL);
    assert(seen.server_name == NULL);
    assert(module_stop(0, NULL) == SCE_KERNEL_STOP_SUCCESS && releases == 1);

    /* A failed hook: the module unloads itself and has nothing to release */
    assert(start(1, 0, -12) == SCE_KERNEL_START_NO_RESIDENT && hooks == 1);
    assert(module_stop(0, NULL) == SCE_KERNEL_STOP_SUCCESS && releases == 0);

    test_psn_rule_without_a_list();
    test_list_rules();
    test_read_errors();
    test_full_list();
    test_long_names();

    puts("tls_fixer-reauth: shell or Store hook, list rules, PSN rule, read errors and limits PASS");
    return 0;
}
