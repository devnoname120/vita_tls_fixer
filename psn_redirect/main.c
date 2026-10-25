/* SPDX-License-Identifier: 0BSD */
/*
    Based on reAuth by Reiko Asakura (https://github.com/psv-plugins-archive/reAuth)
*/

#include <psp2/kernel/modulemgr.h>
#include <taihen.h>

#if TLS_FIXER_ENABLE_DEBUG_LOG
#include <psp2/kernel/clib.h>
#define REAUTH_LOG(format, ...) sceClibPrintf("tls_fixer_psn: " format "\n", ##__VA_ARGS__)
#else
#define REAUTH_LOG(format, ...) ((void)0)
#endif

#include "tls_fixer/redirect_list.h"

/* PSN sign-in moved to a new host; old firmware still asks for the old one
 * The kernel plugin loads this module into the shell after it loads its HTTP library, and into
 * apps after they load the Store library (SceNpCommerce2)
 * It rewrites hostnames in that module's sceHttpCreateConnection calls, by the rules of the host
 * redirect list (ux0:data/tls_fixer/redirects.txt, read through the kernel plugin) and changes
 * nothing else; the PSN rule below always applies, unless the list has its own rule for that host */
#define OLD_HOST "native.np.ac.playstation.net"
#define NEW_HOST "native-vita.np.ac.playstation.net"
/* Space for the host names the list's rules keep; the module has no heap, and typical pairs take
 * about 50 bytes, so this holds the full 32 rules unless the names are very long */
#define NAMES_SIZE 2048u

#define SCE_HTTP_LIBRARY_NID 0xE8F15CDE
#define SCE_HTTP_CREATE_CONNECTION_NID 0xAEB3307E

static SceUID g_hook_id = -1;
static tai_hook_ref_t g_hook_ref;
static TlsFixerHostMap g_map;
static char g_names[NAMES_SIZE];
static size_t g_names_used;
static char g_work[TLS_FIXER_REDIRECT_LIST_WORK_SIZE];

static void copy_name(char *destination, const char *source, size_t length)
{
    for (size_t i = 0; i < length; ++i)
        destination[i] = source[i];
    destination[length] = '\0';
}

/* Keeps one pair from the list; a pair whose names no longer fit is skipped */
static int keep_rule(void *context, const TlsFixerHostRule *rule)
{
    (void)context;
    size_t needed = rule->from_length + rule->to_length + 2u;
    if (needed > sizeof(g_names) - g_names_used)
    {
        REAUTH_LOG("redirect skipped: the list's host names take more than %u bytes", NAMES_SIZE);
        return 0;
    }
    char *from = g_names + g_names_used, *to = from + rule->from_length + 1u;
    copy_name(from, rule->from, rule->from_length);
    copy_name(to, rule->to, rule->to_length);
    g_names_used += needed;
    g_map.rules[g_map.count++] = (TlsFixerHostRule){from, to, rule->from_length, rule->to_length};
    /* One place stays free for the PSN rule */
    return g_map.count == TLS_FIXER_HOST_MAP_MAX_RULES - 1u;
}

/* The list's rules, then the PSN rule unless the list redirects that host itself; a list that
 * cannot be read is left out entirely */
static void load_rules(void)
{
    g_map.count = 0;
    g_names_used = 0;
    int result = tls_fixer_redirect_list_read(tls_fixer_redirects_read, g_work, keep_rule, 0);
    if (result < 0)
    {
        REAUTH_LOG("redirect list not read: rc=0x%08X", (unsigned)result);
        g_map.count = 0;
    }
    if (tls_fixer_host_map_find(&g_map, OLD_HOST, sizeof(OLD_HOST) - 1u) == 0)
        g_map.rules[g_map.count++] = (TlsFixerHostRule){OLD_HOST, NEW_HOST, sizeof(OLD_HOST) - 1u,
                                                      sizeof(NEW_HOST) - 1u};
    REAUTH_LOG("redirects loaded=%u", (unsigned)g_map.count);
}

/* The length of a host name, counted no further than the longest valid one */
static size_t host_length(const char *host)
{
    size_t length = 0;
    while (length <= TLS_FIXER_HOST_MAP_MAX_HOST && host[length] != '\0')
        ++length;
    return length;
}

static int create_connection_hook(int template_id, const char *server_name, const char *scheme,
                                  unsigned short port, int keep_alive)
{
    const TlsFixerHostRule *rule = server_name == 0 ? 0
        : tls_fixer_host_map_find(&g_map, server_name, host_length(server_name));
    if (rule != 0)
    {
        REAUTH_LOG("redirected %s to %s", rule->from, rule->to);
        server_name = rule->to;
    }
    return TAI_CONTINUE(int, g_hook_ref, template_id, server_name, scheme, port, keep_alive);
}

/* The Vita loader enters through _start; macOS, where only the host tests build, has no aliases */
#if !defined(__APPLE__)
int _start(SceSize argc, const void *args) __attribute__((weak, alias("module_start")));
#endif
int module_start(SceSize argc, const void *args)
{
    (void)argc;
    (void)args;
    /* The shell signs in to PSN; apps reach the Store through SceNpCommerce2 */
    static const char *const targets[] = {"SceShell", "SceNpCommerce2"};
    for (unsigned i = 0; i < sizeof(targets) / sizeof(targets[0]); ++i)
    {
        tai_module_info_t info;
        info.size = sizeof(info);
        if (taiGetModuleInfo(targets[i], &info) < 0)
            continue;
        load_rules();
        g_hook_id = taiHookFunctionImport(&g_hook_ref, targets[i], SCE_HTTP_LIBRARY_NID,
                                          SCE_HTTP_CREATE_CONNECTION_NID, create_connection_hook);
        REAUTH_LOG("hook %s rc=0x%08X", targets[i], (unsigned)g_hook_id);
        /* Without its hook the module has nothing to do, so it unloads itself */
        return g_hook_id >= 0 ? SCE_KERNEL_START_SUCCESS : SCE_KERNEL_START_NO_RESIDENT;
    }
    return SCE_KERNEL_START_NO_RESIDENT;
}

int module_stop(SceSize argc, const void *args)
{
    (void)argc;
    (void)args;
    if (g_hook_id >= 0)
        taiHookRelease(g_hook_id, g_hook_ref);
    g_hook_id = -1;
    return SCE_KERNEL_STOP_SUCCESS;
}
