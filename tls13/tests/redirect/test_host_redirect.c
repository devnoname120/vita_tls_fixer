/* Host test of the provider's host redirects: reading ux0:data/tls_fixer/redirects.txt (through the
 * kernel plugin's system call, faked here), installing
 * the three sceHttp hooks, and what each hook passes on to Sony's libhttp
 * Portable C only, so it runs on Linux and macOS alike */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Allocations by the code under test are counted, and can be made to fail: all of them
 * (fail_allocations), or from the given one on (allocations_left counts down to the failure) */
static int outstanding, fail_allocations, allocations_left = -1;
static int allocation_fails(void)
{
    if (fail_allocations || allocations_left == 0)
        return 1;
    if (allocations_left > 0)
        --allocations_left;
    return 0;
}
static void *test_malloc(size_t size)
{
    void *block = allocation_fails() ? NULL : malloc(size);
    if (block != NULL)
        ++outstanding;
    return block;
}
static void *test_calloc(size_t count, size_t size)
{
    void *block = allocation_fails() ? NULL : calloc(count, size);
    if (block != NULL)
        ++outstanding;
    return block;
}
static void *test_realloc(void *old, size_t size)
{
    if (allocation_fails())
        return NULL;
    void *block = realloc(old, size);
    if (block != NULL && old == NULL)
        ++outstanding;
    return block;
}
static void test_free(void *block)
{
    if (block != NULL)
        --outstanding;
    free(block);
}
#define malloc test_malloc
#define calloc test_calloc
#define realloc test_realloc
#define free test_free
#include "../../provider/host_redirect.c"
#undef malloc
#undef calloc
#undef realloc
#undef free

#define LIBHTTP_NID UINT32_C(0xE8F15CDE)
#define NOT_FOUND ((int)0x80010002)

/* ---- The list, as the kernel plugin returns it ---- */
static const char *file_text;
static size_t file_length, file_offset, chunk;
static int read_error, read_error_at, reads;

int tls_fixer_redirects_read(unsigned int offset, void *data, unsigned int size)
{
    assert(data != NULL && size == TLS_FIXER_REDIRECTS_CHUNK);
    /* Each piece is asked for where the previous one ended */
    assert(offset == file_offset);
    if (file_text == NULL)
        return NOT_FOUND;
    /* A read error from the start, or at the given read (counting from 1) */
    if (read_error || ++reads == read_error_at)
        return -5;
    size_t count = file_length - file_offset;
    if (count > size)
        count = size;
    if (chunk != 0 && count > chunk)
        count = chunk; /* short reads, which the plugin passes on from the file system */
    memcpy(data, file_text + file_offset, count);
    file_offset += count;
    return (int)count;
}

/* ---- What Sony's libhttp receives ---- */
static struct {
    int calls, template_id, connection_id, method, keep_alive;
    char host[512], url[512], scheme[16];
    const char *host_pointer, *url_pointer;
    unsigned short port;
    SceULong64 length;
} seen;

static void remember(char *copy, size_t size, const char *value)
{
    snprintf(copy, size, "%s", value != NULL ? value : "(null)");
}

static int original_create_connection(int template_id, const char *server_name, const char *scheme,
                                      unsigned short port, int keep_alive)
{
    ++seen.calls;
    seen.template_id = template_id;
    seen.host_pointer = server_name;
    remember(seen.host, sizeof(seen.host), server_name);
    remember(seen.scheme, sizeof(seen.scheme), scheme);
    seen.port = port;
    seen.keep_alive = keep_alive;
    return 0x20000001;
}

static int original_create_connection_with_url(int template_id, const char *url, int keep_alive)
{
    ++seen.calls;
    seen.template_id = template_id;
    seen.url_pointer = url;
    remember(seen.url, sizeof(seen.url), url);
    seen.keep_alive = keep_alive;
    return 0x20000002;
}

static int original_create_request_with_url(int connection_id, int method, const char *url, SceULong64 length)
{
    ++seen.calls;
    seen.connection_id = connection_id;
    seen.method = method;
    seen.url_pointer = url;
    remember(seen.url, sizeof(seen.url), url);
    seen.length = length;
    return 0x30000001;
}

/* ---- taiHEN ---- */
static struct {
    uint32_t nid;
    const void *original, *hook;
    struct _tai_hook_user record;
} hooked[] = {
    {UINT32_C(0xAEB3307E), (const void *)original_create_connection, NULL, {0, NULL, NULL}},
    {UINT32_C(0xC616C200), (const void *)original_create_connection_with_url, NULL, {0, NULL, NULL}},
    {UINT32_C(0xBD5DA1D0), (const void *)original_create_request_with_url, NULL, {0, NULL, NULL}},
};
#define HOOK_COUNT (sizeof(hooked) / sizeof(hooked[0]))
static int hook_calls, failing_nid_index = -1;

SceUID taiHookFunctionExport(tai_hook_ref_t *reference, const char *module, uint32_t library_nid,
                             uint32_t function_nid, const void *function)
{
    assert(strcmp(module, "SceLibHttp") == 0 && library_nid == LIBHTTP_NID && function != NULL);
    ++hook_calls;
    for (size_t i = 0; i < HOOK_COUNT; ++i)
    {
        if (hooked[i].nid != function_nid)
            continue;
        if ((int)i == failing_nid_index)
            return -100;
        /* The newest hook is first in taiHEN's chain; with no other hook, it continues to Sony */
        hooked[i].hook = function;
        hooked[i].record = (struct _tai_hook_user){0, (void *)(uintptr_t)function, (void *)(uintptr_t)hooked[i].original};
        *reference = (tai_hook_ref_t)&hooked[i].record;
        return 40 + (int)i;
    }
    assert(!"unexpected function NID");
    return -1;
}

int taiHookRelease(SceUID id, tai_hook_ref_t reference) {
    assert(id >= 40 && id < 43 && reference == (tai_hook_ref_t)&hooked[id - 40].record);
    hooked[id - 40].hook = NULL;
    return 0;
}

typedef int (*CreateConnection)(int, const char *, const char *, unsigned short, int);
typedef int (*CreateConnectionWithUrl)(int, const char *, int);
typedef int (*CreateRequestWithUrl)(int, int, const char *, SceULong64);

/* Forgets the previous scenario's list, as a new process would start without one */
static void reset(const char *text)
{
    test_free(g_names);
    g_names = NULL;
    memset(&g_map, 0, sizeof(g_map));
    file_text = text;
    file_length = text != NULL ? strlen(text) : 0;
    file_offset = 0;
    chunk = 0;
    read_error = read_error_at = reads = fail_allocations = 0;
    allocations_left = -1;
    hook_calls = 0;
    failing_nid_index = -1;
    for (size_t i = 0; i < HOOK_COUNT; ++i)
        hooked[i].hook = NULL;
    memset(&seen, 0, sizeof(seen));
}

/* Installs from text, with the hook at failing_index refused (-1 for none), and reports how many
 * hooks were requested; nothing may stay allocated when the list is not used */
static int install_failing(const char *text, int failing_index)
{
    reset(text);
    failing_nid_index = failing_index;
    int before = outstanding;
    tls_fixer_host_redirect_install();
    if (hook_calls == 0 || failing_index >= 0)
        assert(outstanding == before && g_names == NULL);
    else
        /* Only the kept host names stay allocated, for the life of the process */
        assert(outstanding == before + 1 && g_names != NULL && g_map.count > 0);
    return hook_calls;
}

static int install(const char *text)
{
    return install_failing(text, -1);
}

static void test_no_hooks_without_a_usable_list(void)
{
    assert(install(NULL) == 0);
    assert(install("") == 0);
    assert(install("# only comments\r\n\n   # and spaces\n") == 0);
    assert(install("lonely.example.com\nbad_host.example ok.example\n") == 0);
    reset("old.example new.example\n");
    read_error = 1;
    tls_fixer_host_redirect_install();
    assert(hook_calls == 0 && g_names == NULL && outstanding == 0);
}

/* The list is read in pieces, one line at a time, with a 64 KiB limit; at most 32 pairs are
 * kept, and a read error or a failed allocation anywhere leaves nothing behind */
static void test_list_reading(void)
{
    /* 100 KB of comments before the only rule */
    static char large[102400];
    static const char comment[] = "# a comment line that only makes the file larger ............\n";
    size_t used = 0;
    while (used + sizeof(comment) + 32 < sizeof(large))
    {
        memcpy(large + used, comment, sizeof(comment) - 1);
        used += sizeof(comment) - 1;
    }
    strcpy(large + used, "old.example new.example\n");
    assert(install(large) == 0 && g_map.count == 0);

    /* 40 rules: the first 32 are kept, and reading stops once the list is full */
    static char many[4096];
    many[0] = '\0';
    for (int i = 0; i < 40; ++i)
    {
        char rule[64];
        snprintf(rule, sizeof(rule), "old%d.example new%d.example\n", i, i);
        strcat(many, rule);
    }
    assert(install(many) == 3 && g_map.count == TLS_FIXER_HOST_MAP_MAX_RULES);
    assert(strcmp(g_map.rules[31].from, "old31.example") == 0 && file_offset < strlen(many));

    /* A long line is kept when the part cut off is a comment, and skipped when it could cut a name */
    static char long_lines[2048];
    strcpy(long_lines, "kept.example after.example #");
    memset(long_lines + strlen(long_lines), 'x', 700);
    /* Here the cut at 512 bytes would leave "old.example new.exampl", which looks valid */
    strcat(long_lines, "\n");
    memset(long_lines + strlen(long_lines), ' ', 490);
    strcat(long_lines, "old.example new.example.org\nlast.example final.example");
    reset(long_lines);
    chunk = 7;
    tls_fixer_host_redirect_install();
    assert(hook_calls == 3 && g_map.count == 2);
    assert(strcmp(g_map.rules[0].from, "kept.example") == 0 && strcmp(g_map.rules[0].to, "after.example") == 0);
    /* The last line has no newline and is still read */
    assert(strcmp(g_map.rules[1].from, "last.example") == 0 && strcmp(g_map.rules[1].to, "final.example") == 0);

    /* A read error partway through discards everything read so far */
    const char *list = "first.example one.example\nsecond.example two.example\n";
    reset(list);
    chunk = 7;
    read_error_at = 5;
    tls_fixer_host_redirect_install();
    assert(hook_calls == 0 && g_map.count == 0 && g_names == NULL && outstanding == 0);

    /* So does running out of memory, at each allocation in turn */
    for (int left = 0; left < 4; ++left)
    {
        reset(list);
        allocations_left = left;
        tls_fixer_host_redirect_install();
        assert(hook_calls == 0 && g_names == NULL && outstanding == 0);
    }
    /* With enough memory the same list loads */
    assert(install(list) == 3 && g_map.count == 2);
}

static void test_hooks_and_short_reads(void)
{
    const char *list = "# community servers\r\n"
                       "soundshapes.psvita.online.scea.com  sound.ture.fish   # Sound Shapes\r\n"
                       "short.example a-much-longer-name.example.net\n";
    reset(NULL);
    chunk = 7;
    tls_fixer_host_redirect_install();
    assert(hook_calls == 0);
    reset(list);
    chunk = 7;
    tls_fixer_host_redirect_install();
    assert(hook_calls == 3 && file_offset == strlen(list));
    for (size_t i = 0; i < HOOK_COUNT; ++i)
        assert(hooked[i].hook != NULL);
    assert(g_map.count == 2);

    /* No partial rewrite policy survives a failed hook installation. */
    for (int i = 0; i < 3; ++i) {
        assert(install_failing(list, i) == i + 1);
        assert(hooked[0].hook == NULL && hooked[1].hook == NULL && hooked[2].hook == NULL);
    }
}

static void test_create_connection(void)
{
    assert(install("soundshapes.psvita.online.scea.com sound.ture.fish\n") == 3);
    CreateConnection hook = (CreateConnection)hooked[0].hook;
    int before = outstanding;

    assert(hook(5, "soundshapes.psvita.online.scea.com", "https", 443, 1) == 0x20000001);
    assert(strcmp(seen.host, "sound.ture.fish") == 0);
    assert(seen.template_id == 5 && strcmp(seen.scheme, "https") == 0 && seen.port == 443 && seen.keep_alive == 1);
    assert(hook(5, "SoundShapes.PSVita.Online.SCEA.com", "https", 443, 0) == 0x20000001);
    assert(strcmp(seen.host, "sound.ture.fish") == 0 && seen.keep_alive == 0);

    /* Anything else reaches Sony as the very pointer the game passed */
    const char *others[] = {"sound.ture.fish", "soundshapes.psvita.online.scea.com.evil.example",
                            "soundshapes.psvita.online.scea.co", ""};
    for (size_t i = 0; i < sizeof(others) / sizeof(others[0]); ++i)
    {
        assert(hook(5, others[i], "http", 80, 1) == 0x20000001);
        assert(seen.host_pointer == others[i] && seen.port == 80);
    }
    assert(hook(5, NULL, "https", 443, 1) == 0x20000001 && seen.host_pointer == NULL);
    assert(outstanding == before);
}

static void test_url_hooks(void)
{
    assert(install("soundshapes.psvita.online.scea.com sound.ture.fish\n"
                   "short.example a-much-longer-name.example.net\n") == 3);
    CreateConnectionWithUrl connection = (CreateConnectionWithUrl)hooked[1].hook;
    CreateRequestWithUrl request = (CreateRequestWithUrl)hooked[2].hook;
    int before = outstanding;

    assert(connection(3, "https://soundshapes.psvita.online.scea.com", 1) == 0x20000002);
    assert(strcmp(seen.url, "https://sound.ture.fish") == 0 && seen.template_id == 3 && seen.keep_alive == 1);
    assert(outstanding == before);

    /* The 64-bit content length and the other arguments pass through untouched */
    const SceULong64 length = UINT64_C(0x0123456789ABCDEF);
    assert(request(0x20000001, 1, "https://soundshapes.psvita.online.scea.com/identity/login/token/psn", length) == 0x30000001);
    assert(strcmp(seen.url, "https://sound.ture.fish/identity/login/token/psn") == 0);
    assert(seen.connection_id == 0x20000001 && seen.method == 1 && seen.length == length);
    assert(request(0x20000001, 0, "https://short.example:8443/a?b=c#d", 0) == 0x30000001);
    assert(strcmp(seen.url, "https://a-much-longer-name.example.net:8443/a?b=c#d") == 0 && seen.length == 0);
    assert(outstanding == before);

    /* Other URLs reach Sony as the very pointer the game passed, with nothing allocated */
    const char *others[] = {"https://sound.ture.fish/otg", "https://user@short.example/x", "not a url", ""};
    for (size_t i = 0; i < sizeof(others) / sizeof(others[0]); ++i)
    {
        assert(request(7, 0, others[i], 5) == 0x30000001 && seen.url_pointer == others[i] && seen.length == 5);
        assert(connection(3, others[i], 0) == 0x20000002 && seen.url_pointer == others[i]);
    }
    assert(request(7, 0, NULL, 5) == 0x30000001 && seen.url_pointer == NULL);
    assert(outstanding == before);

    /* Out of memory: the original URL is used rather than failing the call */
    fail_allocations = 1;
    const char *url = "https://short.example/x";
    assert(request(7, 0, url, 9) == 0x30000001 && seen.url_pointer == url && seen.length == 9);
    fail_allocations = 0;
    assert(outstanding == before);
}

int main(void)
{
    test_no_hooks_without_a_usable_list();
    test_list_reading();
    test_hooks_and_short_reads();
    test_create_connection();
    test_url_hooks();
    reset(NULL);
    assert(outstanding == 0);
    puts("host redirects: list reading, hook installation, rewritten calls and memory PASS");
    return 0;
}
