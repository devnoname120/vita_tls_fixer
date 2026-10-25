#include "tls_fixer/host_map.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static size_t parse(TlsFixerHostMap *map, char *buffer, const char *text) {
    size_t length = strlen(text);
    memcpy(buffer, text, length);
    buffer[length] = 'Z'; /* the parser may write here; it must not read it as text */
    return tls_fixer_host_map_parse(map, buffer, length);
}

int main(void) {
    TlsFixerHostMap map;
    char text[4096], output[512];
    size_t needed;

    /* Comments, blank lines, CRLF, mixed whitespace and a last line without a newline */
    assert(parse(&map, text,
        "# community servers\r\n"
        "\r\n"
        "soundshapes.psvita.online.scea.com   sound.ture.fish   # Sound Shapes\r\n"
        "\told.example.com\tnew.example.org\n"
        "Short.Example a-much-longer-name.example.net") == 3);
    assert(strcmp(map.rules[0].from, "soundshapes.psvita.online.scea.com") == 0);
    assert(strcmp(map.rules[0].to, "sound.ture.fish") == 0 && map.rules[0].to_length == 15);
    assert(strcmp(map.rules[1].from, "old.example.com") == 0 && strcmp(map.rules[1].to, "new.example.org") == 0);
    assert(strcmp(map.rules[2].to, "a-much-longer-name.example.net") == 0);

    /* Invalid lines are skipped: one word, three words, bad characters, leading dot or dash */
    assert(parse(&map, text,
        "lonely.example.com\n"
        "a.example.com b.example.com c.example.com\n"
        "bad_host.example.com ok.example.com\n"
        "ok.example.com http://url.example.com\n"
        ".dot.example.com ok.example.com\n"
        "ok.example.com -dash.example.com\n"
        "good.example.com fine.example.com\n") == 1);
    assert(strcmp(map.rules[0].from, "good.example.com") == 0);

    /* Over-long names are skipped; the list holds at most TLS_FIXER_HOST_MAP_MAX_RULES rules */
    char long_name[300];
    memset(long_name, 'a', sizeof(long_name) - 1);
    long_name[sizeof(long_name) - 1] = '\0';
    snprintf(text, sizeof(text) - 1, "%s ok.example.com\n", long_name);
    assert(tls_fixer_host_map_parse(&map, text, strlen(text)) == 0);
    text[0] = '\0';
    for (unsigned i = 0; i < TLS_FIXER_HOST_MAP_MAX_RULES + 5; ++i) {
        char line[64];
        snprintf(line, sizeof(line), "h%u.example.com n%u.example.com\n", i, i);
        strcat(text, line);
    }
    assert(tls_fixer_host_map_parse(&map, text, strlen(text)) == TLS_FIXER_HOST_MAP_MAX_RULES);
    assert(parse(&map, text, "") == 0 && map.count == 0);
    assert(tls_fixer_host_map_parse(&map, NULL, 5) == 0 && tls_fixer_host_map_parse(NULL, text, 5) == 0);

    /* One line at a time: names point into the line, which is left untouched */
    TlsFixerHostRule rule;
    const char *line = "  old.example\tnew.example  # comment, ignored\r";
    assert(tls_fixer_host_map_parse_line(line, strlen(line), &rule) == 1);
    assert(rule.from == line + 2 && rule.from_length == 11 && strncmp(rule.to, "new.example", 11) == 0 && rule.to_length == 11);
    assert(tls_fixer_host_map_parse_line("# old.example new.example", 25, &rule) == 0);
    assert(tls_fixer_host_map_parse_line("old.example", 11, &rule) == 0);
    /* A line cut short can still look valid ("old.example new"), which is why the list reader never
     * passes on a line it had to cut, unless the cut fell inside a comment */
    assert(tls_fixer_host_map_parse_line("old.example new.example", 15, &rule) == 1 && rule.to_length == 3);
    assert(tls_fixer_host_map_parse_line(NULL, 5, &rule) == 0 && tls_fixer_host_map_parse_line(line, strlen(line), NULL) == 0);

    /* Hostname lookup ignores case and needs the exact length */
    assert(parse(&map, text, "soundshapes.psvita.online.scea.com sound.ture.fish\nnative.np.ac.playstation.net native-vita.np.ac.playstation.net\n") == 2);
    assert(tls_fixer_host_map_find(&map, "SoundShapes.PSVita.Online.SCEA.com", 34) == &map.rules[0]);
    assert(tls_fixer_host_map_find(&map, "soundshapes.psvita.online.scea.co", 33) == NULL);
    assert(tls_fixer_host_map_find(&map, "soundshapes.psvita.online.scea.com.evil", 39) == NULL);

    /* URL rewrite keeps scheme, port, path, query and fragment; shorter and longer names */
    const char *cases[][2] = {
        {"https://soundshapes.psvita.online.scea.com", "https://sound.ture.fish"},
        {"https://soundshapes.psvita.online.scea.com/otg/~identity:*.hello", "https://sound.ture.fish/otg/~identity:*.hello"},
        {"HTTPS://SOUNDSHAPES.psvita.online.scea.com:443/a?b=c#d", "HTTPS://sound.ture.fish:443/a?b=c#d"},
        {"http://soundshapes.psvita.online.scea.com?x=1", "http://sound.ture.fish?x=1"},
        {"https://native.np.ac.playstation.net/auth", "https://native-vita.np.ac.playstation.net/auth"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        memset(output, 'x', sizeof(output));
        assert(tls_fixer_host_map_rewrite_url(&map, cases[i][0], output, sizeof(output), &needed) == 1);
        assert(strcmp(output, cases[i][1]) == 0 && needed == strlen(cases[i][1]) + 1);
    }

    /* Left alone: other hosts, longer hosts with a matching start, credentials, no scheme */
    const char *untouched[] = {
        "https://sound.ture.fish/otg",
        "https://soundshapes.psvita.online.scea.com.evil.example/x",
        "https://user@soundshapes.psvita.online.scea.com/x",
        "soundshapes.psvita.online.scea.com/x",
        "https:/soundshapes.psvita.online.scea.com",
        "://soundshapes.psvita.online.scea.com",
        "",
    };
    for (size_t i = 0; i < sizeof(untouched) / sizeof(untouched[0]); ++i) {
        memset(output, 'x', sizeof(output));
        assert(tls_fixer_host_map_rewrite_url(&map, untouched[i], output, sizeof(output), &needed) == 0);
        assert(output[0] == 'x' && needed == 0);
    }

    /* A buffer that is too small reports the size it needs and writes nothing */
    memset(output, 'x', sizeof(output));
    assert(tls_fixer_host_map_rewrite_url(&map, cases[4][0], output, 10, &needed) == -1);
    assert(needed == strlen(cases[4][1]) + 1 && output[0] == 'x');
    assert(tls_fixer_host_map_rewrite_url(&map, cases[4][0], NULL, 0, &needed) == -1);
    assert(tls_fixer_host_map_rewrite_url(&map, NULL, output, sizeof(output), &needed) == 0);
    TlsFixerHostMap empty = {0};
    assert(tls_fixer_host_map_rewrite_url(&empty, cases[0][0], output, sizeof(output), &needed) == 0);
    puts("host map: list parsing, case-insensitive lookup and URL host rewrite PASS");
    return 0;
}
