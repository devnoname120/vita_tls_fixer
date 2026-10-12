#include "self_disarm.h"
#include <kernel_mock.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#define CAPACITY (TLS_FIXER_SELF_DISARM_MAX_CONFIG + 16)
#define MISSING ((int32_t)0x80010002)

typedef struct {
    unsigned char bytes[CAPACITY], durable[CAPACITY];
    size_t size, durable_size, position;
    int present, open, flags;
} TestFile;

static TestFile files[2];
static unsigned char memory[TLS_FIXER_SELF_DISARM_MAX_CONFIG];
static int memory_live, writes, syncs, fail_n, event_n;
static char failing_event;
static int corrupt_verify, reading_after_sync;

static int event(char name) {
    if (name == failing_event && ++event_n == fail_n) return 1;
    return 0;
}
static int index_of(const char *path) {
    if (strncmp(path, "ur0:", 4) == 0) return 0;
    assert(strncmp(path, "ux0:", 4) == 0);
    return 1;
}
SceUID ksceKernelAllocMemBlock(const char *name, int type, SceSize size, const void *options) {
    (void)name;
    assert(type == SCE_KERNEL_MEMBLOCK_TYPE_KERNEL_RW && size == sizeof(memory) && options == NULL);
    assert(!memory_live);
    if (event('a')) return -1;
    memory_live = 1;
    return 42;
}
int ksceKernelGetMemBlockBase(SceUID id, void **output) {
    assert(id == 42 && memory_live);
    if (event('b')) return -1;
    *output = memory;
    return 0;
}
int ksceKernelFreeMemBlock(SceUID id) {
    assert(id == 42 && memory_live);
    memory_live = 0;
    return event('f') ? -1 : 0;
}
int ksceIoOpen(const char *path, int flags, int mode) {
    int index = index_of(path);
    assert(strcmp(path + 4, "tai/config.txt") == 0 && mode == 0);
    assert(flags == SCE_O_RDWR || flags == SCE_O_RDONLY);
    if (event('o')) return -123;
    if (!files[index].present) return MISSING;
    assert(!files[index].open);
    files[index].open = 1;
    files[index].position = 0;
    files[index].flags = flags;
    reading_after_sync = syncs > 0;
    return index + 10;
}
int ksceIoClose(int fd) {
    assert(fd >= 10 && fd <= 11 && files[fd - 10].open);
    files[fd - 10].open = 0;
    return event('c') ? -1 : 0;
}
SceOff ksceIoLseek(int fd, SceOff offset, int whence) {
    TestFile *file = &files[fd - 10];
    assert(file->open);
    if (event('l')) return -1;
    assert(whence == SCE_SEEK_SET || whence == SCE_SEEK_END);
    SceOff position = (whence == SCE_SEEK_END ? (SceOff)file->size : 0) + offset;
    assert(position >= 0 && (uint64_t)position <= file->size);
    file->position = (size_t)position;
    return position;
}
int ksceIoRead(int fd, void *data, unsigned int size) {
    TestFile *file = &files[fd - 10];
    size_t count;
    assert(file->open && file->position <= file->size);
    if (event('r')) return -1;
    if (event('e')) return 0;
    count = file->size - file->position;
    if (count > size) count = size;
    if (count > 7) count = 7;
    memcpy(data, file->bytes + file->position, count);
    file->position += count;
    if (corrupt_verify && reading_after_sync && count != 0) ((unsigned char *)data)[0] ^= 1;
    return (int)count;
}
int ksceIoPwrite(int fd, const void *data, unsigned int size, SceOff offset) {
    TestFile *file = &files[fd - 10];
    assert(file->open && file->flags == SCE_O_RDWR);
    assert(size == 1 && *(const char *)data == '#');
    assert(offset >= 0 && (uint64_t)offset < file->size);
    if (event('w')) return -1;
    if (event('z')) return 0;
    file->bytes[(size_t)offset] = '#';
    ++writes;
    return 1;
}
int ksceIoSync(const char *path, unsigned int flags) {
    int index = index_of(path);
    assert(flags == 0);
    if (event('s')) return -1;
    ++syncs;
    memcpy(files[index].durable, files[index].bytes, files[index].size);
    files[index].durable_size = files[index].size;
    return 0;
}

static void install_file(int index, const char *contents) {
    TestFile *file = &files[index];
    file->present = 1;
    file->size = strlen(contents);
    assert(file->size < CAPACITY);
    memcpy(file->bytes, contents, file->size);
    memcpy(file->durable, contents, file->size);
    file->durable_size = file->size;
}
static void reset(const char *contents) {
    assert(!memory_live && !files[0].open && !files[1].open);
    memset(files, 0, sizeof(files));
    writes = syncs = event_n = corrupt_verify = reading_after_sync = 0;
    failing_event = 0;
    fail_n = 1;
    if (contents != NULL) install_file(0, contents);
}
static void expect_bytes(int index, const char *expected) {
    assert(files[index].size == strlen(expected));
    assert(memcmp(files[index].bytes, expected, files[index].size) == 0);
    assert(files[index].durable_size == files[index].size);
    assert(memcmp(files[index].durable, expected, files[index].size) == 0);
}
static void power_cycle(void) {
    assert(!memory_live && !files[0].open && !files[1].open);
    for (unsigned int i = 0; i < 2; ++i) {
        memcpy(files[i].bytes, files[i].durable, files[i].durable_size);
        files[i].size = files[i].durable_size;
        files[i].position = 0;
    }
}
int main(void) {
    const char *armed = "# TLS_FIXER\n*KERNEL\nur0:tai/tls_fixer.skprx\n*main\nur0:tai/henkaku.suprx\n";
    const char *disabled = "# TLS_FIXER\n*KERNEL\n#r0:tai/tls_fixer.skprx\n*main\nur0:tai/henkaku.suprx\n";
    reset(armed);
    assert(tls_fixer_self_disarm() == 0);
    assert(writes == 1 && syncs >= 1);
    expect_bytes(0, disabled);
    power_cycle();
    assert(tls_fixer_self_disarm() != 0);
    assert(writes == 1);
    expect_bytes(0, disabled);

    reset("*KERNEL\nux0:/data/tls_fixer-one-shot/tls_fixer.skprx\n*main\nur0:tai/henkaku.suprx\n");
    assert(tls_fixer_self_disarm() == 0 && writes == 1);
    expect_bytes(0, "*KERNEL\n#x0:/data/tls_fixer-one-shot/tls_fixer.skprx\n*main\nur0:tai/henkaku.suprx\n");
    power_cycle();
    assert(tls_fixer_self_disarm() != 0 && writes == 1);
    reset("*KERNEL\nux0:data/tls_fixer-one-shot/tls_fixer.skprx\n");
    assert(tls_fixer_self_disarm() == 0 && writes == 1);
    expect_bytes(0, "*KERNEL\n#x0:data/tls_fixer-one-shot/tls_fixer.skprx\n");

    reset("#ur0:tai/tls_fixer.skprx\r\n*KERNEL\r\n  ur0:/tai/tls_fixer.skprx  \r\n"
          "ur0:tai/tls_fixer.skprx # literal-path-not-comment\r\n"
          "ur0:tai/other.skprx\r\n*main\r\nur0:tai/tls_fixer.skprx\r\n*KERNEL\r\nur0:tai/tls_fixer.skprx");
    assert(tls_fixer_self_disarm() == 0 && writes == 2);
    expect_bytes(0, "#ur0:tai/tls_fixer.skprx\r\n*KERNEL\r\n  #r0:/tai/tls_fixer.skprx  \r\n"
          "ur0:tai/tls_fixer.skprx # literal-path-not-comment\r\n"
          "ur0:tai/other.skprx\r\n*main\r\nur0:tai/tls_fixer.skprx\r\n*KERNEL\r\n#r0:tai/tls_fixer.skprx");

    reset("*KERNEL\nur0:tai/tls_fixer.skprx\n*\tKERNEL\r\vur0:/tai/tls_fixer.skprx\f\r* ! KERNEL\rur0:tai/tls_fixer.skprx");
    assert(tls_fixer_self_disarm() == 0 && writes == 3);
    expect_bytes(0, "*KERNEL\n#r0:tai/tls_fixer.skprx\n*\tKERNEL\r\v#r0:/tai/tls_fixer.skprx\f\r* ! KERNEL\r#r0:tai/tls_fixer.skprx");

    reset("*KERNEL\nur0:tai/tls_fixer.skprx\nUR0:/TAI/TLS_FIXER.SKPRX\n");
    assert(tls_fixer_self_disarm() == 0 && writes == 2);
    expect_bytes(0, "*KERNEL\n#r0:tai/tls_fixer.skprx\n#R0:/TAI/TLS_FIXER.SKPRX\n");
    reset("*KERNEL\nur0:tai/tls_fixer.skprx\nux0:tai/tls_fixer.skprx\n");
    assert(tls_fixer_self_disarm() != 0 && writes == 0);

    reset(armed);
    install_file(1, "*KERNEL\nur0:/tai/tls_fixer.skprx\n");
    assert(tls_fixer_self_disarm() == 0 && writes == 2);
    expect_bytes(0, disabled);
    expect_bytes(1, "*KERNEL\n#r0:/tai/tls_fixer.skprx\n");
    power_cycle();
    assert(tls_fixer_self_disarm() != 0);

    const char *inactive[] = {NULL, "", "*KERNEL\n#ur0:tai/tls_fixer.skprx\n", "*main\nur0:tai/tls_fixer.skprx\n",
        "*KERNEL\nur0:tai/tls_fixer.skprx.bak\n", "*KERNEL\nur0:tai/something-tls_fixer.skprx\n"};
    for (size_t i = 0; i < sizeof(inactive)/sizeof(inactive[0]); ++i) {
        reset(inactive[i]);
        assert(tls_fixer_self_disarm() != 0 && writes == 0);
    }
    reset(armed);
    files[0].bytes[0] = 0;
    assert(tls_fixer_self_disarm() != 0 && writes == 0);
    reset(armed);
    files[0].size = TLS_FIXER_SELF_DISARM_MAX_CONFIG + 1;
    assert(tls_fixer_self_disarm() != 0 && writes == 0);

    const char failures[] = {'a', 'b', 'o', 'l', 'r', 'e', 'w', 'z', 's', 'c', 'f'};
    for (size_t i = 0; i < sizeof(failures); ++i) {
        reset(armed);
        failing_event = failures[i];
        assert(tls_fixer_self_disarm() != 0);
        assert(!memory_live && !files[0].open && !files[1].open);
        assert(files[0].size == strlen(armed));
        for (size_t j = 0; j < files[0].size; ++j) {
            assert(files[0].bytes[j] == (unsigned char)armed[j] ||
                (armed[j] == 'u' && files[0].bytes[j] == '#'));
        }
    }
    reset(armed);
    corrupt_verify = 1;
    assert(tls_fixer_self_disarm() != 0);
    reset(armed);
    failing_event = 's'; fail_n = 2;
    assert(tls_fixer_self_disarm() != 0);
    reset(armed);
    install_file(1, "*KERNEL\nur0:tai/tls_fixer.skprx\n");
    failing_event = 'o'; fail_n = 3;
    assert(tls_fixer_self_disarm() != 0);
    const struct {
        char event;
        int occurrence;
        const char *stage;
        int code, config;
        unsigned int written, verified;
    } report_cases[] = {
        {'a', 1, "gate.alloc", -1, -1, 0, 0},
        {'b', 1, "gate.base", -1, -1, 0, 0},
        {'o', 1, "gate.open", -123, 0, 0, 0},
        {'l', 1, "gate.size", -1, 0, 0, 0},
        {'l', 2, "gate.seek", -1, 0, 0, 0},
        {'r', 1, "gate.read", -1, 0, 0, 0},
        {'w', 1, "gate.write", -1, 0, 0, 0},
        {'z', 1, "gate.write", 0, 0, 0, 0},
        {'s', 1, "gate.file_sync", -1, 0, 1, 0},
        {'c', 1, "gate.close", -1, 0, 1, 0},
        {'s', 2, "gate.mount_sync", -1, 0, 1, 0},
        {'o', 2, "gate.verify_open", -123, 0, 1, 0},
        {'c', 2, "gate.verify_close", -1, 0, 1, 0},
        {'o', 3, "gate.open", -123, 1, 1, 1},
        {'f', 1, "gate.free", -1, -1, 1, 1}
    };
    for (size_t i = 0; i < sizeof(report_cases) / sizeof(report_cases[0]); ++i) {
        reset(armed);
        failing_event = report_cases[i].event;
        fail_n = report_cases[i].occurrence;
        assert(tls_fixer_self_disarm() != 0);
        const TlsFixerDisarmReport *report = tls_fixer_self_disarm_report();
        assert(report->stage != NULL && strcmp(report->stage, report_cases[i].stage) == 0);
        assert(report->native_result == report_cases[i].code);
        assert(report->config_index == report_cases[i].config);
        assert(report->written_entries == report_cases[i].written);
        assert(report->verified_configs == report_cases[i].verified);
    }
    reset(armed);
    assert(tls_fixer_self_disarm() == 0);
    assert(strcmp(tls_fixer_self_disarm_report()->stage, "gate.complete") == 0);
    assert(tls_fixer_self_disarm_report()->native_result == 0);
    assert(tls_fixer_self_disarm_report()->written_entries == 1);
    assert(tls_fixer_self_disarm_report()->verified_configs == 1);
    reset(NULL);
    puts("startup self-disarm: surgical comments, duplicates, alternate config, persistence/reboot and I/O failures PASS");
    return 0;
}
