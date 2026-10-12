#include <kernel_mock.h>
#include "hook_guard.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#define MODULE_ID 11
#define TEXT_SIZE 0xef84

_Alignas(4) static unsigned char text[TEXT_SIZE];
static SceKernelModuleInfo fixture;
static int query_result, query_calls;

static const struct {
    size_t offset;
    const char *hex;
    const char *mask;
} sites[] = {
    {0x21ec, "2de9f04f4af20407c0f2ae07", "fffffffff0fb008ff0fb008f"},
    {0x21f8, "064689b00c463868904607901bb11b68042b40f0ef80002e00f0b880"
        "18f001054ff00503c0f2010300f0ac809e4200f0b2813046fff74afe0028c0f27b81", NULL},
    {0x2384, "09f00ae9064643e7", NULL},
    {0x23f8, "0122002308f046ee054664e7", NULL},
#if TLS_FIXER_BROWSER_POST_START
    {0x286c, "2de9f04f4af2040689b0c0f2ae06", "fffffffff0fb008ffffff0fb008f"},
    {0x287a, "0025074634688846ddf84ce09246059599460794129d149cbef1000f25d0def80030102b1cbf", NULL},
    {0x29b2, "0df1140e00204a462b46cde900e051460bf10800fff7f9f88146404608f0b6eb059b012b1cd0022b15d0b9f1", NULL},
#endif
};

static unsigned char hex_byte(const char *hex) {
    unsigned int value;
    assert(sscanf(hex, "%2x", &value) == 1);
    return (unsigned char)value;
}

static void reset(void) {
    memset(&fixture, 0, sizeof(fixture));
    memset(text, 0, sizeof(text));
    fixture.size = sizeof(fixture);
    fixture.modid = MODULE_ID;
    fixture.modattr = 7;
    fixture.modver[0] = fixture.modver[1] = 1;
    strcpy(fixture.module_name, "SceKernelModulemgr");
    fixture.start_entry = (void *)((uintptr_t)text + 0x378d);
    fixture.segments[0].size = sizeof(SceKernelSegmentInfo);
    fixture.segments[0].perms = 5;
    fixture.segments[0].vaddr = text;
    fixture.segments[0].memsz = fixture.segments[0].filesz = TEXT_SIZE;
    for (size_t i = 0; i < sizeof(sites) / sizeof(sites[0]); ++i) {
        size_t length = strlen(sites[i].hex) / 2;
        assert(sites[i].offset + length <= sizeof(text));
        for (size_t n = 0; n < length; ++n) {
            text[sites[i].offset + n] = hex_byte(sites[i].hex + n * 2);
        }
    }
    query_result = query_calls = 0;
}

int ksceKernelGetModuleInfo(SceUID pid, SceUID module, SceKernelModuleInfo *info) {
    assert(pid == 0x10005 && module == MODULE_ID);
    assert(info != NULL && info->size == sizeof(*info));
    const unsigned char *raw = (const unsigned char *)info;
    for (size_t i = sizeof(info->size); i < sizeof(*info); ++i) assert(raw[i] == 0);
    ++query_calls;
    if (query_result < 0) return query_result;
    *info = fixture;
    return query_result;
}

static void expect_rejected(void) {
    assert(tls_fixer_validate_loader_hook(MODULE_ID) < 0);
}

int main(void) {
    reset();
    assert(tls_fixer_validate_loader_hook(0) < 0 && query_calls == 0);
    assert(tls_fixer_validate_loader_hook(-1) < 0 && query_calls == 0);
    assert(tls_fixer_validate_loader_hook(MODULE_ID) == 0 && query_calls == 1);

    reset(); query_result = -123; expect_rejected();
    reset(); fixture.modid = MODULE_ID + 1; expect_rejected();
    reset(); fixture.modattr ^= 1; expect_rejected();
    reset(); fixture.modver[0] = 2; expect_rejected();
    reset(); fixture.modver[1] = 2; expect_rejected();
    reset(); memset(fixture.module_name, 'x', sizeof(fixture.module_name)); expect_rejected();
    reset(); fixture.module_name[18] = 'x'; expect_rejected();
    reset(); fixture.start_entry = text; expect_rejected();
    reset(); fixture.segments[0].vaddr = NULL; expect_rejected();
    reset(); fixture.segments[0].vaddr = (void *)(uintptr_t)1; expect_rejected();
    reset(); fixture.segments[0].size = 0; expect_rejected();
    reset(); fixture.segments[0].filesz -= 1; expect_rejected();
    reset(); fixture.segments[0].filesz += 1; expect_rejected();
    reset(); fixture.segments[0].memsz = 16; expect_rejected();
    reset(); fixture.segments[0].perms = 6; expect_rejected();
    reset(); fixture.segments[0].vaddr = (void *)(UINTPTR_MAX - 7);
    fixture.start_entry = NULL; expect_rejected();

    reset();
    fixture.segments[0].perms |= 0x100000;
    fixture.segments[0].memsz += 0x1000;
    assert(tls_fixer_validate_loader_hook(MODULE_ID) == 0);

    reset();
    for (size_t i = 0; i < sizeof(sites) / sizeof(sites[0]); ++i) {
        size_t length = strlen(sites[i].hex) / 2;
        for (size_t n = 0; n < length; ++n) {
            unsigned char mask = sites[i].mask == NULL ? 0xff : hex_byte(sites[i].mask + n * 2);
            for (unsigned int bit = 1; bit <= 128; bit <<= 1) {
                text[sites[i].offset + n] ^= (unsigned char)bit;
                int result = tls_fixer_validate_loader_hook(MODULE_ID);
                assert((mask & bit) ? result < 0 : result == 0);
                text[sites[i].offset + n] ^= (unsigned char)bit;
            }
        }
    }
    assert(tls_fixer_validate_loader_hook(MODULE_ID) == 0);
    puts("kernel hook guard: metadata, bounds, changed instructions and relocated immediates PASS");
    return 0;
}
