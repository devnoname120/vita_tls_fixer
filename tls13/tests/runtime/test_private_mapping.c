#include "private_mapping.h"
#include <assert.h>
#include <stdio.h>
#include <psp2/kernel/sysmem.h>

static SceKernelMemBlockInfo response;
static int query_error;
int sceKernelGetMemBlockInfoByAddr(void *address, SceKernelMemBlockInfo *info) {
    assert(address != NULL && info->size == sizeof(*info));
    *info = response;
    return query_error;
}

int main(void) {
    void *text = (void *)(uintptr_t)0x81160400;
    response = (SceKernelMemBlockInfo){ .mappedBase = (void *)(uintptr_t)0x81160000,
        .mappedSize = 0x1e000, .type = 0x0c20d050, .access = 5 };
    assert(tls_fixer_require_private_mapping(text, 119120, 1) == 0);
    response.access = 4;
    assert(tls_fixer_require_private_mapping(text, 119120, 1) == 0);
    const unsigned shared_types[] = {0x0320d050,0x03f0d050,0x0c20d060,0};
    for (unsigned i=0;i<4;++i) {
        response.type = (int)shared_types[i];
        assert(tls_fixer_require_private_mapping(text,119120,1)<0);
    }
    response.type = 0x0c20d050;
    response.access = 7;
    assert(tls_fixer_require_private_mapping(text,119120,1)<0);
    response.access = 5; response.mappedSize = 119120;
    assert(tls_fixer_require_private_mapping(text,119120,1)<0);
    response.mappedSize = 0x1e000; query_error = -1;
    assert(tls_fixer_require_private_mapping(text,119120,1)<0);
    query_error = 0;
    assert(tls_fixer_require_private_mapping(text,SIZE_MAX,1)<0);
    assert(tls_fixer_require_private_mapping(text,0,1)<0);
    response.mappedBase = (void *)(uintptr_t)0xe0000000;
    assert(tls_fixer_require_private_mapping(response.mappedBase,16,1)<0);
    response = (SceKernelMemBlockInfo){ .mappedBase=(void *)(uintptr_t)0x81080000,
        .mappedSize=0x1000,.type=0x0c20d060,.access=6 };
    assert(tls_fixer_require_private_mapping(response.mappedBase,0x640,0)==0);
    assert(tls_fixer_require_private_mapping(response.mappedBase,0x640,1)<0);
    puts("private RX/RW complete ranges accepted; shared, unknown, writable-code, truncated and failed queries rejected");
}
