#include "user_runtime.h"
#include <psp2/kernel/processmgr.h>
#include <psp2/kernel/modulemgr.h>
#include <psp2/io/stat.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

unsigned int _newlib_heap_size_user = 1024u * 1024u;

int main(void) {
    char path[160];
    (void)sceIoMkdir("ux0:/data/vita-tls-check", 0777);
    snprintf(path, sizeof(path), "ux0:/data/vita-tls-check/runtime-smoke-%08X-%llu.txt",
        (unsigned)sceKernelGetProcessId(), (unsigned long long)sceKernelGetSystemTimeWide());
    FILE *file = fopen(path, "w");
    if (file == NULL) return 1;
    unsigned failures = 0;
#define CHECK(name, condition) do { \
    int passed = !!(condition); \
    fprintf(file, "%s=%s\n", name, passed ? "PASS" : "FAIL"); \
    fflush(file); failures += !passed; \
} while (0)
    SceUID ids[64]; SceSize count = 64;
    int listed = sceKernelGetModuleList(0xff, ids, &count), libc = 0;
    for (unsigned i=0; listed>=0 && i<count && i<64; ++i) {
        SceKernelModuleInfo info = {0}; info.size = sizeof(info);
        if (sceKernelGetModuleInfo(ids[i], &info)>=0 && strcmp(info.module_name,"SceLibc")==0) libc=1;
    }
    CHECK("no_SceLibc", listed>=0 && count<64 && !libc);
    int initialized = tls_fixer_user_runtime_init();
    CHECK("runtime_init", initialized == 0);
    if (initialized == 0) {
        unsigned char *data = __wrap_calloc(32768, 4);
        int zero = data != NULL;
        for (unsigned i=0; data!=NULL && i<131072; ++i) if (data[i]) zero=0;
        CHECK("calloc_zero", zero);
        CHECK("malloc_alignment", data!=NULL && ((uintptr_t)data % 8)==0);
        CHECK("calloc_overflow", __wrap_calloc(SIZE_MAX, 2)==NULL);
        if (data != NULL) {
            __wrap_memset(data, 0x5a, 131072);
            unsigned char *grown=__wrap_realloc(data, 262144);
            CHECK("realloc_preserves", grown!=NULL && grown[0]==0x5a && grown[131071]==0x5a);
            if (grown != NULL) data=grown;
            __wrap_free(data);
        }
        char buffer[128];
        int result=__wrap_snprintf(buffer,sizeof(buffer),"hex=%08X time=%llu size=%zu",0x80431075u,
            1234567890123ULL,(size_t)17);
        fprintf(file,"formatted_rc=%d formatted=%s\n",result,buffer);
        CHECK("format_hex_u64_size", result==(int)strlen("hex=80431075 time=1234567890123 size=17") &&
            strcmp(buffer,"hex=80431075 time=1234567890123 size=17")==0);
        result=__wrap_snprintf(buffer,4,"%s","abcdef");
        fprintf(file,"truncated_rc=%d truncated=%s\n",result,buffer);
        CHECK("format_truncation", result==6 && strcmp(buffer,"abc")==0);
        result=__wrap_snprintf(NULL,0,"%s","abcdef");
        fprintf(file,"size_only_rc=%d\n",result);
        CHECK("format_size_only", result==6);
        CHECK("strings", __wrap_strlen("abc")==3 && __wrap_strcmp("abc","abc")==0);
        TlsFixerRuntimeStats stats={0};
        CHECK("heap_accounting", tls_fixer_user_runtime_stats(&stats)==0 && stats.outstanding==0);
        fprintf(file,"capacity=%u used=%u peak=%u outstanding=%u\n",stats.capacity,stats.used,stats.peak,stats.outstanding);
        CHECK("runtime_destroy", tls_fixer_user_runtime_destroy()==0);
    }
    fprintf(file,"failures=%u\n",failures);
    fclose(file);
    return failures ? 1 : 0;
}
