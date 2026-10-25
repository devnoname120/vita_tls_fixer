#ifndef TLS_FIXER_REAUTH_TEST_TAIHEN_H
#define TLS_FIXER_REAUTH_TEST_TAIHEN_H
#include <psp2/kernel/modulemgr.h>

/* taiHEN, reduced to what the module calls; the tests implement these */
typedef uintptr_t tai_hook_ref_t;
typedef struct {
    size_t size;
    SceUID modid;
    uint32_t module_nid;
    char name[27];
} tai_module_info_t;

int taiGetModuleInfo(const char *module, tai_module_info_t *info);
SceUID taiHookFunctionImport(tai_hook_ref_t *reference, const char *module, uint32_t library_nid,
                             uint32_t function_nid, const void *function);
int taiHookRelease(SceUID hook_id, tai_hook_ref_t reference);

/* The module hooks one function, sceHttpCreateConnection; the tests store the original in the
 * reference, so continuing calls it directly */
#define TAI_CONTINUE(type, reference, ...) \
    ((type (*)(int, const char *, const char *, unsigned short, int))(reference))(__VA_ARGS__)

#endif
