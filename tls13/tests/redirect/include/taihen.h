#ifndef TLS_FIXER_REDIRECT_TEST_TAIHEN_H
#define TLS_FIXER_REDIRECT_TEST_TAIHEN_H
#include <psp2/types.h>

/* taiHEN's hook record, laid out as in taihen.h, and the one call the code makes */
typedef uintptr_t tai_hook_ref_t;
struct _tai_hook_user {
    uintptr_t next;
    void *func;
    void *old;
};
SceUID taiHookFunctionExport(tai_hook_ref_t *reference, const char *module, uint32_t library_nid,
                             uint32_t function_nid, const void *function);

int taiHookRelease(SceUID hook_id, tai_hook_ref_t reference);
#endif
