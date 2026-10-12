#ifndef TLS_FIXER_MOCK_TAIHEN_H
#define TLS_FIXER_MOCK_TAIHEN_H
#include <stdint.h>
#include <stddef.h>
typedef uintptr_t tai_hook_ref_t;
struct _tai_hook_user {
    struct _tai_hook_user *next;
    void *func;
    void *old;
};
int taiHookFunctionExport(tai_hook_ref_t *, const char *, uint32_t, uint32_t, const void *);
int taiHookRelease(int, tai_hook_ref_t);
int taiHookFunctionOffset(tai_hook_ref_t *, int, int, size_t, int, const void *);
const void *mock_hook_by_nid(uint32_t);
extern int mock_hook_fail_index;
extern int mock_legacy_certificate_result;
unsigned int mock_hooks_active(void);
#endif
