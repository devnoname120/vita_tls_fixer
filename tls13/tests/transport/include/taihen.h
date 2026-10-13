#ifndef TLS_FIXER_MOCK_TAIHEN_H
#define TLS_FIXER_MOCK_TAIHEN_H
#include <stdint.h>
#include <stddef.h>
typedef uintptr_t tai_hook_ref_t;
typedef struct {
    size_t size;
    int modid;
    uint32_t module_nid;
    char name[27];
    uintptr_t exports_start, exports_end, imports_start, imports_end;
} tai_module_info_t;
int taiGetModuleInfo(const char *, tai_module_info_t *);
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
extern int mock_ssl_shared;
unsigned int mock_hooks_active(void);
#endif
