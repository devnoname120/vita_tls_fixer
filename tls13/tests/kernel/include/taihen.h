#ifndef TLS_FIXER_KERNEL_TAIHEN_MOCK_H
#define TLS_FIXER_KERNEL_TAIHEN_MOCK_H
#include <kernel_mock.h>
typedef uintptr_t tai_hook_ref_t;
typedef struct {
    size_t size;
    SceUID modid;
    uint32_t module_nid;
    char name[27];
    uintptr_t exports_start, exports_end, imports_start, imports_end;
} tai_module_info_t;
int taiGetModuleInfoForKernel(SceUID, const char *, tai_module_info_t *);
#define KERNEL_PID 0x10005
#define TLS_FIXER_TAI_CONTINUE4(type, reference, ...) \
    ((type (*)(SceUID, const char *, uint32_t, int *))(reference))(__VA_ARGS__)
#define TLS_FIXER_TAI_CONTINUE7(type, reference, ...) \
    ((type (*)(SceUID, SceUID, SceSize, const void *, uint32_t, const void *, int *))(reference))(__VA_ARGS__)
#define TLS_FIXER_TAI_ARITY(_1, _2, _3, _4, _5, _6, _7, selected, ...) selected
#define TAI_CONTINUE(type, reference, ...) \
    TLS_FIXER_TAI_ARITY(__VA_ARGS__, TLS_FIXER_TAI_CONTINUE7, unused6, unused5, TLS_FIXER_TAI_CONTINUE4) \
        (type, reference, __VA_ARGS__)
int taiHookFunctionOffsetForKernel(SceUID, tai_hook_ref_t *, SceUID, int, size_t, int, const void *);
#endif
