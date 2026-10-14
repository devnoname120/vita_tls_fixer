#include <stddef.h>
#include <psp2kern/kernel/modulemgr.h>

/* Native queries write a firmware-defined layout, independently of host test shims. */
_Static_assert(sizeof(void *) == 4, "ARM32 pointers");
_Static_assert(sizeof(SceSize) == 4, "Module-list count width");
_Static_assert(sizeof(SceKernelModuleInfo) == 0x1b8, "FW 3.60 module-info output extent");
_Static_assert(offsetof(SceKernelModuleInfo, modid) == 0x04, "Module PUID output");
_Static_assert(offsetof(SceKernelModuleInfo, modattr) == 0x08, "Declared SELF module attribute");
_Static_assert(offsetof(SceKernelModuleInfo, module_name) == 0x0c, "Module name output");
_Static_assert(offsetof(SceKernelModuleInfo, path) == 0x54, "Module path output");
_Static_assert(offsetof(SceKernelModuleInfo, segments) == 0x154, "Segment output");
_Static_assert(offsetof(SceKernelModuleInfo, state) == 0x1b4, "Lifecycle state output");
_Static_assert(sizeof(SceKernelSegmentInfo) == 0x18, "Segment stride");
_Static_assert(SCE_KERNEL_START_NO_RESIDENT == 1, "Nonresident is not failure");
_Static_assert(SCE_KERNEL_START_FAILED == 2, "Module-start failure result");
_Static_assert(__builtin_types_compatible_p(__typeof__(&ksceKernelGetModuleInfo),
    int (*)(SceUID, SceUID, SceKernelModuleInfo *)), "Module-info prototype");
_Static_assert(__builtin_types_compatible_p(__typeof__(&ksceKernelGetModuleList),
    int (*)(SceUID, int, int, SceUID *, SceSize *)), "Module-list prototype");
