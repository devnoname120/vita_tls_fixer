#include "webkit_callback.h"
#include "runtime_udp.h"
#include "../provider/diagnostics.h"

#include <psp2/kernel/modulemgr.h>
#include <psp2/kernel/sysmem.h>
#include <psp2common/kernel/modulemgr.h>

#include <stdint.h>
#include <string.h>

static int reject_callback(unsigned int reason) {
    tls_fixer_runtime_mark(TLS_FIXER_RT_CALLBACK_REJECT, (int32_t)reason);
    TLS_FIXER_LOG("browser default callback rejected: reason=%u", reason);
    (void)reason;
    return 0;
}

static unsigned int request_range_rejection(const void *userdata,
    const SceKernelMemBlockInfo *info) {
    uintptr_t address = (uintptr_t)userdata;
    uintptr_t base = (uintptr_t)info->mappedBase;
    size_t mapped_size = (size_t)info->mappedSize;
    size_t offset;

    if (info->mappedBase == NULL || address < base) return TLS_FIXER_WEBKIT_REJECT_USERDATA_RANGE;
    offset = (size_t)(address - base);
    if (offset > mapped_size || TLS_FIXER_WEBKIT_REQUEST_SIZE > mapped_size - offset) {
        return TLS_FIXER_WEBKIT_REJECT_USERDATA_RANGE;
    }
    if ((info->access & (SCE_KERNEL_MEMORY_ACCESS_R | SCE_KERNEL_MEMORY_ACCESS_W)) !=
            (SCE_KERNEL_MEMORY_ACCESS_R | SCE_KERNEL_MEMORY_ACCESS_W)) {
        return TLS_FIXER_WEBKIT_REJECT_USERDATA_ACCESS;
    }
    return 0;
}

int tls_fixer_webkit_is_default_ctx_callback(const void *callback, const void *userdata) {
    SceKernelModuleInfo module;
    SceKernelMemBlockInfo memory;
    uintptr_t tagged = (uintptr_t)callback;
    uintptr_t address;
    uintptr_t text;
    uintptr_t expected_vtable;
    uint32_t vtable;
    SceUID module_id;
    unsigned int rejection;

    if (callback == NULL || userdata == NULL || (tagged & 1u) == 0 ||
        ((uintptr_t)userdata & (sizeof(uint32_t) - 1u)) != 0) {
        return reject_callback(TLS_FIXER_WEBKIT_REJECT_ARGUMENT);
    }
    address = tagged & ~(uintptr_t)1u;
    module_id = sceKernelGetModuleIdByAddr((void *)address);
    if (module_id < 0) return reject_callback(TLS_FIXER_WEBKIT_REJECT_MODULE_LOOKUP);

    memset(&module, 0, sizeof(module));
    module.size = sizeof(module);
    if (sceKernelGetModuleInfo(module_id, &module) < 0) {
        return reject_callback(TLS_FIXER_WEBKIT_REJECT_MODULE_INFO);
    }
    if (memcmp(module.module_name, TLS_FIXER_WEBKIT_MODULE_NAME,
            sizeof(TLS_FIXER_WEBKIT_MODULE_NAME)) != 0) {
        return reject_callback(TLS_FIXER_WEBKIT_REJECT_MODULE_NAME);
    }
    if (module.segments[0].vaddr == NULL || module.segments[1].vaddr == NULL) {
        return reject_callback(TLS_FIXER_WEBKIT_REJECT_SEGMENT_ADDRESS);
    }
    int geometry_known = 0;
    for (size_t i = 0; i < sizeof(tls_fixer_webkit_profiles) / sizeof(tls_fixer_webkit_profiles[0]); ++i) {
        const TlsFixerWebKitProfile *candidate = &tls_fixer_webkit_profiles[i];
        if (module.segments[0].filesz == candidate->text_size &&
            module.segments[0].memsz == candidate->text_size &&
            module.segments[1].filesz == candidate->data_filesz &&
            module.segments[1].memsz == candidate->data_memsz) { geometry_known = 1; break; }
    }
    if (!geometry_known) {
        return reject_callback(TLS_FIXER_WEBKIT_REJECT_SEGMENT_GEOMETRY);
    }

    text = (uintptr_t)module.segments[0].vaddr;
    const TlsFixerWebKitProfile *profile = tls_fixer_select_webkit_profile(
        (const unsigned char *)text, module.segments[0].filesz, module.segments[0].memsz,
        module.segments[1].filesz, module.segments[1].memsz);
    if (profile == NULL) return reject_callback(TLS_FIXER_WEBKIT_REJECT_MODULE_IDENTITY);
    if (profile->callback_offset > module.segments[0].filesz ||
        sizeof(tls_fixer_webkit_ctx_callback_signature) >
            module.segments[0].filesz - profile->callback_offset ||
        address != text + profile->callback_offset) {
        return reject_callback(TLS_FIXER_WEBKIT_REJECT_CALLBACK_ADDRESS);
    }
    if (memcmp((const void *)address, profile->callback_signature,
            sizeof(tls_fixer_webkit_ctx_callback_signature)) != 0) {
        return reject_callback(TLS_FIXER_WEBKIT_REJECT_CALLBACK_SIGNATURE);
    }

    memset(&memory, 0, sizeof(memory));
    memory.size = sizeof(memory);
    if (sceKernelGetMemBlockInfoByAddr((void *)userdata, &memory) < 0) {
        return reject_callback(TLS_FIXER_WEBKIT_REJECT_USERDATA_INFO);
    }
    rejection = request_range_rejection(userdata, &memory);
    if (rejection != 0) {
        return reject_callback(rejection);
    }

    expected_vtable = text + profile->vtable_offset;
    if (expected_vtable > UINT32_MAX) {
        return reject_callback(TLS_FIXER_WEBKIT_REJECT_VTABLE_RANGE);
    }
    memcpy(&vtable, userdata, sizeof(vtable));
    if (vtable != (uint32_t)expected_vtable) {
        return reject_callback(TLS_FIXER_WEBKIT_REJECT_VTABLE_VALUE);
    }
    return 1;
}
