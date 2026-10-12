#include "tls_fixer/cert_policy.h"
#include "tls_fixer/sony_abi.h"
#include <string.h>

int tls_fixer_cert_callback_accepted(int result, uint32_t verification_detail,
                                uintptr_t callback, const TlsFixerCertPolicy *policy) {
    int parameter = 0;
    if (result < 0) {
        return 0;
    }
    if (verification_detail == 0) {
        return 1;
    }
    if (policy == NULL || policy->is_game_program == NULL ||
        policy->is_system_callback == NULL || policy->compatibility_version == NULL ||
        policy->system_parameter == NULL) {
        return 0;
    }

    /* The original libhttp applies these checks after, not before, callback acceptance. */
    if (policy->is_game_program() != 0 && policy->is_system_callback((void *)callback) == 0) {
        return 1;
    }
    if (policy->compatibility_version() < UINT32_C(0x02100000)) {
        return 1;
    }
    return policy->system_parameter(0x00563bfe, &parameter) == 0 && parameter != 0;
}

int tls_fixer_cert_policy_bind(TlsFixerCertPolicy *policy, const void *text, size_t text_size) {
    uintptr_t base = (uintptr_t)text;
    if (policy == NULL) {
        return -1;
    }
    memset(policy, 0, sizeof(*policy));
    if (text == NULL || text_size != TLS_FIXER_LIBHTTP_TEXT_SIZE ||
        tls_fixer_read_u32(text, 0x1945c) != UINT32_C(0x347c1bdb) ||
        tls_fixer_read_u32(text, 0x19464) != UINT32_C(0xfff8f7f0) ||
        tls_fixer_read_u32(text, 0x194c4) != UINT32_C(0x9f793f84) ||
        tls_fixer_read_u32(text, 0x19514) != UINT32_C(0x85e6d2bb)) {
        return -1;
    }
    /* These are ARM import veneers in the independently hash-gated module, not Thumb functions. */
    policy->is_game_program = (int (*)(void))(base + 0x18380);
    policy->is_system_callback = (int (*)(void *))(base + 0x18620);
    policy->compatibility_version = (uint32_t (*)(void))(base + 0x18600);
    policy->system_parameter = (int (*)(int, int *))(base + 0x18360);
    return 0;
}
