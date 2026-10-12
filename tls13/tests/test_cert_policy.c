#include "tls_fixer/cert_policy.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>

static int game_result, system_result, parameter_result, parameter_value;
static uint32_t sdk_version;
static unsigned int calls;

static int is_game(void) { calls |= 1; return game_result; }
static int is_system(void *address) {
    assert(address == (void *)(uintptr_t)0x1234);
    calls |= 2;
    return system_result;
}
static uint32_t get_sdk(void) { calls |= 4; return sdk_version; }
static int get_parameter(int selector, int *value) {
    assert(selector == 0x00563bfe);
    calls |= 8;
    *value = parameter_value;
    return parameter_result;
}

int main(void) {
    TlsFixerCertPolicy policy = {is_game, is_system, get_sdk, get_parameter};
    assert(!tls_fixer_cert_callback_accepted(-1, 0, 0x1234, &policy));
    assert(tls_fixer_cert_callback_accepted(0, 0, 0x1234, NULL));
    assert(calls == 0);
    assert(!tls_fixer_cert_callback_accepted(0, 4, 0x1234, NULL));
    sdk_version = 0x03570000;
    game_result = 0;
    parameter_result = -1;
    parameter_value = 1;
    assert(!tls_fixer_cert_callback_accepted(0, 4, 0x1234, &policy));
    assert(calls == (1 | 4 | 8));
    calls = 0;
    parameter_result = 0;
    parameter_value = 0;
    assert(!tls_fixer_cert_callback_accepted(1, 4, 0x1234, &policy));
    parameter_value = 1;
    assert(tls_fixer_cert_callback_accepted(1, 4, 0x1234, &policy));
    calls = 0;
    game_result = 1;
    system_result = 0;
    assert(tls_fixer_cert_callback_accepted(0, 0x3f, 0x1234, &policy));
    assert(calls == (1 | 2));
    calls = 0;
    system_result = -1;
    parameter_value = 0;
    sdk_version = 0x020fffff;
    assert(tls_fixer_cert_callback_accepted(0, 4, 0x1234, &policy));
    assert(calls == (1 | 2 | 4));
    sdk_version = 0x02100000;
    assert(!tls_fixer_cert_callback_accepted(0, 4, 0x1234, &policy));
    sdk_version = UINT32_MAX;
    assert(!tls_fixer_cert_callback_accepted(0, 4, 0x1234, &policy));
    calls = 0;
    assert(!tls_fixer_cert_callback_accepted(-1, 0x3f, 0x1234, &policy));
    assert(calls == 0);
    puts("certificate callback policy: post-callback permission checks PASS");
    return 0;
}
