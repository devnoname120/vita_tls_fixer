#define _GNU_SOURCE
#include "runtime_udp.h"
#define main runtime_hook_fixture
#include "test_module.c"
#undef main

static unsigned int marks[TLS_FIXER_RT_STAGE_LIMIT];

void tls_fixer_runtime_mark(unsigned int stage, int32_t result) {
    (void)result;
    assert(stage > 0 && stage < TLS_FIXER_RT_STAGE_LIMIT);
    ++marks[stage];
}

int main(int argc, char **argv) {
    int result = runtime_hook_fixture(argc, argv);
    assert(marks[TLS_FIXER_RT_CONNECT_ENTER] == 1);
    assert(marks[TLS_FIXER_RT_LEGACY_ENTER] == 1 && marks[TLS_FIXER_RT_LEGACY_RETURN] == 1);
    assert(marks[TLS_FIXER_RT_CLOSE_ENTER] == 1 && marks[TLS_FIXER_RT_CLOSE_RETURN] == 1);
    assert(marks[TLS_FIXER_RT_PENDING_ENTER] == 1 && marks[TLS_FIXER_RT_PENDING_RETURN] == 1);
    assert(marks[TLS_FIXER_RT_CHECK_ENTER] == 1 && marks[TLS_FIXER_RT_CHECK_RETURN] == 1);
    return result;
}
