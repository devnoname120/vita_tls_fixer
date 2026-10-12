#define _GNU_SOURCE
#include "runtime_udp.h"
#define main runtime_backend_fixture
#include "test_backend.c"
#undef main

static unsigned int marks[TLS_FIXER_RT_STAGE_LIMIT];

void tls_fixer_runtime_mark(unsigned int stage, int32_t result) {
    (void)result;
    assert(stage > 0 && stage < TLS_FIXER_RT_STAGE_LIMIT);
    __atomic_add_fetch(&marks[stage], 1, __ATOMIC_RELAXED);
}

int main(int argc, char **argv) {
    int result = runtime_backend_fixture(argc, argv);
    if (strcmp(argv[3], "legacy-existing") == 0) assert(marks[TLS_FIXER_RT_OPTIONS_ENTER] == 0);
    else assert(marks[TLS_FIXER_RT_OPTIONS_ENTER] > 0);
    assert(marks[TLS_FIXER_RT_OPTIONS_RETURN] == marks[TLS_FIXER_RT_OPTIONS_ENTER]);
    return result;
}
