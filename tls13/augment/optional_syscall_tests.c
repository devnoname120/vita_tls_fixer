#include "optional_syscall.h"
#include <assert.h>
#include <stdio.h>

int main(void) {
    const uint32_t unresolved[] = {0xe24fc008, 0xe3a0f000, 0xe1a00000};
    const uint32_t file_placeholder[] = {0xe3e00000, 0xe12fff1e, 0xe1a00000};
    const uint32_t user_function[] = {0xe300c100, 0xe348c100, 0xe12fff1c};
    assert(!tls_fixer_syscall_stub_bound(0));
    assert(!tls_fixer_syscall_stub_bound(unresolved));
    assert(!tls_fixer_syscall_stub_bound(file_placeholder));
    assert(!tls_fixer_syscall_stub_bound(user_function));
    assert(!tls_fixer_user_stub_bound(0));
    assert(!tls_fixer_user_stub_bound(unresolved));
    assert(!tls_fixer_user_stub_bound(file_placeholder));
    assert(tls_fixer_user_stub_bound(user_function));
    for (unsigned int ordinal = 0; ordinal < 4096; ++ordinal) {
        uint32_t code[] = {0xe300c000 | ordinal, 0xef000000, 0xe12fff1e};
        assert(tls_fixer_syscall_stub_bound(code));
        assert(!tls_fixer_user_stub_bound(code));
        for (unsigned int word = 0; word < 3; ++word) {
            for (unsigned int bit = word == 0 ? 12 : 0; bit < 32; ++bit) {
                code[word] ^= UINT32_C(1) << bit;
                assert(!tls_fixer_syscall_stub_bound(code));
                code[word] ^= UINT32_C(1) << bit;
            }
        }
    }
    const uint32_t targets[] = {0, 1, 0x7fffffff, 0x80000000, 0x8180abcd,
                                0xe0604001, 0xefffffff, 0xf0000000, 0xffffffff};
    for (unsigned int i = 0; i < sizeof(targets) / sizeof(targets[0]); ++i) {
        uint32_t target = targets[i];
        uint32_t code[] = {0xe300c000 | (target & 0xfff) | ((target & 0xf000) << 4),
                          0xe340c000 | ((target >> 16) & 0xfff) | ((target >> 12) & 0xf0000),
                          0xe12fff1c};
        int valid = target >= 0x80000000 && target < 0xf0000000;
        assert(tls_fixer_user_stub_bound(code) == valid);
        if (!valid) continue;
        for (unsigned int word = 0; word < 3; ++word) {
            for (unsigned int bit = 0; bit < 32; ++bit) {
                uint32_t changed = UINT32_C(1) << bit;
                if (word < 2 && (changed & UINT32_C(0xfff0f000)) == 0) continue;
                code[word] ^= changed;
                assert(!tls_fixer_user_stub_bound(code));
                code[word] ^= changed;
            }
        }
    }
    puts("Optional syscall and user imports reject unresolved, wrong-kind and malformed stubs");
    return 0;
}
