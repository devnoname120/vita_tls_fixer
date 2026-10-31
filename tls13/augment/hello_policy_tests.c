#include "hello_policy.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

static unsigned int g_allocations, g_live;
static int g_fail;
static void *allocate(size_t size) {
    ++g_allocations;
    if (g_fail) return NULL;
    void *p = malloc(size);
    assert(p != NULL);
    ++g_live;
    return p;
}
static void release(void *p) { assert(g_live > 0); --g_live; free(p); }

int main(void) {
    TlsFixerHelloPolicy p;
    tls_fixer_hello_policy_init(&p, allocate, release);
    /* Native defaults/public APIs may leave 0x40 and the override marker set.
     * Neither creates an explicit private-profile record. */
    assert(tls_fixer_hello_policy_get(&p, 0x1000) == 0);
    tls_fixer_hello_policy_private_result(&p, 0x1000, 0x25, 1, 0);
    tls_fixer_hello_policy_private_result(&p, 0x1000, 0x40, 1, -1);
    assert(g_allocations == 0);
    assert(tls_fixer_hello_policy_get(&p, 0x1000) == 0);

    tls_fixer_hello_policy_private_result(&p, 0x1000, 0x40, 1, 0);
    assert(tls_fixer_hello_policy_get(&p, 0x1000) == 1 && g_live == 1);
    tls_fixer_hello_policy_private_result(&p, 0x1000, 0x40, 1, 0);
    assert(g_allocations == 1 && g_live == 1);
    /* Settings copy snapshots the parent. Changing/deleting a template later
     * must not change the connection, request or internal cloned settings. */
    tls_fixer_hello_policy_set(&p, 0x2000, tls_fixer_hello_policy_get(&p, 0x1000));
    tls_fixer_hello_policy_set(&p, 0x3000, tls_fixer_hello_policy_get(&p, 0x2000));
    tls_fixer_hello_policy_set(&p, 0x4000, tls_fixer_hello_policy_get(&p, 0x3000));
    tls_fixer_hello_policy_private_result(&p, 0x1000, 0x40, 0, 0);
    assert(tls_fixer_hello_policy_get(&p, 0x1000) == 0);
    assert(tls_fixer_hello_policy_get(&p, 0x4000) == 1);
    tls_fixer_hello_policy_private_result(&p, 0x3000, 0x40, 0, -1);
    assert(tls_fixer_hello_policy_get(&p, 0x3000) == 1);
    tls_fixer_hello_policy_private_result(&p, 0x3000, 0x40, 0, 0);
    assert(tls_fixer_hello_policy_get(&p, 0x3000) == 0);
    assert(tls_fixer_hello_policy_get(&p, 0x4000) == 1);

    /* Cleanup happens before native allocation reuse. Reusing the address for
     * an ordinary connection must not inherit the old private profile. */
    tls_fixer_hello_policy_forget(&p, 0x4000);
    assert(tls_fixer_hello_policy_get(&p, 0x4000) == 0);
    tls_fixer_hello_policy_set(&p, 0x2000, 0);
    assert(g_live == 0);

    /* A successful native option update with untrackable metadata must keep
     * the native result and make provider selection conservative. */
    g_fail = 1;
    tls_fixer_hello_policy_private_result(&p, 0x5000, 0x40, 1, 0);
    assert(tls_fixer_hello_policy_get(&p, 0x5000) == -1);
    assert(tls_fixer_hello_policy_get(&p, 0x6000) == -1);
    g_fail = 0;
    tls_fixer_hello_policy_clear(&p);
    assert(tls_fixer_hello_policy_get(&p, 0x5000) == 0 && g_live == 0);
    tls_fixer_hello_policy_private_result(&p, 0, 0x40, 1, 0);
    assert(tls_fixer_hello_policy_get(&p, 0x6000) == -1);
    tls_fixer_hello_policy_clear(&p);

    /* Reinitialization releases every marker and permits modern TLS again. */
    for (uintptr_t i = 1; i <= 128; ++i)
        tls_fixer_hello_policy_private_result(&p, i, 0x40, 1, 0);
    assert(g_live == 128);
    tls_fixer_hello_policy_clear(&p);
    assert(g_live == 0 && tls_fixer_hello_policy_get(&p, 1) == 0);
    puts("Private HTTPS profile inheritance, failures, reuse and cleanup: PASS");
    return 0;
}
