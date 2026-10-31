#ifndef TLS_FIXER_HELLO_POLICY_H
#define TLS_FIXER_HELLO_POLICY_H

#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>

typedef struct TlsFixerHelloEntry TlsFixerHelloEntry;
typedef struct TlsFixerHelloPolicy {
    TlsFixerHelloEntry *entries;
    void *(*allocate)(size_t);
    void (*release)(void *);
    atomic_int uncertain;
} TlsFixerHelloPolicy;

/* Callers serialize the list. An uncertain result selects the original native
 * transport until HTTP termination, rather than guessing a handshake profile. */
void tls_fixer_hello_policy_init(TlsFixerHelloPolicy *, void *(*)(size_t), void (*)(void *));
void tls_fixer_hello_policy_clear(TlsFixerHelloPolicy *);
void tls_fixer_hello_policy_forget(TlsFixerHelloPolicy *, uintptr_t);
int tls_fixer_hello_policy_get(const TlsFixerHelloPolicy *, uintptr_t);
void tls_fixer_hello_policy_set(TlsFixerHelloPolicy *, uintptr_t, int);
void tls_fixer_hello_policy_private_result(TlsFixerHelloPolicy *, uintptr_t, unsigned int, int, int);

#endif
