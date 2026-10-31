#include "hello_policy.h"

struct TlsFixerHelloEntry {
    uintptr_t settings;
    TlsFixerHelloEntry *next;
};

void tls_fixer_hello_policy_init(TlsFixerHelloPolicy *p, void *(*allocate)(size_t), void (*release)(void *)) {
    p->entries = NULL;
    p->allocate = allocate;
    p->release = release;
    atomic_init(&p->uncertain, 0);
}

void tls_fixer_hello_policy_clear(TlsFixerHelloPolicy *p) {
    while (p->entries != NULL) {
        TlsFixerHelloEntry *entry = p->entries;
        p->entries = entry->next;
        p->release(entry);
    }
    atomic_store(&p->uncertain, 0);
}

void tls_fixer_hello_policy_forget(TlsFixerHelloPolicy *p, uintptr_t settings) {
    TlsFixerHelloEntry **slot = &p->entries;
    while (*slot != NULL) {
        if ((*slot)->settings == settings) {
            TlsFixerHelloEntry *entry = *slot;
            *slot = entry->next;
            p->release(entry);
            return;
        }
        slot = &(*slot)->next;
    }
}

int tls_fixer_hello_policy_get(const TlsFixerHelloPolicy *p, uintptr_t settings) {
    if (atomic_load(&p->uncertain)) return -1;
    for (const TlsFixerHelloEntry *entry = p->entries; entry != NULL; entry = entry->next)
        if (entry->settings == settings) return 1;
    return 0;
}

void tls_fixer_hello_policy_set(TlsFixerHelloPolicy *p, uintptr_t settings, int profile) {
    if (profile < 0 || settings == 0) {
        atomic_store(&p->uncertain, 1);
        return;
    }
    if (!profile) {
        tls_fixer_hello_policy_forget(p, settings);
        return;
    }
    /* Repeated enable calls do not allocate. Ordinary connections allocate no
     * tracking node; a node is just two words in a Vita process. */
    for (TlsFixerHelloEntry *entry = p->entries; entry != NULL; entry = entry->next)
        if (entry->settings == settings) return;
    TlsFixerHelloEntry *entry = p->allocate(sizeof(*entry));
    if (entry == NULL) {
        atomic_store(&p->uncertain, 1);
        return;
    }
    entry->settings = settings;
    entry->next = p->entries;
    p->entries = entry;
}

void tls_fixer_hello_policy_private_result(TlsFixerHelloPolicy *p, uintptr_t settings,
    unsigned int flags, int enable, int result) {
    if (result >= 0 && (flags & 0x40u) != 0)
        tls_fixer_hello_policy_set(p, settings, enable);
}
