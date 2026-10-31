#include "cert_facade.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static unsigned int decoded;
typedef struct MockName MockName;
typedef struct MockMethods {
    void *unused;
    int (*release)(void *);
    int (*clone)(void *, int, void **);
} MockMethods;
struct MockName { const MockMethods *interface; const unsigned char *bytes; unsigned char owned[2]; };
static MockName borrowed, owned;
static unsigned int created, released, clone_failure;
static void *expected_factory;
static int release_name(void *name) {
    assert(name == &borrowed || name == &owned);
    ++released;
    return 0;
}
static int clone_name(void *name, int mode, void **out) {
    assert(name == &borrowed && mode == 0);
    if (clone_failure) return 10005;
    owned.interface = borrowed.interface;
    memcpy(owned.owned, borrowed.bytes, 2);
    owned.bytes = owned.owned;
    *out = &owned;
    return 0;
}
static const MockMethods methods = {NULL, release_name, clone_name};
static int parse_name(void *factory, int format, unsigned int length, const void *data,
                       unsigned int *consumed, void **out) {
    assert(factory == expected_factory && format == 1 && length == 2);
    borrowed.interface = &methods;
    borrowed.bytes = data;
    *consumed = 2;
    *out = &borrowed;
    ++created;
    return 0;
}
static int decode(void *integer, int format, const void *data, unsigned int length) {
    assert(integer == &decoded && format == 2 && length == 15);
    assert(memcmp(data, "20510607080910Z", 15) == 0);
    ++decoded;
    return 0;
}

int main(void) {
    const unsigned char serial[] = {0x10, 0x20, 0x30};
    const unsigned char name[] = {0x30, 0};
    TlsFixerCertView view = {{serial,sizeof(serial)}, {name,sizeof(name)}, {name,sizeof(name)},
                            "20200102030405Z", "20510607080910Z"};
    TlsFixerNativeCertApi api = {.integer_decode = decode};
    TlsFixerCertFacade facade;
    assert(tls_fixer_cert_facade_init(&facade, &api, &decoded, &view) == 0);
    int (*get)(TlsFixerCertFacade *, int, void *);
    int (*convert)(TlsFixerCertFacade *, const void *, void *);
    memcpy(&get, (const char *)facade.interface + 9 * sizeof(void *), sizeof(get));
    memcpy(&convert, (const char *)facade.interface + 12 * sizeof(void *), sizeof(convert));
    struct {unsigned int length; const void *data;} s;
    struct {unsigned int tag, length; const void *data;} value;
    assert(get(&facade, 2, &s) == 0 && s.length == 3 && s.data == serial);
    for (int key = 4; key <= 7; ++key) {
        assert(get(&facade, key, &value) == 0);
        assert(value.tag == ((key == 4 || key == 7) ? 16u : 24u));
    }
    void *factory = NULL;
    assert(get(&facade, 32773, &factory) == 0 && factory == &facade.name_factory);
    assert(facade.name_factory.target == &decoded && facade.name_factory.owner == &facade);
    assert(get(&facade, 6, &value) == 0);
    assert(convert(&facade, &value, &decoded) == 0 && decoded == 1);
    value.data = "20510607080910Z";
    assert(convert(&facade, &value, &decoded) != 0 && decoded == 1);
    assert(get(&facade, 123, &value) != 0);
    tls_fixer_cert_facade_end(&facade);
    assert(get(&facade, 2, &s) != 0);
    assert(get(&facade, 32773, &factory) != 0);
    assert(convert(&facade, &value, &decoded) != 0);
    view.not_before[0] = 'x';
    assert(tls_fixer_cert_facade_init(&facade, &api, &decoded, &view) < 0);
    assert(get(&facade, 2, &s) != 0);
    view.not_before[0] = '2';
    struct {void *unused[6]; int (*create)(void *, int, unsigned int, const void *, unsigned int *, void **);}
        name_methods = {{0}, parse_name};
    struct {void *unused[20]; void *names;} factory_methods = {{0}, &name_methods};
    struct {void *interface;} native_factory = {&factory_methods};
    expected_factory = &native_factory;
    assert(tls_fixer_cert_facade_init(&facade, &api, &native_factory, &view) == 0);
    assert(get(&facade, 32773, &factory) == 0);
    const void *factory_interface, *name_interface;
    memcpy(&factory_interface, factory, sizeof(factory_interface));
    memcpy(&name_interface, (const char *)factory_interface + 20 * sizeof(void *), sizeof(name_interface));
    int (*create_name)(void *, int, unsigned int, const void *, unsigned int *, void **);
    memcpy(&create_name, (const char *)name_interface + 6 * sizeof(void *), sizeof(create_name));
    unsigned char source[2] = {0x30, 0};
    void *out = NULL;
    unsigned int consumed = 0;
    assert(create_name(factory, 1, 2, source, &consumed, &out) == 0 && out == &owned);
    assert(consumed == 2 && created == 1 && released == 1);
    memset(source, 0xa5, sizeof(source));
    assert(owned.bytes[0] == 0x30 && owned.bytes[1] == 0);
    assert(release_name(out) == 0 && released == 2);
    clone_failure = 1;
    assert(create_name(factory, 1, 2, source, &consumed, &out) == 10005 && out == NULL);
    assert(created == 2 && released == 3);
    tls_fixer_cert_facade_end(&facade);
    assert(create_name(factory, 1, 2, source, &consumed, &out) != 0 && created == 2);
    puts("Certificate facade property, stale-handle and native time dispatch checks passed");
    return 0;
}
