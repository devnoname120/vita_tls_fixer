#include "cert_facade.h"

#include <limits.h>
#include <string.h>

typedef struct Asn1Value {
    unsigned int tag;
    unsigned int length;
    const void *data;
} Asn1Value;

typedef struct CertInterface {
    void *unused[9];
    int (*property)(TlsFixerCertFacade *, int, void *);
    void *unused2[2];
    int (*time_to_integer)(TlsFixerCertFacade *, const Asn1Value *, void *);
} CertInterface;

typedef int (*CreateName)(void *, int, unsigned int, const void *, unsigned int *, void **);
typedef struct NameFactoryInterface {
    void *unused[6];
    CreateName create;
} NameFactoryInterface;
typedef struct FactoryInterface {
    void *unused[20];
    const NameFactoryInterface *names;
} FactoryInterface;
typedef struct NameInterface {
    void *unused;
    int (*release)(void *);
    int (*clone)(void *, int, void **);
} NameInterface;

static int create_owned_name(void *object, int format, unsigned int length, const void *der,
                             unsigned int *consumed, void **out) {
    TlsFixerNameFactoryProxy *proxy = object;
    if (out == NULL) return 10017;
    *out = NULL;
    if (proxy == NULL || proxy->target == NULL || proxy->owner == NULL ||
        !__atomic_load_n(&proxy->owner->active, __ATOMIC_ACQUIRE)) return 10017;
    const FactoryInterface *factory = *(const FactoryInterface *const *)proxy->target;
    if (factory == NULL || factory->names == NULL || factory->names->create == NULL) return 10011;
    void *borrowed = NULL, *owned = NULL;
    int result = factory->names->create(proxy->target, format, length, der, consumed, &borrowed);
    if (result != 0) return result;
    if (borrowed == NULL) return 10005;
    const NameInterface *methods = *(const NameInterface *const *)borrowed;
    if (methods == NULL || methods->release == NULL || methods->clone == NULL) return 10011;
    /* Native clone mode 0 duplicates ASN.1 nodes and their bytes (internal
     * flag 2). Mode 1 only shares the nodes (flag 8) and is unsuitable here.
     * The returned object and its destructor belong entirely to Sony SSL. */
    result = methods->clone(borrowed, 0, &owned);
    (void)methods->release(borrowed);
    if (result != 0 || owned == NULL) {
        if (owned != NULL) {
            const NameInterface *owned_methods = *(const NameInterface *const *)owned;
            (void)owned_methods->release(owned);
        }
        return result != 0 ? result : 10005;
    }
    *out = owned;
    return 0;
}

static const NameFactoryInterface g_name_factory = {{0}, create_owned_name};
static const FactoryInterface g_factory_interface = {{0}, &g_name_factory};

#if UINTPTR_MAX == UINT32_MAX
_Static_assert(offsetof(CertInterface, property) == 36, "Sony certificate property slot");
_Static_assert(offsetof(CertInterface, time_to_integer) == 48, "Sony certificate time slot");
_Static_assert(sizeof(Asn1Value) == 12, "Sony ASN.1 property ABI");
_Static_assert(offsetof(FactoryInterface, names) == 80, "Sony name factory interface slot");
_Static_assert(offsetof(NameFactoryInterface, create) == 24, "Sony name factory create slot");
_Static_assert(offsetof(NameInterface, clone) == 8, "Sony name clone slot");
#endif

static int property(TlsFixerCertFacade *facade, int key, void *out) {
    if (facade == NULL || out == NULL || !__atomic_load_n(&facade->active, __ATOMIC_ACQUIRE))
        return 10017;
    if (key == 2) {
        struct Serial { unsigned int length; const void *data; } *serial = out;
        serial->length = (unsigned int)facade->view.serial.length;
        serial->data = facade->view.serial.data;
        return 0;
    }
    if (key == 32773) {
        *(void **)out = &facade->name_factory;
        return 0;
    }
    Asn1Value *value = out;
    switch (key) {
        case 4:
            *value = (Asn1Value){16, (unsigned int)facade->view.issuer.length, facade->view.issuer.data};
            return 0;
        case 7:
            *value = (Asn1Value){16, (unsigned int)facade->view.subject.length, facade->view.subject.data};
            return 0;
        case 5:
        case 6:
            *value = (Asn1Value){24, 15, key == 5 ? facade->view.not_before : facade->view.not_after};
            return 0;
        default:
            return 10021;
    }
}

static int time_to_integer(TlsFixerCertFacade *facade, const Asn1Value *value, void *integer) {
    if (facade == NULL || value == NULL || integer == NULL ||
        !__atomic_load_n(&facade->active, __ATOMIC_ACQUIRE) || value->tag != 24 || value->length != 15 ||
        (value->data != facade->view.not_before && value->data != facade->view.not_after)) return 10017;
    /* Sony's own certificate time adapter maps ASN.1 GeneralizedTime (24) to
     * native bigint input format 2. It subsequently uses the normal RTC API. */
    return facade->api->integer_decode(integer, 2, value->data, value->length);
}

static const CertInterface g_interface = {{0}, property, {0}, time_to_integer};

static int valid_time(const char *time) {
    for (unsigned int i = 0; i < 14; ++i)
        if (time[i] < '0' || time[i] > '9') return 0;
    return time[14] == 'Z' && time[15] == 0;
}

int tls_fixer_cert_facade_init(TlsFixerCertFacade *facade, const TlsFixerNativeCertApi *api,
                             void *factory, const TlsFixerCertView *view) {
    if (facade == NULL) return -1;
    memset(facade, 0, sizeof(*facade));
    facade->interface = &g_interface;
    if (api == NULL || api->integer_decode == NULL || factory == NULL || view == NULL ||
        view->serial.data == NULL || view->serial.length == 0 || view->serial.length > UINT_MAX ||
        view->issuer.data == NULL || view->issuer.length == 0 || view->issuer.length > UINT_MAX ||
        view->subject.data == NULL || view->subject.length == 0 || view->subject.length > UINT_MAX ||
        !valid_time(view->not_before) || !valid_time(view->not_after)) return -1;
    facade->api = api;
    facade->factory = factory;
    facade->name_factory = (TlsFixerNameFactoryProxy){&g_factory_interface, factory, facade};
    facade->view = *view;
    __atomic_store_n(&facade->active, 1, __ATOMIC_RELEASE);
    return 0;
}

void tls_fixer_cert_facade_end(TlsFixerCertFacade *facade) {
    if (facade != NULL) __atomic_store_n(&facade->active, 0, __ATOMIC_RELEASE);
}
