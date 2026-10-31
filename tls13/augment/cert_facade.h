#ifndef TLS_FIXER_CERT_FACADE_H
#define TLS_FIXER_CERT_FACADE_H

#include "native_cert.h"

typedef struct TlsFixerCertView {
    TlsFixerNativeCertDer serial;
    TlsFixerNativeCertDer issuer;
    TlsFixerNativeCertDer subject;
    char not_before[16]; /* GeneralizedTime YYYYMMDDhhmmssZ, then NUL. */
    char not_after[16];
} TlsFixerCertView;

struct TlsFixerCertFacade;
typedef struct TlsFixerNameFactoryProxy {
    const void *interface;
    void *target;
    struct TlsFixerCertFacade *owner;
} TlsFixerNameFactoryProxy;

typedef struct TlsFixerCertFacade {
    const void *interface;
    const TlsFixerNativeCertApi *api;
    void *factory;
    TlsFixerNameFactoryProxy name_factory;
    TlsFixerCertView view;
    uint8_t active;
} TlsFixerCertFacade;

int tls_fixer_cert_facade_init(TlsFixerCertFacade *facade, const TlsFixerNativeCertApi *api,
                             void *factory, const TlsFixerCertView *view);
void tls_fixer_cert_facade_end(TlsFixerCertFacade *facade);

#endif
