#ifndef TLS_FIXER_EMBEDDED_HTTP_H
#define TLS_FIXER_EMBEDDED_HTTP_H

#include <stddef.h>
#include <stdint.h>
#include <psp2/types.h>
#include <psp2/net/http.h>
#include "native_cert.h"

typedef int (*TlsFixerNativeEntry)(SceSize, const void *);
typedef struct TlsFixerEmbeddedBindings {
    uint32_t magic, version;
    void *text, *data;
    TlsFixerNativeEntry start, stop;
    int (*http_init)(unsigned int);
    int (*http_term)(void);
    int (*create)(void *, int);
    int (*connect)(void *);
    int (*map_io)(void *, int);
    int (*read)(void *, void *, unsigned int);
    int (*write)(void *, const void *, unsigned int);
    int (*shutdown)(void *);
    int (*load_cert)(int, const SceHttpsData **, const SceHttpsData *, const SceHttpsData *);
    int (*unload_cert)(void);
    void *redirects[3];
    TlsFixerNativeCertApi certificates;
    int (*enable_private)(int, unsigned int);
    int (*disable_private)(int, unsigned int);
    int (*acquire_object)(void **, int, unsigned int, int);
    int (*release_object[3])(void *);
    int (*copy_settings)(const void *, void *);
    void (*destroy_settings)(void *);
    int (*free_allocation)(void *, void *);
} TlsFixerEmbeddedBindings;

#if UINTPTR_MAX == UINT32_MAX
_Static_assert(sizeof(TlsFixerEmbeddedBindings) == 152, "embedded binding ABI");
#endif
extern TlsFixerEmbeddedBindings g_tls_fixer_embedded_bindings;

int tls_fixer_embedded_enter(void);
void tls_fixer_embedded_leave(void);
int tls_fixer_embedded_cert_init(void);
void tls_fixer_embedded_cert_destroy(void);
void tls_fixer_embedded_redirect_init(void);
void tls_fixer_embedded_redirect_destroy(void);
int tls_fixer_embedded_redirect_connection(int, const char *, const char *, unsigned short, int);
int tls_fixer_embedded_redirect_connection_url(int, const char *, int);
int tls_fixer_embedded_redirect_request_url(int, int, const char *, SceULong64);
void tls_fixer_embedded_profile_init(void);
void tls_fixer_embedded_profile_destroy(void);
int tls_fixer_embedded_profile_for_request(const void *);
int tls_fixer_embedded_enable_private(int, unsigned int);
int tls_fixer_embedded_disable_private(int, unsigned int);
int tls_fixer_embedded_copy_settings(const void *, void *);
void tls_fixer_embedded_destroy_settings(void *);
int tls_fixer_embedded_free_failed_connection(void *, void *);
int tls_fixer_embedded_free_failed_request(void *, void *);
#if TLS_FIXER_EMBEDDED_COMPARE_HTTP
void tls_fixer_embedded_compare_write(void *, const void *, unsigned int, int, int);
void tls_fixer_embedded_compare_connected(void *);
void tls_fixer_embedded_compare_identity(void *);
void tls_fixer_embedded_capture_hello(void *, const unsigned char *, size_t, int);
void tls_fixer_embedded_observe_native_bio(void *, int);
#endif

#endif
