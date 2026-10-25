#ifndef TLS_FIXER_PROVIDER_H
#define TLS_FIXER_PROVIDER_H

#include <stddef.h>
#include <stdint.h>

#include <taihen.h>
#include <psp2/types.h>

#include <mbedtls/x509_crt.h>
#include "ca_index.h"

#include "tls_fixer/cert_registry.h"
#include "tls_fixer/module_gate.h"
#include "tls_fixer/cert_policy.h"
#include "tls_fixer/registry.h"
#include "tls_fixer/sony_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TLS_FIXER_HOOK_COUNT 6

typedef enum TlsFixerProviderState {
    TLS_FIXER_PROVIDER_STOPPED = 0,
    TLS_FIXER_PROVIDER_STARTING,
    TLS_FIXER_PROVIDER_ACTIVE,
    TLS_FIXER_PROVIDER_STOPPING
} TlsFixerProviderState;

typedef struct TlsFixerProviderGlobal {
    TlsFixerProviderState state;
    int32_t libhttp_modid;
    uintptr_t text_address;
    size_t text_size;
    uintptr_t data_address;
    size_t data_size;
    uintptr_t global_https_options_address;
    int hook_ids[TLS_FIXER_HOOK_COUNT];
    tai_hook_ref_t hook_refs[TLS_FIXER_HOOK_COUNT];
    TlsFixerRegistry registry;
    TlsFixerCertPolicy cert_policy;
    TlsFixerCertRegistry cert_registry;
    SceUID registry_mutex;
    TlsFixerCaIndex ca_index;
    uint8_t registry_mutex_initialized;
    uint8_t ca_index_initialized;
    uint8_t crypto_initialized;
} TlsFixerProviderGlobal;

extern TlsFixerProviderGlobal g_tls_fixer_http;

int tls_fixer_http_validate_start_args(SceSize argc, const void *args, TlsFixerStartArgs *out);
int tls_fixer_http_validate_module(
    int32_t modid,
    uintptr_t *text_address,
    size_t *text_size,
    uintptr_t *data_address,
    size_t *data_size);
int tls_fixer_http_install_hooks(void);
void tls_fixer_http_release_hooks(void);
int tls_fixer_trust_store_init(void);
void tls_fixer_trust_store_free(void);

#ifdef __cplusplus
}
#endif

#endif
