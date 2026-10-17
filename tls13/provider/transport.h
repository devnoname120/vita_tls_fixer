#ifndef TLS_FIXER_TRANSPORT_H
#define TLS_FIXER_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>

#include <psp2/types.h>

#include <mbedtls/build_info.h>
#include <mbedtls/ssl.h>

#include "tls_fixer/error_map.h"
#include "tls_fixer/registry.h"
#include "tls_fixer/sony_abi.h"

#if MBEDTLS_VERSION_NUMBER != 0x04020000
#error "tls_fixer requires the pinned Mbed TLS 4.2.0 source build"
#endif

#ifndef MBEDTLS_SSL_PROTO_TLS1_3
#error "tls_fixer requires Mbed TLS TLS 1.3 support"
#endif

#if !defined(MBEDTLS_THREADING_C) || !defined(MBEDTLS_THREADING_ALT)
#error "tls_fixer requires the explicit Vita threading port"
#endif

typedef enum TlsFixerConnectionState {
    TLS_FIXER_CONNECTION_INITIALIZING = 0,
    TLS_FIXER_CONNECTION_HANDSHAKING,
    TLS_FIXER_CONNECTION_ACTIVE,
    TLS_FIXER_CONNECTION_FAILED,
    TLS_FIXER_CONNECTION_CLOSING
} TlsFixerConnectionState;

typedef struct TlsFixerConnection {
    void *sony_connection;
    int socket;
    char *hostname;
    TlsFixerConnectionState state;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config config;
    mbedtls_x509_crt_profile certificate_profile;
    SceUID mutex;
    int32_t last_tls_error;
    int32_t last_net_error;
    uint32_t last_verify_flags;
    uint32_t https_options;
    size_t pending_write_length;
    unsigned char pending_write[TLS_FIXER_MAX_IO_CHUNK];
    uint8_t mutex_initialized;
    uint8_t ssl_initialized;
    uint8_t config_initialized;
} TlsFixerConnection;

int tls_fixer_transport_global_init(void);
int tls_fixer_transport_global_destroy(void);
void tls_fixer_transport_cleanup(void *context, void *payload);

int tls_fixer_transport_create(void *request, int socket, int *handled);
int tls_fixer_transport_connect(void *request, int *handled);
int tls_fixer_transport_map_io(void *connection, int result, int *handled);
int tls_fixer_transport_read(
    void *connection,
    void *buffer,
    unsigned int length,
    int *handled);
int tls_fixer_transport_write(
    void *connection,
    const void *buffer,
    unsigned int length,
    int *handled);
int tls_fixer_transport_shutdown(void *connection, int *handled);

int tls_fixer_vita_send(void *context, const unsigned char *buffer, size_t length);
int tls_fixer_vita_recv(void *context, unsigned char *buffer, size_t length);

#endif
