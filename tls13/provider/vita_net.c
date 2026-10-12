#include "transport.h"

#include <psp2/net/net.h>
#include <psp2common/net.h>

#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

static unsigned int net_length(size_t length) {
    if (length > UINT_MAX) {
        return UINT_MAX;
    }
    return (unsigned int)length;
}

int tls_fixer_vita_send(void *context, const unsigned char *buffer, size_t length) {
    TlsFixerConnection *connection = context;
    int result;

    if (connection == NULL || buffer == NULL) {
        return MBEDTLS_ERR_NET_INVALID_CONTEXT;
    }

    connection->last_net_error = 0;
    result = sceNetSend(connection->socket, buffer, net_length(length), 0);
    if (result > 0 || (result == 0 && length == 0)) {
        return result;
    }
    if (result == 0) {
        return MBEDTLS_ERR_NET_SEND_FAILED;
    }

    connection->last_net_error = result;
    switch ((uint32_t)result) {
        case (uint32_t)SCE_NET_ERROR_EAGAIN:
        case (uint32_t)SCE_NET_ERROR_EINTR:
            return MBEDTLS_ERR_SSL_WANT_WRITE;
        case (uint32_t)SCE_NET_ERROR_ECONNRESET:
            return MBEDTLS_ERR_NET_CONN_RESET;
        case (uint32_t)SCE_NET_ERROR_ETIMEDOUT:
            return MBEDTLS_ERR_SSL_TIMEOUT;
        default:
            return MBEDTLS_ERR_NET_SEND_FAILED;
    }
}

int tls_fixer_vita_recv(void *context, unsigned char *buffer, size_t length) {
    TlsFixerConnection *connection = context;
    int result;

    if (connection == NULL || buffer == NULL) {
        return MBEDTLS_ERR_NET_INVALID_CONTEXT;
    }

    connection->last_net_error = 0;
    result = sceNetRecv(connection->socket, buffer, net_length(length), 0);
    if (result >= 0) {
        return result;
    }

    connection->last_net_error = result;
    switch ((uint32_t)result) {
        case (uint32_t)SCE_NET_ERROR_EAGAIN:
        case (uint32_t)SCE_NET_ERROR_EINTR:
            return MBEDTLS_ERR_SSL_WANT_READ;
        case (uint32_t)SCE_NET_ERROR_ECONNRESET:
            return MBEDTLS_ERR_NET_CONN_RESET;
        case (uint32_t)SCE_NET_ERROR_ETIMEDOUT:
            return MBEDTLS_ERR_SSL_TIMEOUT;
        default:
            return MBEDTLS_ERR_NET_RECV_FAILED;
    }
}
