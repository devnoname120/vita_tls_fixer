#include "../native_hello_profile.h"
#include "crypto_platform.h"
#if defined(TLS_FIXER_MBEDTLS36)
#include <mbedtls/psa_util.h>
#endif
#include <psa/crypto.h>
#include <psa/crypto_extra.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

/* Captured from our working Sony request, with only random bytes zeroed. */
static const char expected_hex[] = "16030300820100007e03030000000000000000000000000000000000000000000000000000000000000000000010003d003c0035002f000a0005000400ff0100004500000033003100002e4956303030312d4e50585330313030312d30302e617574682e6e702e61632e706c617973746174696f6e2e6e6574000d000a00080401060105010201";
typedef struct { unsigned char sent[4096], reply[54]; size_t sent_bytes, read; int respond; } Wire;
static int send_bytes(void *arg, const unsigned char *bytes, size_t size) {
    Wire *wire = arg; assert(size <= sizeof(wire->sent) - wire->sent_bytes);
    memcpy(wire->sent + wire->sent_bytes, bytes, size); wire->sent_bytes += size;
    return (int)size;
}
static int receive_bytes(void *arg, unsigned char *bytes, size_t size) {
    Wire *wire = arg;
    if (!wire->respond || wire->read == sizeof(wire->reply)) return MBEDTLS_ERR_SSL_WANT_READ;
    if (size > sizeof(wire->reply) - wire->read) size = sizeof(wire->reply) - wire->read;
    memcpy(bytes, wire->reply + wire->read, size); wire->read += size; return (int)size;
}
static int run(mbedtls_ssl_config *config, Wire *wire) {
    mbedtls_ssl_context ssl; mbedtls_ssl_init(&ssl);
    assert(mbedtls_ssl_setup(&ssl, config) == 0);
    assert(mbedtls_ssl_set_hostname(&ssl, "IV0001-NPXS01001-00.auth.np.ac.playstation.net") == 0);
    mbedtls_ssl_set_bio(&ssl, wire, send_bytes, receive_bytes, NULL);
    int result = mbedtls_ssl_handshake(&ssl); mbedtls_ssl_free(&ssl); return result;
}
int main(void) {
    assert(tls_fixer_crypto_platform_init() == 0 && psa_crypto_init() == PSA_SUCCESS);
    mbedtls_ssl_config config; mbedtls_ssl_config_init(&config);
    assert(mbedtls_ssl_config_defaults(&config, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT) == 0);
#if defined(TLS_FIXER_MBEDTLS36)
    mbedtls_ssl_conf_rng(&config, mbedtls_psa_get_random, MBEDTLS_PSA_RANDOM_STATE);
#endif
    mbedtls_ssl_conf_authmode(&config, MBEDTLS_SSL_VERIFY_OPTIONAL);
    assert(tls_fixer_native_hello_profile(&config) == 0);
    Wire wire = {0}; assert(run(&config, &wire) == MBEDTLS_ERR_SSL_WANT_READ);
    unsigned char expected[sizeof(expected_hex)/2]; size_t count = strlen(expected_hex)/2;
    for (size_t i = 0; i < count; ++i) { unsigned int value; assert(sscanf(expected_hex + 2*i, "%2x", &value) == 1); expected[i] = (unsigned char)value; }
    assert(wire.sent_bytes == count); memset(wire.sent + 11, 0, 32);
    assert(memcmp(wire.sent, expected, count) == 0);
    for (unsigned int cipher = 0; cipher < 2; ++cipher) {
        memset(&wire, 0, sizeof(wire)); wire.respond = 1;
        const unsigned char hello[54] = {22,3,3,0,49,2,0,0,45,3,3};
        memcpy(wire.reply, hello, sizeof(hello));
        wire.reply[45] = cipher ? 5 : 0x3c;
        wire.reply[48] = 5; wire.reply[49] = 0xff; wire.reply[50] = 1; wire.reply[52] = 1;
        int rc = run(&config, &wire);
        assert(rc == (cipher ? MBEDTLS_ERR_SSL_BAD_INPUT_DATA : MBEDTLS_ERR_SSL_WANT_READ));
    }
    mbedtls_ssl_config_free(&config); mbedtls_psa_crypto_free(); tls_fixer_crypto_platform_free();
    puts("Native hello: exact captured offer; supported suite accepted; unimplemented selection rejected");
    return 0;
}
