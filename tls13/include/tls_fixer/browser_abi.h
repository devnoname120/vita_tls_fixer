#ifndef TLS_FIXER_BROWSER_ABI_H
#define TLS_FIXER_BROWSER_ABI_H

#include <stddef.h>
#include <stdint.h>

#define TLS_FIXER_BROWSER_START_MAGIC UINT32_C(0x42544c53)
#define TLS_FIXER_BROWSER_START_VERSION UINT32_C(1)
#define TLS_FIXER_BROWSER_CONNECT_OFFSET ((size_t)0xa5ece)
#define TLS_FIXER_BROWSER_CLOSE_OFFSET ((size_t)0xa36ba)
#define TLS_FIXER_BROWSER_PENDING_OFFSET ((size_t)0xa6240)
#define TLS_FIXER_BROWSER_CHECK_OFFSET ((size_t)0xa354c)
#define TLS_FIXER_BROWSER_TIMELEFT_OFFSET ((size_t)0x93f18)
#define TLS_FIXER_BROWSER_WAIT_OFFSET ((size_t)0x97e82)

#define TLS_FIXER_CURL_EASY_OFFSET ((size_t)0)
#define TLS_FIXER_CURL_HOST_OFFSET ((size_t)136)
#define TLS_FIXER_CURL_SOCKET_OFFSET ((size_t)320)
#define TLS_FIXER_CURL_RECV_OFFSET ((size_t)340)
#define TLS_FIXER_CURL_SEND_OFFSET ((size_t)348)
#define TLS_FIXER_CURL_SSL_OFFSET ((size_t)356)
#define TLS_FIXER_CURL_SSL_STRIDE ((size_t)24)
#define TLS_FIXER_CURL_SSL_STATE_OFFSET ((size_t)4)
#define TLS_FIXER_CURL_SSL_CONTEXT_OFFSET ((size_t)8)
#define TLS_FIXER_CURL_SSL_HANDLE_OFFSET ((size_t)12)
#define TLS_FIXER_CURL_SSL_CONNECTING_OFFSET ((size_t)20)

#define TLS_FIXER_CURL_VERSION_OFFSET ((size_t)636)
#define TLS_FIXER_CURL_VERIFY_RESULT_OFFSET ((size_t)640)
#define TLS_FIXER_CURL_VERIFY_PEER_OFFSET ((size_t)644)
#define TLS_FIXER_CURL_VERIFY_HOST_OFFSET ((size_t)645)
#define TLS_FIXER_CURL_CTX_CALLBACK_OFFSET ((size_t)680)
#define TLS_FIXER_CURL_CTX_CALLBACK_DATA_OFFSET ((size_t)684)
#define TLS_FIXER_CURL_CERTINFO_OFFSET ((size_t)689)
#define TLS_FIXER_CURL_CAPATH_OFFSET ((size_t)896)
#define TLS_FIXER_CURL_CAFILE_OFFSET ((size_t)900)
#define TLS_FIXER_CURL_CIPHERS_OFFSET ((size_t)904)
#define TLS_FIXER_CURL_CRL_OFFSET ((size_t)920)
#define TLS_FIXER_CURL_ISSUER_OFFSET ((size_t)924)

#define TLS_FIXER_CURLE_OK 0
#define TLS_FIXER_CURLE_NOT_BUILT_IN 4
#define TLS_FIXER_CURLE_OUT_OF_MEMORY 27
#define TLS_FIXER_CURLE_OPERATION_TIMEDOUT 28
#define TLS_FIXER_CURLE_SSL_CONNECT_ERROR 35
#define TLS_FIXER_CURLE_ABORTED_BY_CALLBACK 42
#define TLS_FIXER_CURLE_BAD_FUNCTION_ARGUMENT 43
#define TLS_FIXER_CURLE_PEER_FAILED_VERIFICATION 51
#define TLS_FIXER_CURLE_SEND_ERROR 55
#define TLS_FIXER_CURLE_RECV_ERROR 56
#define TLS_FIXER_CURLE_SSL_CACERT 60
#define TLS_FIXER_CURLE_SSL_CACERT_BADFILE 77
#define TLS_FIXER_CURLE_AGAIN 81

typedef struct TlsFixerBrowserStartArgs {
    uint32_t magic;
    uint32_t version;
    int32_t compat_modid;
    uint32_t reserved;
} TlsFixerBrowserStartArgs;

typedef struct TlsFixerBrowserOptions {
    void *easy;
    int socket;
    const char *hostname;
    const char *ca_file;
    uint32_t tls12_suites;
    uint8_t verify_peer;
    uint8_t verify_host;
} TlsFixerBrowserOptions;

typedef int (*TlsFixerBrowserContextCallbackValidator)(const void *callback,
    const void *userdata);

enum {
    TLS_FIXER_BROWSER_CONFIG_OK = 0,
    TLS_FIXER_BROWSER_CONFIG_LEGACY = 1,
    TLS_FIXER_BROWSER_CONFIG_INVALID = -1,
    TLS_FIXER_BROWSER_RSA_GCM128 = 1,
    TLS_FIXER_BROWSER_RSA_GCM256 = 2,
    TLS_FIXER_BROWSER_ECDSA_GCM128 = 4,
    TLS_FIXER_BROWSER_ECDSA_GCM256 = 8
};

int tls_fixer_browser_read_options(const void *connection, unsigned int socket_index,
    const char *browser_default_ciphers,
    TlsFixerBrowserContextCallbackValidator callback_validator,
    TlsFixerBrowserOptions *options);

#endif
