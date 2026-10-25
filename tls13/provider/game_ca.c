/* SPDX-License-Identifier: 0BSD */
#include "game_ca.h"
#include "ca_index.h"
#include "provider.h"

#include <mbedtls/platform.h>
#include <psp2/kernel/threadmgr/mutex.h>
#include <stdlib.h>
#include <string.h>

/* App-owned trust is kept separately from the indexed system bundle. The registry
 * mutex protects additions and copies, never a network operation. */
static mbedtls_x509_crt *g_game_cas;

static void free_chain(mbedtls_x509_crt *chain) {
    if (chain == NULL) return;
    mbedtls_x509_crt_free(chain);
    mbedtls_free(chain);
}

static int append_chain(mbedtls_x509_crt *chain) {
    if (sceKernelLockMutex(g_tls_fixer_http.registry_mutex, 1, NULL) < 0) return -1;
    mbedtls_x509_crt **tail = &g_game_cas;
    while (*tail != NULL) tail = &(*tail)->next;
    while (chain != NULL) {
        mbedtls_x509_crt *next = chain->next;
        int duplicate = 0;
        for (const mbedtls_x509_crt *ca = g_game_cas; ca != NULL; ca = ca->next) {
            if (ca->raw.len == chain->raw.len && memcmp(ca->raw.p, chain->raw.p, ca->raw.len) == 0) {
                duplicate = 1; break;
            }
        }
        chain->next = NULL;
        if (duplicate) free_chain(chain);
        else { *tail = chain; tail = &chain->next; }
        chain = next;
    }
    (void)sceKernelUnlockMutex(g_tls_fixer_http.registry_mutex, 1);
    return 0;
}

void tls_fixer_game_ca_free(void) {
    if (sceKernelLockMutex(g_tls_fixer_http.registry_mutex, 1, NULL) < 0) return;
    mbedtls_x509_crt *previous = g_game_cas;
    g_game_cas = NULL;
    (void)sceKernelUnlockMutex(g_tls_fixer_http.registry_mutex, 1);
    free_chain(previous);
}

static int is_pem(const unsigned char *data, size_t size) {
    static const char marker[] = "-----BEGIN CERTIFICATE-----";
    for (size_t i = 0; i + sizeof(marker) - 1 <= size; ++i)
        if (memcmp(data + i, marker, sizeof(marker) - 1) == 0) return 1;
    return 0;
}

int tls_fixer_game_ca_load(int count, const SceHttpsData **certificates) {
    /* Sony appends CA DER nodes (LibHttp +0x137d0). Empty loads do not clear
     * either the CA list or the client identity; only unload removes CAs. */
    if (count <= 0 || certificates == NULL) return 0;
    if (count > 512) return -1;
    mbedtls_x509_crt *chain = mbedtls_calloc(1, sizeof(*chain));
    if (chain == NULL) return MBEDTLS_ERR_X509_ALLOC_FAILED;
    mbedtls_x509_crt_init(chain);
    int result = 0;
    for (int i = 0; i < count; ++i) {
        const SceHttpsData *data = certificates[i];
        if (data == NULL || data->ptr == NULL || data->size == 0) {
            result = MBEDTLS_ERR_X509_BAD_INPUT_DATA;
            break;
        }
        /* Reject unrepresentable input before adding a terminator on 32-bit Vita. */
        if (data->size > 4u * 1024u * 1024u) { result = MBEDTLS_ERR_X509_BAD_INPUT_DATA; break; }
        if (is_pem((const unsigned char *)data->ptr, data->size)) {
            unsigned char *pem = malloc((size_t)data->size + 1u);
            if (pem == NULL) { result = MBEDTLS_ERR_X509_ALLOC_FAILED; break; }
            memcpy(pem, data->ptr, data->size);
            pem[data->size] = '\0';
            result = mbedtls_x509_crt_parse(chain, pem, (size_t)data->size + 1u);
            free(pem);
        } else {
            result = mbedtls_x509_crt_parse_der(chain, (const unsigned char *)data->ptr, data->size);
        }
        /* A partially parsed PEM collection cannot extend the app's trust silently. */
        if (result != 0) break;
    }
    if (result == 0) result = append_chain(chain);
    if (result != 0) free_chain(chain);
    return result;
}

int tls_fixer_game_ca_find(const mbedtls_x509_crt *child, mbedtls_x509_crt **candidates) {
    if (child == NULL || candidates == NULL) return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    if (sceKernelLockMutex(g_tls_fixer_http.registry_mutex, 1, NULL) < 0) return MBEDTLS_ERR_X509_FATAL_ERROR;
    int result = 0;
    uint32_t hash = tls_fixer_ca_name_hash(&child->issuer);
    for (const mbedtls_x509_crt *ca = g_game_cas; ca != NULL && ca->raw.p != NULL; ca = ca->next) {
        if (tls_fixer_ca_name_hash(&ca->subject) != hash) continue;
        if (*candidates == NULL) {
            *candidates = mbedtls_calloc(1, sizeof(**candidates));
            if (*candidates == NULL) { result = MBEDTLS_ERR_X509_ALLOC_FAILED; break; }
            mbedtls_x509_crt_init(*candidates);
        }
        result = mbedtls_x509_crt_parse_der(*candidates, ca->raw.p, ca->raw.len);
        if (result != 0) break;
    }
    (void)sceKernelUnlockMutex(g_tls_fixer_http.registry_mutex, 1);
    if (result != 0) { free_chain(*candidates); *candidates = NULL; }
    return result;
}
