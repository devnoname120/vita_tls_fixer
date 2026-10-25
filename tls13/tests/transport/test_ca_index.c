#define _POSIX_C_SOURCE 200809L
#include "ca_index.h"
#include "ca_file.h"
#include "crypto_platform.h"
#include <vita_mock.h>
#include <mbedtls/platform.h>
#include <psa/crypto.h>
#include <psa/crypto_extra.h>
#include <psp2/io/fcntl.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int fail_open, fail_read, fail_seek, fail_close, open_count;
static int allocation_number = -1;
static unsigned read_chunk;
void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
static int allocation_fails(void) { return allocation_number >= 0 && allocation_number-- == 0; }
void *__wrap_malloc(size_t size) { return allocation_fails() ? NULL : __real_malloc(size); }
void *__wrap_calloc(size_t count, size_t size) { return allocation_fails() ? NULL : __real_calloc(count, size); }
int __real_sceIoOpen(const char *, int, int);
int __real_sceIoRead(int, void *, unsigned);
int __real_sceIoClose(int);
int64_t __real_sceIoLseek(int, int64_t, int);
int __wrap_sceIoOpen(const char *path, int flags, int mode) {
    if (fail_open) return -1;
    int fd = __real_sceIoOpen(path, flags, mode);
    if (fd >= 0) ++open_count;
    return fd;
}
int __wrap_sceIoRead(int fd, void *buffer, unsigned size) {
    if (fail_read) return -1;
    if (read_chunk != 0 && size > read_chunk) size = read_chunk;
    return __real_sceIoRead(fd, buffer, size);
}
int64_t __wrap_sceIoLseek(int fd, int64_t offset, int whence) {
    return fail_seek ? -1 : __real_sceIoLseek(fd, offset, whence);
}
int __wrap_sceIoClose(int fd) {
    assert(open_count > 0); --open_count;
    int result = __real_sceIoClose(fd);
    return fail_close ? -1 : result;
}
static void free_chain(mbedtls_x509_crt *chain) {
    if (chain != NULL) { mbedtls_x509_crt_free(chain); mbedtls_free(chain); }
}
static void bad_bundle(const char *path, const char *begin, size_t length, const char *suffix) {
    FILE *file = fopen(path, "wb"); assert(file != NULL);
    assert(fwrite(begin, 1, length, file) == length);
    assert(fwrite(suffix, 1, strlen(suffix), file) == strlen(suffix));
    assert(fclose(file) == 0);
    TlsFixerCaIndex index = {0};
    assert(tls_fixer_ca_index_build(&index, path) != 0);
    assert(index.entries == NULL && index.count == 0 && open_count == 0);
}
int main(int argc, char **argv) {
    assert(argc == 2);
    assert(tls_fixer_crypto_platform_init() == 0 && psa_crypto_init() == PSA_SUCCESS);
    mbedtls_x509_crt roots;
    mbedtls_x509_crt_init(&roots);
    assert(tls_fixer_load_ca_file(&roots, argv[1]) == 0);
    TlsFixerCaIndex index = {0};
    read_chunk = 7;
    assert(tls_fixer_ca_index_build(&index, argv[1]) == 0);
    size_t count = 0;
    for (mbedtls_x509_crt *root = &roots; root != NULL; root = root->next) {
        mbedtls_x509_crt *candidates = NULL;
        assert(tls_fixer_ca_index_find(&index, root, &candidates) == 0);
        /* These bundled certificates are self-issued: the exact DER must be found. */
        int found = 0;
        for (mbedtls_x509_crt *c = candidates; c != NULL; c = c->next)
            if (c->raw.len == root->raw.len && memcmp(c->raw.p, root->raw.p, c->raw.len) == 0) found = 1;
        assert(found); ++count; free_chain(candidates);
    }
    assert(count == index.count && open_count == 0);
    read_chunk = 0;
    for (int fault = 0; fault < 4; ++fault) {
        int *flag = (int *[]){&fail_open, &fail_read, &fail_seek, &fail_close}[fault];
        *flag = 1;
        mbedtls_x509_crt *candidates = NULL;
        assert(tls_fixer_ca_index_find(&index, &roots, &candidates) < 0 && candidates == NULL);
        assert(open_count == 0);
        TlsFixerCaIndex failed = {0};
        assert(tls_fixer_ca_index_build(&failed, argv[1]) < 0 && failed.entries == NULL);
        assert(open_count == 0); *flag = 0;
    }
    tls_fixer_ca_index_free(&index);
    for (int i = 0; i < 10; ++i) {
        allocation_number = i;
        assert(tls_fixer_ca_index_build(&index, argv[1]) != 0 && index.entries == NULL);
        assert(open_count == 0);
        allocation_number = -1;
    }
    char temporary[] = "/tmp/tls_fixer-index-XXXXXX";
    int fd = mkstemp(temporary); assert(fd >= 0); close(fd);
    FILE *bundle = fopen(argv[1], "rb"); assert(bundle != NULL);
    char block[8192] = {0}; size_t length = fread(block, 1, sizeof(block)-1, bundle); fclose(bundle);
    assert(length > 0);
    char *begin = strstr(block, "-----BEGIN CERTIFICATE-----");
    char *end = strstr(begin, "-----END CERTIFICATE-----"); assert(end != NULL);
    length = (size_t)(end - begin) + strlen("-----END CERTIFICATE-----");
    bad_bundle(temporary, begin, length, "\n-----BEGIN CERTIFICATE-----\ntruncated\n");
    bad_bundle(temporary, begin, length, "\n-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n");
    /* A final PEM delimiter without newline is still a complete certificate. */
    FILE *one = fopen(temporary, "wb"); assert(one != NULL);
    assert(fwrite(begin, 1, length, one) == length && fclose(one) == 0);
    assert(tls_fixer_ca_index_build(&index, temporary) == 0 && index.count == 1);
    mbedtls_x509_crt *candidate = NULL;
    assert(tls_fixer_ca_index_find(&index, &roots, &candidate) == 0 && candidate != NULL);
    free_chain(candidate);
    /* Truncation after indexing is an I/O error, never an empty successful lookup. */
    assert(truncate(temporary, 0) == 0);
    candidate = NULL;
    assert(tls_fixer_ca_index_find(&index, &roots, &candidate) < 0 && candidate == NULL);
    tls_fixer_ca_index_free(&index);
    unlink(temporary);
    mbedtls_x509_crt_free(&roots);
    mbedtls_psa_crypto_free(); tls_fixer_crypto_platform_free();
    printf("CA index: %zu exact roots, short reads, I/O/allocation faults, malformed tails, truncation PASS\n", count);
    return 0;
}
