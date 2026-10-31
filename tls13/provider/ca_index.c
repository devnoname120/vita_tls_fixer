/* SPDX-License-Identifier: 0BSD */
#include "ca_index.h"
#include "diagnostics.h"

#include <mbedtls/platform.h>
#include <psa/crypto.h>
#include <psp2/io/fcntl.h>
#include <stdlib.h>
#include <string.h>
#include "sony_dnas_roots.h"

#define MAX_FILE_SIZE (4 * 1024 * 1024)
#define LINE_CAPACITY 160u
#define CHUNK_SIZE 512u

static const char k_begin[] = "-----BEGIN CERTIFICATE-----";
static const char k_end[] = "-----END CERTIFICATE-----";

/* Hash of a distinguished name that agrees for names Mbed TLS considers equal (string values
 * compare case-insensitively)
 * Used only to pre-select candidates; Mbed TLS still performs the real name comparison */
uint32_t tls_fixer_ca_name_hash(const mbedtls_x509_name *name) {
    uint32_t hash = 2166136261u;
    for (; name != NULL; name = name->next) {
        for (size_t i = 0; i < name->oid.len; ++i) hash = (hash ^ name->oid.p[i]) * 16777619u;
        hash = (hash ^ 0xFFu) * 16777619u;
        for (size_t i = 0; i < name->val.len; ++i) {
            unsigned char c = name->val.p[i];
            if (c >= 'A' && c <= 'Z') c = (unsigned char)(c + ('a' - 'A'));
            hash = (hash ^ c) * 16777619u;
        }
        hash = (hash ^ 0xFEu) * 16777619u;
    }
    return hash;
}

typedef struct Reader {
    SceUID fd;
    unsigned char buffer[CHUNK_SIZE];
    size_t position;
    size_t length;
    uint32_t base;
    /* Parsing one root needs a sizeable descriptor. Keep it with the existing
     * heap-backed reader: inlining it into the index loop exhausted small
     * system-app stacks when HTTP initialization gained diagnostic frames. */
    mbedtls_x509_crt certificate;
} Reader;

/* 1 = byte read, 0 = end of file, -1 = I/O error */
static int reader_next(Reader *reader, unsigned char *out) {
    if (reader->position == reader->length) {
        int count = sceIoRead(reader->fd, reader->buffer, sizeof(reader->buffer));
        if (count < 0) return -1;
        if (count == 0) return 0;
        reader->base += (uint32_t)reader->length;
        if (reader->base + (uint32_t)count > MAX_FILE_SIZE) return -1;
        reader->length = (size_t)count;
        reader->position = 0;
    }
    *out = reader->buffer[reader->position++];
    return 1;
}

static uint32_t reader_offset(const Reader *reader) {
    return reader->base + (uint32_t)reader->position;
}

static int starts_with(const unsigned char *line, size_t length, const char *prefix, size_t prefix_length) {
    return length >= prefix_length && memcmp(line, prefix, prefix_length) == 0;
}

static int add_entry(TlsFixerCaIndex *index, mbedtls_x509_crt *crt, unsigned char *block, size_t block_length,
    uint32_t start, uint32_t end) {
    if (index->count >= TLS_FIXER_CA_INDEX_MAX_ENTRIES) return MBEDTLS_ERR_X509_ALLOC_FAILED;
    block[block_length] = '\0';
    mbedtls_x509_crt_init(crt);
    int result = mbedtls_x509_crt_parse(crt, block, block_length + 1);
    if (result == 0 && crt->raw.p != NULL) {
        TlsFixerCaEntry *entry = &index->entries[index->count++];
        entry->name_hash = tls_fixer_ca_name_hash(&crt->subject);
        entry->offset = start;
        entry->length = end - start;
    }
    mbedtls_x509_crt_free(crt);
    return result == 0 ? 0 : MBEDTLS_ERR_X509_INVALID_FORMAT;
}

int tls_fixer_ca_index_build(TlsFixerCaIndex *index, const char *path) {
    Reader *reader = NULL;
    unsigned char *block = NULL;
    unsigned char line[LINE_CAPACITY];
    size_t block_length = 0;
    uint32_t block_start = 0;
    int in_block = 0;
    int64_t file_size;
    int result = MBEDTLS_ERR_X509_FILE_IO_ERROR;

    if (index == NULL || path == NULL || *path == '\0' ||
        strlen(path) >= sizeof(index->path)) return result;
    memset(index, 0, sizeof(*index));

    reader = calloc(1, sizeof(*reader));
    if (reader != NULL) reader->fd = -1;
    block = malloc(TLS_FIXER_CA_INDEX_MAX_BLOCK + 2u);
    index->entries = calloc(TLS_FIXER_CA_INDEX_MAX_ENTRIES, sizeof(*index->entries));
    if (reader == NULL || block == NULL || index->entries == NULL) {
        result = MBEDTLS_ERR_X509_ALLOC_FAILED;
        goto cleanup;
    }
    reader->fd = sceIoOpen(path, SCE_O_RDONLY, 0);
    TLS_FIXER_LOG("event=ca.open path=%s fd=%08X", path, reader->fd);
    if (reader->fd < 0) goto cleanup;
    file_size = sceIoLseek(reader->fd, 0, SCE_SEEK_END);
    TLS_FIXER_LOG("event=ca.size bytes=%lld", (long long)file_size);
    if (file_size <= 0 || file_size > MAX_FILE_SIZE ||
        sceIoLseek(reader->fd, 0, SCE_SEEK_SET) < 0) goto cleanup;

    for (;;) {
        size_t line_length = 0;
        int overflow = 0;
        int status = 1;
        uint32_t line_start = reader_offset(reader);
        unsigned char c;

        while ((status = reader_next(reader, &c)) == 1) {
            if (c == '\0') { result = MBEDTLS_ERR_X509_INVALID_FORMAT; goto cleanup; }
            if (c == '\n') break;
            if (line_length < sizeof(line)) line[line_length++] = c;
            else overflow = 1;
        }
        if (status < 0) goto cleanup;
        if (status == 0 && line_length == 0 && !overflow) break;

        if (!in_block && !overflow &&
            starts_with(line, line_length, k_begin, sizeof(k_begin) - 1u)) {
            in_block = 1;
            block_start = line_start;
            block_length = 0;
        }
        if (in_block) {
            if (overflow || block_length + line_length + 1u > TLS_FIXER_CA_INDEX_MAX_BLOCK) {
                result = MBEDTLS_ERR_X509_INVALID_FORMAT;
                goto cleanup;
            } else {
                memcpy(block + block_length, line, line_length);
                block_length += line_length;
                block[block_length++] = '\n';
                if (starts_with(line, line_length, k_end, sizeof(k_end) - 1u)) {
                    int added = add_entry(index, &reader->certificate, block, block_length, block_start, reader_offset(reader));
                    if (added != 0) { result = added; goto cleanup; }
                    in_block = 0;
                }
            }
        }
        if (status == 0) break;
    }

    TLS_FIXER_LOG("event=ca.index entries=%u", (unsigned int)index->count);
    if (index->count == 0 || in_block) {
        result = MBEDTLS_ERR_X509_INVALID_FORMAT;
        goto cleanup;
    }
    TlsFixerCaEntry *compact = realloc(index->entries, index->count * sizeof(*index->entries));
    if (compact != NULL) index->entries = compact;
    memcpy(index->path, path, strlen(path) + 1u);
    result = 0;

cleanup:
    if (reader != NULL && reader->fd >= 0 && sceIoClose(reader->fd) < 0 && result == 0) {
        result = MBEDTLS_ERR_X509_FILE_IO_ERROR;
    }
    free(reader);
    free(block);
    if (result != 0) tls_fixer_ca_index_free(index);
    return result;
}

void tls_fixer_ca_index_free(TlsFixerCaIndex *index) {
    if (index == NULL) return;
    free(index->entries);
    memset(index, 0, sizeof(*index));
}

int tls_fixer_ca_index_find(void *context, const mbedtls_x509_crt *child,
    mbedtls_x509_crt **candidates) {
    const TlsFixerCaIndex *index = context;
    mbedtls_x509_crt *head = NULL;
    unsigned char *block = NULL;
    SceUID fd = -1;
    uint32_t hash;
    int result = 0;

    if (candidates == NULL) return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    *candidates = NULL;
    if (index == NULL || index->entries == NULL || child == NULL) return 0;

    hash = tls_fixer_ca_name_hash(&child->issuer);
    for (size_t i = 0; i < index->count; ++i) {
        const TlsFixerCaEntry *entry = &index->entries[i];
        size_t consumed = 0;
        if (entry->name_hash != hash || entry->length > TLS_FIXER_CA_INDEX_MAX_BLOCK) continue;
        if (head == NULL) {
            head = mbedtls_calloc(1, sizeof(*head));
            block = malloc(TLS_FIXER_CA_INDEX_MAX_BLOCK + 2u);
            if (head == NULL || block == NULL) {
                result = MBEDTLS_ERR_X509_ALLOC_FAILED;
                goto cleanup;
            }
            mbedtls_x509_crt_init(head);
            fd = sceIoOpen(index->path, SCE_O_RDONLY, 0);
            if (fd < 0) { result = MBEDTLS_ERR_X509_FILE_IO_ERROR; goto cleanup; }
        }
        if (sceIoLseek(fd, entry->offset, SCE_SEEK_SET) != entry->offset) {
            result = MBEDTLS_ERR_X509_FILE_IO_ERROR; goto cleanup;
        }
        while (consumed < entry->length) {
            int count = sceIoRead(fd, block + consumed, (SceSize)(entry->length - consumed));
            if (count <= 0) break;
            consumed += (size_t)count;
        }
        if (consumed != entry->length) { result = MBEDTLS_ERR_X509_FILE_IO_ERROR; goto cleanup; }
        block[consumed++] = '\n';
        block[consumed++] = '\0';
        result = mbedtls_x509_crt_parse(head, block, consumed);
        if (result != 0) {
            if (result > 0) result = MBEDTLS_ERR_X509_INVALID_FORMAT;
            goto cleanup;
        }
    }

cleanup:
    if (fd >= 0 && sceIoClose(fd) < 0 && result == 0) result = MBEDTLS_ERR_X509_FILE_IO_ERROR;
    free(block);
    if (result != 0 || head == NULL || head->raw.p == NULL) {
        if (head != NULL) {
            mbedtls_x509_crt_free(head);
            mbedtls_free(head);
        }
        return result;
    }
    *candidates = head;
    return 0;
}

int tls_fixer_ca_index_find_sony(void *context, const mbedtls_x509_crt *child,
    mbedtls_x509_crt **candidates) {
    int result = tls_fixer_ca_index_find(context, child, candidates);
    if (result != 0) return result;
    mbedtls_x509_crt **cursor = candidates;
    while (*cursor != NULL) {
        mbedtls_x509_crt *candidate = *cursor;
        unsigned char digest[32];
        size_t length = 0;
        if (psa_hash_compute(PSA_ALG_SHA_256, candidate->raw.p, candidate->raw.len,
                            digest, sizeof(digest), &length) != PSA_SUCCESS || length != sizeof(digest)) {
            mbedtls_x509_crt_free(*candidates);
            mbedtls_free(*candidates);
            *candidates = NULL;
            return MBEDTLS_ERR_X509_FATAL_ERROR;
        }
        int keep = 0;
        for (size_t i = 0; i < sizeof(k_sony_dnas_sha256) / sizeof(k_sony_dnas_sha256[0]); ++i)
            if (memcmp(digest, k_sony_dnas_sha256[i], sizeof(digest)) == 0) keep = 1;
        if (keep) {
            cursor = &candidate->next;
        } else {
            *cursor = candidate->next;
            candidate->next = NULL;
            mbedtls_x509_crt_free(candidate);
            mbedtls_free(candidate);
        }
    }
    return 0;
}

int tls_fixer_ca_trusts_exact(mbedtls_x509_crt_ca_cb_t find, void *context,
    const mbedtls_x509_crt *certificate) {
    mbedtls_x509_crt *candidates = NULL;
    int trusted = 0;

    if (find == NULL || certificate == NULL || certificate->raw.p == NULL ||
        certificate->issuer_raw.len != certificate->subject_raw.len ||
        memcmp(certificate->issuer_raw.p, certificate->subject_raw.p, certificate->subject_raw.len) != 0)
        return 0;
    /* Its issuer is itself, so the trusted certificates with its subject include any copy of it */
    if (find(context, certificate, &candidates) == 0) {
        for (const mbedtls_x509_crt *candidate = candidates; candidate != NULL; candidate = candidate->next) {
            if (candidate->raw.len == certificate->raw.len &&
                memcmp(candidate->raw.p, certificate->raw.p, certificate->raw.len) == 0) {
                trusted = 1;
                break;
            }
        }
    }
    if (candidates != NULL) {
        mbedtls_x509_crt_free(candidates);
        mbedtls_free(candidates);
    }
    return trusted;
}
