#ifndef TLS_FIXER_FIRMWARE_PROFILES_H
#define TLS_FIXER_FIRMWARE_PROFILES_H

#include <stddef.h>
#include <stdint.h>

typedef struct TlsFixerKernelProfile {
    uint32_t module_nid;
    size_t text_size, metadata_offset;
    unsigned int family;
} TlsFixerKernelProfile;

typedef struct TlsFixerWebKitProfile {
    uint32_t module_nid;
    size_t text_size, data_filesz, data_memsz, metadata_offset;
    size_t callback_offset, vtable_offset;
    const unsigned char *callback_signature;
} TlsFixerWebKitProfile;

/* External firmware identities, independently checked on every available kit image. */
static const TlsFixerKernelProfile tls_fixer_kernel_profiles[] = {
    {0x726c6635, 0xef84, 0xb9d0, 0}, /* 3.60 */
    {0xa5a80af8, 0xef84, 0xb9d0, 0}, /* 3.61 */
    {0xb87084f7, 0xf034, 0xba80, 1}, /* 3.63 */
    {0x781c6f50, 0xf034, 0xba80, 1}, /* 3.65 */
    {0x352000c9, 0xf034, 0xba80, 1}, /* 3.67 */
    {0xd9c169a6, 0xf034, 0xba80, 1}, /* 3.68 */
    {0x626a6c37, 0xf034, 0xba80, 1}, /* 3.69 */
    {0x7d7448ce, 0xf034, 0xba80, 1}, /* 3.70 */
    {0x5e2d8132, 0xf034, 0xba80, 1}, /* 3.71 */
    {0xce41f3d9, 0xf034, 0xba80, 1}, /* 3.72 */
    {0xf280f289, 0xf034, 0xba80, 1}, /* 3.73 */
    {0x8f483354, 0xf034, 0xba80, 1}  /* 3.74 */
};

static const unsigned char tls_fixer_webkit_callback_360[] = {
    0x10,0xb5,0x08,0x1c,0x11,0x1c,0xf1,0xf2,0xba,0xe5,0x00,0x20,0x10,0xbd
};
static const unsigned char tls_fixer_webkit_callback_361[] = {
    0x10,0xb5,0x08,0x1c,0x11,0x1c,0xf1,0xf2,0xa8,0xe5,0x00,0x20,0x10,0xbd
};
static const unsigned char tls_fixer_webkit_callback_367[] = {
    0x10,0xb5,0x08,0x1c,0x11,0x1c,0xf1,0xf2,0xa6,0xe5,0x00,0x20,0x10,0xbd
};
static const unsigned char tls_fixer_webkit_callback_368[] = {
    0x10,0xb5,0x08,0x1c,0x11,0x1c,0xf8,0xf2,0x60,0xe7,0x00,0x20,0x10,0xbd
};

static const TlsFixerWebKitProfile tls_fixer_webkit_profiles[] = {
    {0x20163df2,0xaf2ebc,0xce34,0x115c0,0x85fb04,0x16c7b6,0xa98084,tls_fixer_webkit_callback_360},
    {0x95a02949,0xaf2e9c,0xce34,0x115c0,0x85fae4,0x16c7ba,0xa98064,tls_fixer_webkit_callback_361},
    {0xb1fe1b01,0xaf2e9c,0xce34,0x115c0,0x85fae4,0x16c7ba,0xa98064,tls_fixer_webkit_callback_361},
    {0xa33a93f7,0xaf2e9c,0xce34,0x115c0,0x85fae4,0x16c7ba,0xa98064,tls_fixer_webkit_callback_361},
    {0xe87b919e,0xaf2eb4,0xce34,0x115c0,0x85fafc,0x16c7d6,0xa9807c,tls_fixer_webkit_callback_367},
    {0x0c92976b,0xafada4,0xdb54,0x122e8,0x8671a8,0x16cb0e,0xa9ff6c,tls_fixer_webkit_callback_368},
    {0x829a7082,0xafada4,0xdb54,0x122e8,0x8671a8,0x16cb0e,0xa9ff6c,tls_fixer_webkit_callback_368},
    {0x4492e657,0xafada4,0xdb54,0x122e8,0x8671a8,0x16cb0e,0xa9ff6c,tls_fixer_webkit_callback_368},
    {0xc417b585,0xafada4,0xdb54,0x122e8,0x8671a8,0x16cb0e,0xa9ff6c,tls_fixer_webkit_callback_368},
    {0x5143d9cf,0xafada4,0xdb54,0x122e8,0x8671a8,0x16cb0e,0xa9ff6c,tls_fixer_webkit_callback_368},
    {0xf82ddf69,0xafada4,0xdb54,0x122e8,0x8671a8,0x16cb0e,0xa9ff6c,tls_fixer_webkit_callback_368},
    {0x52fe25c9,0xafada4,0xdb54,0x122e8,0x8671a8,0x16cb0e,0xa9ff6c,tls_fixer_webkit_callback_368},
    {0x87f5a440,0xaf2ebc,0xce34,0x115c0,0x85fb04,0x16c7b6,0xa98084,tls_fixer_webkit_callback_360}, /* testkit 3.60 */
    {0x250680e1,0xaf2e9c,0xce34,0x115c0,0x85fae4,0x16c7ba,0xa98064,tls_fixer_webkit_callback_361}, /* testkit 3.61 */
    {0x334fdbac,0xaf2e9c,0xce34,0x115c0,0x85fae4,0x16c7ba,0xa98064,tls_fixer_webkit_callback_361}, /* testkit 3.63 */
    {0xe32c493d,0xaf2e9c,0xce34,0x115c0,0x85fae4,0x16c7ba,0xa98064,tls_fixer_webkit_callback_361}, /* testkit 3.65 */
    {0xa82568bf,0xaf2eb4,0xce34,0x115c0,0x85fafc,0x16c7d6,0xa9807c,tls_fixer_webkit_callback_367}, /* testkit 3.67 */
    {0xcad8ce30,0xafada4,0xdb54,0x122e8,0x8671a8,0x16cb0e,0xa9ff6c,tls_fixer_webkit_callback_368}, /* testkit 3.68 */
    {0x145c1700,0xafada4,0xdb54,0x122e8,0x8671a8,0x16cb0e,0xa9ff6c,tls_fixer_webkit_callback_368}, /* testkit 3.70 */
    {0x536b8987,0xafada4,0xdb54,0x122e8,0x8671a8,0x16cb0e,0xa9ff6c,tls_fixer_webkit_callback_368}, /* testkit 3.72 */
    {0x81ca3d03,0xafada4,0xdb54,0x122e8,0x8671a8,0x16cb0e,0xa9ff6c,tls_fixer_webkit_callback_368}, /* testkit 3.73 */
    {0x1a29ef0d,0xaf2ebc,0xce34,0x115c0,0x85fb04,0x16c7b6,0xa98084,tls_fixer_webkit_callback_360}, /* devkit 3.60 */
    {0x9c6be71b,0xaf2e9c,0xce34,0x115c0,0x85fae4,0x16c7ba,0xa98064,tls_fixer_webkit_callback_361}, /* devkit 3.61 */
    {0xd2747a81,0xaf2e9c,0xce34,0x115c0,0x85fae4,0x16c7ba,0xa98064,tls_fixer_webkit_callback_361}, /* devkit 3.63 */
    {0x8deccd66,0xaf2e9c,0xce34,0x115c0,0x85fae4,0x16c7ba,0xa98064,tls_fixer_webkit_callback_361}, /* devkit 3.65 */
    {0xa7754683,0xaf2eb4,0xce34,0x115c0,0x85fafc,0x16c7d6,0xa9807c,tls_fixer_webkit_callback_367}, /* devkit 3.67 */
    {0x029b02d6,0xafada4,0xdb54,0x122e8,0x8671a8,0x16cb0e,0xa9ff6c,tls_fixer_webkit_callback_368}, /* devkit 3.68 */
    {0xde76dce7,0xafada4,0xdb54,0x122e8,0x8671a8,0x16cb0e,0xa9ff6c,tls_fixer_webkit_callback_368}, /* devkit 3.69 */
    {0x1953403e,0xafada4,0xdb54,0x122e8,0x8671a8,0x16cb0e,0xa9ff6c,tls_fixer_webkit_callback_368}, /* devkit 3.70 */
    {0xd9e17ef3,0xafada4,0xdb54,0x122e8,0x8671a8,0x16cb0e,0xa9ff6c,tls_fixer_webkit_callback_368}, /* devkit 3.71 */
    {0x8b26b9a7,0xafada4,0xdb54,0x122e8,0x8671a8,0x16cb0e,0xa9ff6c,tls_fixer_webkit_callback_368}, /* devkit 3.73 */
};

static inline uint32_t tls_fixer_profile_u32(const unsigned char *bytes) {
    return (uint32_t)bytes[0] | (uint32_t)bytes[1] << 8 |
        (uint32_t)bytes[2] << 16 | (uint32_t)bytes[3] << 24;
}

/* The mapped module-info record remains in RX on the saved 3.60 hardware capture.
 * Read only inside the native-reported segment; do not add startup module queries. */
static inline int tls_fixer_profile_metadata_matches(const unsigned char *text,
    size_t size, size_t offset, const char *name, uint32_t nid) {
    if (text == NULL || offset > size || 0x38u > size - offset) return 0;
    const unsigned char *info = text + offset;
    if (info[31] != 6 || tls_fixer_profile_u32(info + 0x34) != nid) return 0;
    for (size_t i = 0; i < 27; ++i) {
        if (info[4 + i] != (unsigned char)name[i]) return 0;
        if (name[i] == '\0') return 1;
    }
    return 0;
}

static inline const TlsFixerKernelProfile *tls_fixer_select_kernel_profile(
    const unsigned char *text, size_t size) {
    for (size_t i = 0; i < sizeof(tls_fixer_kernel_profiles) / sizeof(tls_fixer_kernel_profiles[0]); ++i) {
        const TlsFixerKernelProfile *profile = &tls_fixer_kernel_profiles[i];
        if (size == profile->text_size && tls_fixer_profile_metadata_matches(text, size,
                profile->metadata_offset, "SceKernelModulemgr", profile->module_nid)) return profile;
    }
    return NULL;
}

static inline const TlsFixerWebKitProfile *tls_fixer_select_webkit_profile(
    const unsigned char *text, size_t filesz, size_t memsz, size_t data_filesz, size_t data_memsz) {
    for (size_t i = 0; i < sizeof(tls_fixer_webkit_profiles) / sizeof(tls_fixer_webkit_profiles[0]); ++i) {
        const TlsFixerWebKitProfile *profile = &tls_fixer_webkit_profiles[i];
        if (filesz == profile->text_size && memsz == filesz && data_filesz == profile->data_filesz &&
            data_memsz == profile->data_memsz && tls_fixer_profile_metadata_matches(text, filesz,
                profile->metadata_offset, "SceWebKit", profile->module_nid)) return profile;
    }
    return NULL;
}

#endif
