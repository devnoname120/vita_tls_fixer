/* SPDX-License-Identifier: 0BSD */
#ifndef TLS_FIXER_STORE_COVER_FIRMWARE_H
#define TLS_FIXER_STORE_COVER_FIRMWARE_H
#include <stdint.h>
/* Product ABI verified against retail/testkit/devkit 3.60-3.74 images.
 * Unknown modules retain Sony's original artwork behavior. */
static inline int store_cover_commerce_supported(uint32_t nid) {
    switch (nid) {
    case UINT32_C(0x969bda0):
    case UINT32_C(0x10fe2f0b):
    case UINT32_C(0x16634eb5):
    case UINT32_C(0x1bd65714):
    case UINT32_C(0x2217e9c4):
    case UINT32_C(0x27e01f74):
    case UINT32_C(0x36ed4666):
    case UINT32_C(0x4c96e117):
    case UINT32_C(0x4fa885b0):
    case UINT32_C(0x52126dd9):
    case UINT32_C(0x5b549723):
    case UINT32_C(0x5fd74ec9):
    case UINT32_C(0x64d2b38c):
    case UINT32_C(0x66e4d5b5):
    case UINT32_C(0x6aa42925):
    case UINT32_C(0x6e2088c4):
    case UINT32_C(0x7b6f9382):
    case UINT32_C(0x7dfc1a3c):
    case UINT32_C(0x97d3551e):
    case UINT32_C(0x9857a781):
    case UINT32_C(0xa5550b0e):
    case UINT32_C(0xab7fe511):
    case UINT32_C(0xacbde3ef):
    case UINT32_C(0xbd77bc74):
    case UINT32_C(0xc1d84f9f):
    case UINT32_C(0xc69f5c42):
    case UINT32_C(0xcf82287c):
    case UINT32_C(0xd7fc3b77):
    case UINT32_C(0xe2becb59):
    case UINT32_C(0xe3aa1877):
    case UINT32_C(0xed4a51b4):
        return 1;
    default: return 0;
    }
}
#endif
