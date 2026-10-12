#ifndef TLS_FIXER_X509_NAMES_H
#define TLS_FIXER_X509_NAMES_H

#include <stddef.h>

const char *tls_fixer_x509_attribute_name(const unsigned char *oid, size_t length);

#endif
