#ifndef TLS_FIXER_CA_FILE_H
#define TLS_FIXER_CA_FILE_H

#include <mbedtls/x509_crt.h>

#define TLS_FIXER_DEFAULT_CA_PATH "vs0:/data/external/cert/CA_LIST.cer"

int tls_fixer_load_ca_file(mbedtls_x509_crt *chain, const char *path);

#endif
