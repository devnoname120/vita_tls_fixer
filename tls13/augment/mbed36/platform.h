#ifndef TLS_FIXER_PLATFORM36_H
#define TLS_FIXER_PLATFORM36_H
#include <stddef.h>
int mbedtls_hardware_poll(void *unused, unsigned char *output, size_t length, size_t *written);
#endif
