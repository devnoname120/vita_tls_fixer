#ifndef TLS_FIXER_STACK_PROBE_H
#define TLS_FIXER_STACK_PROBE_H
#include <stdint.h>
int tls_fixer_stack_probe_init(void);
uint32_t tls_fixer_stack_probe_read(void);
#endif
