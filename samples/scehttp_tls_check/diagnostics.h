#ifndef TLS_CHECK_DIAGNOSTICS_H
#define TLS_CHECK_DIAGNOSTICS_H

#include <stdint.h>

/* Observation only: logging failure must never alter the request result. */
void check_diag_init(void);
void check_diag_close(void);
void check_diag_sync(void);
void check_diag(const char *format, ...) __attribute__((format(printf, 1, 2)));
void check_diag_modules(const char *stage);
uint64_t check_diag_time(void);

#endif
