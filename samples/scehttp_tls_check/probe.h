#ifndef VITA_TLS_CHECK_PROBE_H
#define VITA_TLS_CHECK_PROBE_H
#include "model.h"
typedef int (*CheckFetch)(void *context, unsigned test, int verify, char *body,
                          size_t *length, CheckResult *result);
void check_run_protocol(unsigned test, CheckFetch fetch, void *context, char *body,
                        size_t *length, CheckResult *result);
#endif
