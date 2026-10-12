#ifndef TLS_FIXER_POST_START_H
#define TLS_FIXER_POST_START_H

#include <psp2kern/types.h>

#define TLS_FIXER_PENDING_BROWSER_LIMIT 8u
#define TLS_FIXER_PENDING_BROWSER_PATH_SIZE 256u

int tls_fixer_post_start_init(void);
int tls_fixer_post_start_destroy(void);
int tls_fixer_post_start_defer(SceUID pid, SceUID module, const char *path);
int tls_fixer_post_start_defer_http(SceUID pid, SceUID module);
int tls_fixer_post_start_complete(SceUID pid, SceUID module, int native_result);

#endif
