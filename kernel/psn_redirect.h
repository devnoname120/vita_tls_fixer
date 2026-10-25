#ifndef TLS_FIXER_PSN_REDIRECT_H
#define TLS_FIXER_PSN_REDIRECT_H
#include <psp2kern/types.h>
#ifndef TLS_FIXER_ENABLE_PSN_REDIRECT
#define TLS_FIXER_ENABLE_PSN_REDIRECT 0
#endif
#if TLS_FIXER_ENABLE_PSN_REDIRECT
int tls_fixer_psn_redirect_init(void);
void tls_fixer_psn_redirect_destroy(void);
int tls_fixer_psn_redirect_wanted(SceUID pid, const char *path, int is_libhttp);
int tls_fixer_psn_redirect_inject(SceUID pid);
#else
static inline int tls_fixer_psn_redirect_init(void) { return 0; }
static inline void tls_fixer_psn_redirect_destroy(void) {}
static inline int tls_fixer_psn_redirect_wanted(SceUID pid, const char *path, int is_libhttp) {
    (void)pid; (void)path; (void)is_libhttp; return 0;
}
static inline int tls_fixer_psn_redirect_inject(SceUID pid) { (void)pid; return 0; }
#endif
#endif
