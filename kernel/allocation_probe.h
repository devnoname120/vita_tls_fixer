#ifndef TLS_FIXER_ALLOCATION_PROBE_H
#define TLS_FIXER_ALLOCATION_PROBE_H
#ifndef TLS_FIXER_ALLOCATION_PROBE
#define TLS_FIXER_ALLOCATION_PROBE 0
#endif
#if TLS_FIXER_ALLOCATION_PROBE
int tls_fixer_allocation_probe_prepare(void);
int tls_fixer_allocation_probe_install(void);
int tls_fixer_allocation_probe_resident(void);
void tls_fixer_allocation_probe_drain(void);
#else
static inline int tls_fixer_allocation_probe_prepare(void) { return 0; }
static inline int tls_fixer_allocation_probe_install(void) { return 0; }
static inline int tls_fixer_allocation_probe_resident(void) { return 0; }
static inline void tls_fixer_allocation_probe_drain(void) {}
#endif
#endif
