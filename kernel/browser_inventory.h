#ifndef TLS_FIXER_BROWSER_INVENTORY_H
#define TLS_FIXER_BROWSER_INVENTORY_H

#include <psp2kern/types.h>
#ifndef TLS_FIXER_BROWSER_INVENTORY
#define TLS_FIXER_BROWSER_INVENTORY 0
#endif

#define TLS_FIXER_BROWSER_INVENTORY_PATH "ur0:tai/tls_fixer-browser-inventory.log"
#if TLS_FIXER_BROWSER_INVENTORY
void tls_fixer_browser_inventory_reset(void);
void tls_fixer_browser_inventory_request(SceUID pid);
int tls_fixer_browser_inventory_tick(void);
#else
static inline void tls_fixer_browser_inventory_reset(void) {}
static inline void tls_fixer_browser_inventory_request(SceUID pid) { (void)pid; }
static inline int tls_fixer_browser_inventory_tick(void) { return 0; }
#endif

#endif
