#ifndef TLS_FIXER_HOST_REDIRECT_H
#define TLS_FIXER_HOST_REDIRECT_H

/* Host redirects for this app, read from ux0:data/tls_fixer/redirects.txt through the kernel plugin
 * When the list has rules, the app's sceHttpCreateConnection, sceHttpCreateConnectionWithURL and
 * sceHttpCreateRequestWithURL calls go to the new host instead of the old one
 * Best effort: a missing or unreadable list, or a failed hook, never affects the provider */
void tls_fixer_host_redirect_install(void);

#endif
