#ifndef TLS_FIXER_INSTALLER_NETWORK_VITA_H
#define TLS_FIXER_INSTALLER_NETWORK_VITA_H

typedef struct TlsFixerInstallerNetwork {
    void *memory;
    int module_owned, net_owned, ctl_owned;
} TlsFixerInstallerNetwork;

int tls_fixer_installer_network_start(TlsFixerInstallerNetwork *network);
void tls_fixer_installer_network_stop(TlsFixerInstallerNetwork *network);

#endif
