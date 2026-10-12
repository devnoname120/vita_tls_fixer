#ifndef TLS_FIXER_PROBE_PLATFORM_VITA_H
#define TLS_FIXER_PROBE_PLATFORM_VITA_H
#include "core.h"

typedef struct TlsFixerProbeNetwork {
    void *memory;
    int module_owned, net_owned, ctl_owned;
    int socket, epoll, error, cleanup_error;
    TlsFixerProbeIo io;
} TlsFixerProbeNetwork;

int tls_fixer_probe_network_init(TlsFixerProbeNetwork *network);
int tls_fixer_probe_network_ready(TlsFixerProbeNetwork *network);
int tls_fixer_probe_network_free(TlsFixerProbeNetwork *network);
#endif
