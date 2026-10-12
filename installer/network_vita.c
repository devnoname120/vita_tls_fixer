#include "network_vita.h"

#include <psp2/kernel/processmgr.h>
#include <psp2/kernel/threadmgr.h>
#include <psp2/net/net.h>
#include <psp2/net/netctl.h>
#include <psp2/sysmodule.h>
#include <stdlib.h>
#include <string.h>

int tls_fixer_installer_network_start(TlsFixerInstallerNetwork *network) {
    memset(network, 0, sizeof(*network));
    int result = sceSysmoduleIsLoaded(SCE_SYSMODULE_NET);
    if ((unsigned int)result == (unsigned int)SCE_SYSMODULE_ERROR_UNLOADED) {
        if (sceSysmoduleLoadModule(SCE_SYSMODULE_NET) < 0) return -1;
        network->module_owned = 1;
    } else if (result != SCE_SYSMODULE_LOADED) return -1;
    network->memory = malloc(1024 * 1024);
    if (network->memory == NULL) return -1;
    SceNetInitParam parameters = {network->memory, 1024 * 1024, 0};
    if (sceNetInit(&parameters) < 0) return -1;
    network->net_owned = 1;
    if (sceNetCtlInit() < 0) return -1;
    network->ctl_owned = 1;
    uint64_t begin = sceKernelGetSystemTimeWide();
    for (;;) {
        int state = -1;
        if (sceNetCtlInetGetState(&state) < 0) return -1;
        if (state == SCE_NETCTL_STATE_CONNECTED) return 0;
        uint64_t now = sceKernelGetSystemTimeWide();
        if (now < begin || now - begin >= 5000000) return -1;
        if (sceKernelDelayThread(100000) < 0) return -1;
    }
}

void tls_fixer_installer_network_stop(TlsFixerInstallerNetwork *network) {
    if (network->ctl_owned) { sceNetCtlTerm(); network->ctl_owned = 0; }
    if (network->net_owned) {
        /* Keep referenced memory/modules alive on a failed native termination. */
        if (sceNetTerm() < 0) return;
        network->net_owned = 0;
    }
    free(network->memory);
    network->memory = NULL;
    if (network->module_owned && sceSysmoduleUnloadModule(SCE_SYSMODULE_NET) >= 0)
        network->module_owned = 0;
}
