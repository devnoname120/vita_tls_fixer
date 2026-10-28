#include <kernel_mock.h>
SceUID ksceKernelFindMemBlockByAddrForPid(SceUID pid, const void *address, SceSize size);
int ksceKernelGetMemBlockType(SceUID block, unsigned int *type);
