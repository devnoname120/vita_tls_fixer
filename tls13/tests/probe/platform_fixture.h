#ifndef PROBE_PLATFORM_FIXTURE_H
#define PROBE_PLATFORM_FIXTURE_H
#include <stddef.h>
#include <stdint.h>
#define SCE_SYSMODULE_NET 1
#define SCE_SYSMODULE_LOADED 0
#define SCE_SYSMODULE_ERROR_UNLOADED ((int)0x805a1001)
#define SCE_NET_AF_INET 2
#define SCE_NET_SOCK_STREAM 1
#define SCE_NET_SOL_SOCKET 65535
#define SCE_NET_SO_NBIO 0x1100
#define SCE_NET_SO_ERROR 0x1007
#define SCE_NET_EPOLL_CTL_ADD 1
#define SCE_NET_EPOLL_CTL_MOD 2
#define SCE_NET_EPOLLIN 1
#define SCE_NET_EPOLLOUT 2
#define SCE_NET_EPOLLERR 8
#define SCE_NET_EPOLLHUP 16
#define SCE_NET_ERROR_EAGAIN ((int)0x80410123)
#define SCE_NET_ERROR_EINTR ((int)0x80410104)
#define SCE_NET_ERROR_EINPROGRESS ((int)0x80410124)
#define SCE_NET_ERROR_EALREADY ((int)0x80410125)
#define SCE_NET_ERROR_ECONNRESET ((int)0x80410136)
#define SCE_NET_ERROR_ETIMEDOUT ((int)0x8041013c)
#define SCE_NETCTL_STATE_CONNECTED 3

typedef struct { void *memory; int size, flags; } SceNetInitParam;
typedef struct { uint32_t s_addr; } SceNetInAddr;
typedef struct { uint8_t sin_len, sin_family; uint16_t sin_port; SceNetInAddr sin_addr; char pad[8]; } SceNetSockaddrIn;
typedef struct { char data[16]; } SceNetSockaddr;
typedef struct { unsigned int events; int unused[7]; } SceNetEpollEvent;
int sceSysmoduleIsLoaded(int);
int sceSysmoduleLoadModule(int);
int sceSysmoduleUnloadModule(int);
int sceNetInit(SceNetInitParam *);
int sceNetTerm(void);
int sceNetCtlInit(void);
void sceNetCtlTerm(void);
int sceNetCtlInetGetState(int *);
int sceKernelDelayThread(unsigned int);
uint64_t sceKernelGetSystemTimeWide(void);
int sceNetInetPton(int, const char *, void *);
uint16_t sceNetHtons(uint16_t);
int sceNetSocket(const char *, int, int, int);
int sceNetSetsockopt(int, int, int, const void *, unsigned int);
int sceNetGetsockopt(int, int, int, void *, unsigned int *);
int sceNetEpollCreate(const char *, int);
int sceNetEpollControl(int, int, int, SceNetEpollEvent *);
int sceNetEpollWait(int, SceNetEpollEvent *, int, int);
int sceNetEpollDestroy(int);
int sceNetSocketClose(int);
int sceNetConnect(int, const SceNetSockaddr *, unsigned int);
int sceNetSend(int, const void *, unsigned int, int);
int sceNetRecv(int, void *, unsigned int, int);
#endif
