#ifndef TLS_FIXER_VITA_MOCK_H
#define TLS_FIXER_VITA_MOCK_H

#include <stddef.h>
#include <stdint.h>

typedef int SceUID;
typedef uint32_t SceSize;
typedef uint16_t SceUInt16;
typedef uint32_t SceUInt;
typedef struct { uint64_t tick; } SceRtcTick;
typedef struct {
    uint16_t year, month, day, hour, minute, second;
    uint32_t microsecond;
} SceDateTime;

#define SCE_O_RDONLY 1
#define SCE_O_WRONLY 2
#define SCE_O_APPEND 0x100
#define SCE_O_CREAT 0x200
#define SCE_SEEK_SET 0
#define SCE_SEEK_END 2
#define SCE_NET_ERROR_EAGAIN ((int32_t)0x80410123)
#define SCE_NET_ERROR_EINTR ((int32_t)0x80410104)
#define SCE_NET_ERROR_ECONNRESET ((int32_t)0x80410136)
#define SCE_NET_ERROR_ETIMEDOUT ((int32_t)0x8041013c)
#define SCE_NET_MSG_DONTWAIT 0x80
#define SCE_NET_AF_INET 2
#define SCE_NET_SOCK_DGRAM 2
typedef struct { uint32_t s_addr; } SceNetInAddr;
typedef struct { uint8_t sa_len, sa_family; char sa_data[14]; } SceNetSockaddr;
typedef struct {
    uint8_t sin_len, sin_family;
    uint16_t sin_port;
    SceNetInAddr sin_addr;
    uint16_t sin_vport;
    char sin_zero[6];
} SceNetSockaddrIn;

int sceKernelGetRandomNumber(void *output, SceSize size);
SceUID sceKernelGetProcessId(void);
SceUID sceKernelGetThreadId(void);
uint64_t sceKernelGetSystemTimeWide(void);
SceUID sceKernelCreateMutex(const char *, unsigned int, int, const void *);
int sceKernelDeleteMutex(SceUID);
int sceKernelLockMutex(SceUID, int, unsigned int *);
int sceKernelTryLockMutex(SceUID, int);
int sceKernelUnlockMutex(SceUID, int);
SceUID sceKernelCreateCond(const char *, unsigned int, SceUID, const void *);
int sceKernelDeleteCond(SceUID);
int sceKernelWaitCond(SceUID, unsigned int *);
int sceKernelSignalCond(SceUID);
int sceKernelSignalCondAll(SceUID);
int sceRtcGetCurrentTick(SceRtcTick *);
int sceRtcSetTick(SceDateTime *, const SceRtcTick *);
int sceRtcCheckValid(const SceDateTime *);
int sceRtcGetTick(const SceDateTime *, SceRtcTick *);
int sceRtcGetDaysInMonth(int, int);
int sceRtcGetDayOfWeek(int, int, int);
int sceNetSend(int, const void *, unsigned int, int);
int sceNetRecv(int, void *, unsigned int, int);
int sceNetSocket(const char *, int, int, int);
int sceNetSocketClose(int);
int sceNetInetPton(int, const char *, void *);
uint16_t sceNetHtons(uint16_t);
int *sceNetErrnoLoc(void);
int sceNetSendto(int, const void *, unsigned int, int, const SceNetSockaddr *, unsigned int);
int sceIoOpen(const char *, int, int);
int sceIoClose(int);
int sceIoRead(int, void *, unsigned int);
int sceIoWrite(int, const void *, unsigned int);
int64_t sceIoLseek(int, int64_t, int);

extern int mock_entropy_fail_after;
extern unsigned int mock_entropy_calls;
extern unsigned int mock_entropy_max_request;
extern int mock_clock_failure;
extern const char *mock_ca_file;
extern const char *mock_log_file;
extern const char *mock_savedata_log_file;
extern int mock_log_primary_failure;
extern int mock_log_fallback_failure;
extern unsigned int mock_log_write_chunk;
extern int mock_log_write_failure;
extern int mock_send_eagain;
extern int mock_recv_eagain;

#endif
