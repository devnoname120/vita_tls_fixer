#ifndef TLS_FIXER_PROBE_REPORT_NATIVE_FIXTURE_H
#define TLS_FIXER_PROBE_REPORT_NATIVE_FIXTURE_H
#include <stdint.h>
typedef unsigned int SceSize;
typedef struct { unsigned int st_mode; } SceIoStat;
#define SCE_O_WRONLY 2
#define SCE_O_CREAT 0x200
#define SCE_O_EXCL 0x800
#define SCE_S_ISDIR(m) (((m) & 0xf000u) == 0x1000u)
int sceIoMkdir(const char *, unsigned int);
int sceIoGetstat(const char *, SceIoStat *);
int sceIoOpen(const char *, int, unsigned int);
int sceIoWrite(int, const void *, SceSize);
int sceIoSync(const char *, unsigned int);
int sceIoClose(int);
#endif
