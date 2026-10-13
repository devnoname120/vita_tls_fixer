#define _GNU_SOURCE
#include <vita_mock.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MOCK_CAPACITY 1024
static pthread_mutex_t table_lock = PTHREAD_MUTEX_INITIALIZER;
static struct { pthread_mutex_t native; int used; } mutexes[MOCK_CAPACITY];
static struct { pthread_cond_t native; int used, mutex; } conditions[MOCK_CAPACITY];
int mock_entropy_fail_after = -1;
unsigned int mock_entropy_calls;
unsigned int mock_entropy_max_request;
int mock_clock_failure;
const char *mock_ca_file;
int mock_ca_namespace_error, mock_ca_namespace_unterminated;

int _sceAppMgrConvertVs0UserDrivePath(const char *path, char *output, SceSize capacity,
    const void *options) {
    assert(path != NULL && options != NULL && capacity == 0x124);
    if (mock_ca_namespace_error) return -1;
    if (mock_ca_namespace_unterminated) memset(output, 'x', capacity);
    else { assert(strlen(path) < capacity); strcpy(output, path); }
    return 0;
}
const char *mock_log_file;
const char *mock_savedata_log_file;
int mock_log_primary_failure;
int mock_log_fallback_failure;
unsigned int mock_log_write_chunk;
int mock_log_write_failure;
int mock_send_eagain;
int mock_recv_eagain;

int sceKernelGetRandomNumber(void *output, SceSize size) {
    unsigned int calls = __atomic_add_fetch(&mock_entropy_calls, 1, __ATOMIC_RELAXED);
    if (size > mock_entropy_max_request) mock_entropy_max_request = size;
    if (size > 64 || (mock_entropy_fail_after >= 0 && calls > (unsigned int)mock_entropy_fail_after)) return -1;
    return getrandom(output, size, 0) == (ssize_t)size ? 0 : -1;
}

SceUID sceKernelGetProcessId(void) { return (SceUID)getpid(); }

uint64_t sceKernelGetSystemTimeWide(void) {
    struct timespec now;
    assert(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    return (uint64_t)now.tv_sec * 1000000 + (uint64_t)now.tv_nsec / 1000;
}

SceUID sceKernelCreateMutex(const char *name, unsigned int attr, int count, const void *options) {
    int id;
    pthread_mutexattr_t attributes;
    (void)name; (void)attr; (void)options;
    assert(count == 0);
    pthread_mutexattr_init(&attributes);
    pthread_mutexattr_settype(&attributes, PTHREAD_MUTEX_ERRORCHECK);
    pthread_mutex_lock(&table_lock);
    for (id = 1; id < MOCK_CAPACITY && mutexes[id].used; ++id) {}
    if (id < MOCK_CAPACITY) {
        assert(pthread_mutex_init(&mutexes[id].native, &attributes) == 0);
        mutexes[id].used = 1;
    }
    pthread_mutex_unlock(&table_lock);
    pthread_mutexattr_destroy(&attributes);
    return id < MOCK_CAPACITY ? id : -1;
}

int sceKernelDeleteMutex(SceUID id) {
    int result;
    assert(id > 0 && id < MOCK_CAPACITY && mutexes[id].used);
    pthread_mutex_lock(&table_lock);
    result = pthread_mutex_destroy(&mutexes[id].native);
    if (result == 0) mutexes[id].used = 0;
    pthread_mutex_unlock(&table_lock);
    return -result;
}

int sceKernelLockMutex(SceUID id, int count, unsigned int *timeout) {
    assert(id > 0 && id < MOCK_CAPACITY && mutexes[id].used && count == 1 && timeout == NULL);
    return -pthread_mutex_lock(&mutexes[id].native);
}

int sceKernelTryLockMutex(SceUID id, int count) {
    assert(id > 0 && id < MOCK_CAPACITY && mutexes[id].used && count == 1);
    return -pthread_mutex_trylock(&mutexes[id].native);
}

int sceKernelUnlockMutex(SceUID id, int count) {
    assert(id > 0 && id < MOCK_CAPACITY && mutexes[id].used && count == 1);
    return -pthread_mutex_unlock(&mutexes[id].native);
}

SceUID sceKernelCreateCond(const char *name, unsigned int attr, SceUID mutex, const void *options) {
    int id;
    (void)name; (void)attr; (void)options;
    assert(mutex > 0 && mutex < MOCK_CAPACITY && mutexes[mutex].used);
    pthread_mutex_lock(&table_lock);
    for (id = 1; id < MOCK_CAPACITY && conditions[id].used; ++id) {}
    if (id < MOCK_CAPACITY) {
        assert(pthread_cond_init(&conditions[id].native, NULL) == 0);
        conditions[id].mutex = mutex;
        conditions[id].used = 1;
    }
    pthread_mutex_unlock(&table_lock);
    return id < MOCK_CAPACITY ? id : -1;
}

int sceKernelDeleteCond(SceUID id) {
    int result;
    assert(id > 0 && id < MOCK_CAPACITY && conditions[id].used);
    pthread_mutex_lock(&table_lock);
    result = pthread_cond_destroy(&conditions[id].native);
    if (result == 0) conditions[id].used = 0;
    pthread_mutex_unlock(&table_lock);
    return -result;
}

int sceKernelWaitCond(SceUID id, unsigned int *timeout) {
    assert(id > 0 && id < MOCK_CAPACITY && conditions[id].used && timeout == NULL);
    return -pthread_cond_wait(&conditions[id].native, &mutexes[conditions[id].mutex].native);
}

int sceKernelSignalCond(SceUID id) {
    assert(id > 0 && id < MOCK_CAPACITY && conditions[id].used);
    return -pthread_cond_signal(&conditions[id].native);
}

int sceKernelSignalCondAll(SceUID id) {
    assert(id > 0 && id < MOCK_CAPACITY && conditions[id].used);
    return -pthread_cond_broadcast(&conditions[id].native);
}

int sceRtcGetCurrentTick(SceRtcTick *tick) {
    struct timespec now;
    if (mock_clock_failure || clock_gettime(CLOCK_REALTIME, &now) != 0) return -1;
    tick->tick = UINT64_C(62135596800000000) + (uint64_t)now.tv_sec * 1000000 + (uint64_t)now.tv_nsec / 1000;
    return 0;
}

int sceRtcSetTick(SceDateTime *date, const SceRtcTick *tick) {
    time_t seconds = (time_t)(tick->tick / 1000000) - INT64_C(62135596800);
    struct tm utc;
    if (gmtime_r(&seconds, &utc) == NULL) return -1;
    date->year = (uint16_t)(utc.tm_year + 1900);
    date->month = (uint16_t)(utc.tm_mon + 1);
    date->day = (uint16_t)utc.tm_mday;
    date->hour = (uint16_t)utc.tm_hour;
    date->minute = (uint16_t)utc.tm_min;
    date->second = (uint16_t)utc.tm_sec;
    date->microsecond = (uint32_t)(tick->tick % 1000000);
    return 0;
}

int sceRtcGetDaysInMonth(int year, int month) {
    static const int days[] = {31,28,31,30,31,30,31,31,30,31,30,31};
    if (month < 1 || month > 12) return -1;
    return days[month-1] + (month == 2 && year % 4 == 0 && (year % 100 != 0 || year % 400 == 0));
}

int sceRtcGetDayOfWeek(int year, int month, int day) {
    struct tm date = { .tm_year = year - 1900, .tm_mon = month - 1, .tm_mday = day };
    (void)timegm(&date);
    return date.tm_wday;
}

int sceRtcCheckValid(const SceDateTime *date) {
    if (date->year < 1 || date->year > 9999 || date->month < 1 || date->month > 12 ||
        date->day < 1 || date->day > sceRtcGetDaysInMonth(date->year, date->month) ||
        date->hour > 23 || date->minute > 59 || date->second > 59 || date->microsecond > 999999) {
        return -1;
    }
    return 0;
}

int sceRtcGetTick(const SceDateTime *date, SceRtcTick *tick) {
    struct tm utc = { .tm_year = date->year - 1900, .tm_mon = date->month - 1,
        .tm_mday = date->day, .tm_hour = date->hour, .tm_min = date->minute, .tm_sec = date->second };
    if (sceRtcCheckValid(date) < 0) return -1;
    tick->tick = (uint64_t)((int64_t)timegm(&utc) + INT64_C(62135596800)) * 1000000 + date->microsecond;
    return 0;
}

static int socket_result(ssize_t result) {
    if (result >= 0) return (int)result;
    if (errno == EAGAIN || errno == EWOULDBLOCK) return SCE_NET_ERROR_EAGAIN;
    if (errno == EINTR) return SCE_NET_ERROR_EINTR;
    if (errno == ETIMEDOUT) return SCE_NET_ERROR_ETIMEDOUT;
    return SCE_NET_ERROR_ECONNRESET;
}

int sceNetSend(int fd, const void *buffer, unsigned int length, int flags) {
    if (mock_send_eagain > 0) { --mock_send_eagain; return SCE_NET_ERROR_EAGAIN; }
    assert((flags & ~SCE_NET_MSG_DONTWAIT) == 0);
    return socket_result(send(fd, buffer, length,
        (flags & SCE_NET_MSG_DONTWAIT ? MSG_DONTWAIT : 0) | MSG_NOSIGNAL));
}

int sceNetRecv(int fd, void *buffer, unsigned int length, int flags) {
    if (mock_recv_eagain > 0) { --mock_recv_eagain; return SCE_NET_ERROR_EAGAIN; }
    assert((flags & ~SCE_NET_MSG_DONTWAIT) == 0);
    return socket_result(recv(fd, buffer, length,
        flags & SCE_NET_MSG_DONTWAIT ? MSG_DONTWAIT : 0));
}

int sceIoOpen(const char *path, int flags, int mode) {
    (void)mode;
    if (strncmp(path, "vs0:", 4) == 0 && mock_ca_file != NULL) path = mock_ca_file;
    if (strncmp(path, "ux0:", 4) == 0) {
        if (mock_log_primary_failure) return -1;
        if (mock_log_file != NULL) path = mock_log_file;
    }
    if (strncmp(path, "savedata0:", 10) == 0) {
        if (mock_log_fallback_failure) return -1;
        if (mock_savedata_log_file != NULL) path = mock_savedata_log_file;
    }
    if (flags & SCE_O_WRONLY) {
        return open(path, O_WRONLY | (flags & SCE_O_APPEND ? O_APPEND : 0) |
            (flags & SCE_O_CREAT ? O_CREAT : 0), 0600);
    }
    return open(path, O_RDONLY);
}
int sceIoClose(int fd) { return close(fd); }
int sceIoRead(int fd, void *buffer, unsigned int size) { return (int)read(fd, buffer, size); }
int sceIoWrite(int fd, const void *buffer, unsigned int size) {
    if (mock_log_write_failure) return -1;
    if (mock_log_write_chunk && size > mock_log_write_chunk) size = mock_log_write_chunk;
    return (int)write(fd, buffer, size);
}
int64_t sceIoLseek(int fd, int64_t offset, int origin) { return lseek(fd, offset, origin); }
