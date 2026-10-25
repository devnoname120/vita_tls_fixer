#include "tls_fixer/redirects.h"
#include <kernel_mock.h>
#include <assert.h>
#include <stdio.h>

#define FD 31
#define NOT_FOUND ((int)0x80010002)
#define INVALID ((int)0x80010016)

int syscall_depth;
static const char *file_text;
static int read_error, copy_error, opens, closes;
static SceSize largest_read;

int ksceIoOpen(const char *path, int flags, int mode) {
    assert(strcmp(path, "ux0:data/tls_fixer/redirects.txt") == 0 && flags == SCE_O_RDONLY && mode == 0);
    /* The file is only touched inside the syscall state */
    assert(syscall_depth == 1);
    if (file_text == NULL) return NOT_FOUND;
    /* Only successful opens are counted, as only those need closing */
    ++opens;
    return FD;
}
int ksceIoPread(SceUID fd, void *data, SceSize size, SceOff offset) {
    assert(fd == FD && offset >= 0);
    if (size > largest_read) largest_read = size;
    if (read_error) return read_error;
    size_t length = strlen(file_text);
    if ((size_t)offset >= length) return 0;
    size_t count = length - (size_t)offset;
    if (count > size) count = size;
    memcpy(data, file_text + offset, count);
    return (int)count;
}
int ksceIoClose(int fd) { assert(fd == FD && syscall_depth == 1); ++closes; return 0; }
int ksceKernelCopyToUser(void *destination, const void *source, SceSize length) {
    assert(syscall_depth == 1);
    if (copy_error) return copy_error;
    memcpy(destination, source, length);
    return 0;
}

static void reset(const char *text) {
    file_text = text;
    read_error = copy_error = opens = closes = 0;
    largest_read = 0;
}

static void check_state_restored(void) {
    assert(syscall_depth == 0 && opens == closes);
}

/* The list is copied in pieces, from any offset, and the end reads as 0 */
static void test_reads_in_pieces(void) {
    char buffer[300];
    reset("old.example new.example\nsecond.example two.example\n");
    memset(buffer, 0, sizeof(buffer));
    assert(tls_fixer_redirects_read(0, buffer, 10) == 10 && memcmp(buffer, "old.exampl", 10) == 0);
    assert(tls_fixer_redirects_read(24, buffer, 6) == 6 && memcmp(buffer, "second", 6) == 0);
    int length = (int)strlen(file_text);
    assert(tls_fixer_redirects_read(0, buffer, sizeof(buffer)) == length);
    assert(tls_fixer_redirects_read((unsigned int)length, buffer, 10) == 0);
    assert(tls_fixer_redirects_read(100000, buffer, 10) == 0);
    /* Each read opens and closes the list, so the next game sees the latest edits */
    assert(opens == 5);
    check_state_restored();
}

/* A request larger than a piece is cut to one, so the kernel's buffer cannot overflow */
static void test_large_requests_are_cut(void) {
    static char big[1024];
    char buffer[1024];
    memset(big, 'a', sizeof(big) - 1);
    reset(big);
    assert(tls_fixer_redirects_read(0, buffer, sizeof(buffer)) == (int)TLS_FIXER_REDIRECTS_CHUNK);
    assert(largest_read == TLS_FIXER_REDIRECTS_CHUNK);
    check_state_restored();
}

/* Errors are returned as they are, and nothing is left open */
static void test_errors(void) {
    char buffer[16];
    reset(NULL);
    assert(tls_fixer_redirects_read(0, buffer, sizeof(buffer)) == NOT_FOUND && closes == 0);
    check_state_restored();

    reset("old.example new.example\n");
    read_error = (int)0x80010005;
    assert(tls_fixer_redirects_read(0, buffer, sizeof(buffer)) == (int)0x80010005 && closes == 1);
    check_state_restored();

    /* A bad destination in the caller's memory */
    reset("old.example new.example\n");
    copy_error = (int)0x800F0000;
    assert(tls_fixer_redirects_read(0, buffer, sizeof(buffer)) == INVALID && closes == 1);
    check_state_restored();

    /* Arguments are checked before anything is opened */
    reset("old.example new.example\n");
    assert(tls_fixer_redirects_read(0, NULL, 16) == INVALID);
    assert(tls_fixer_redirects_read(0, buffer, 0) == INVALID);
    assert(opens == 0);
    check_state_restored();
}

int main(void) {
    test_reads_in_pieces();
    test_large_requests_are_cut();
    test_errors();
    puts("kernel redirect list reads PASS");
    return 0;
}
