#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdio.h>
#include <unistd.h>

int __wrap_printf(const char *format, ...);
int __wrap_puts(const char *text);

int main(void) {
    FILE *capture = tmpfile();
    assert(capture != NULL);
    assert(fflush(stdout) == 0);
    int previous = dup(STDOUT_FILENO);
    assert(previous >= 0 && dup2(fileno(capture), STDOUT_FILENO) >= 0);
    assert(__wrap_printf("%s:%u", "quiet", 17) == 8);
    assert(__wrap_printf("%s", "") == 0);
    assert(__wrap_puts("quiet") >= 0);
    assert(fflush(stdout) == 0);
    assert(lseek(fileno(capture), 0, SEEK_END) == 0);
    assert(dup2(previous, STDOUT_FILENO) >= 0);
    close(previous);
    fclose(capture);
    puts("Release printf/puts preserve results without console output: PASS");
    return 0;
}
