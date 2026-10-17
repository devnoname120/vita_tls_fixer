#include <stdarg.h>
#include <stdio.h>

/* Release builds silence library diagnostics as well as provider trace calls.
 * Keep printf's count semantics without writing to the host process console. */
int __wrap_printf(const char *format, ...) {
    va_list args;
    va_start(args, format);
    int result = vsnprintf(NULL, 0, format, args);
    va_end(args);
    return result;
}

int __wrap_puts(const char *text) {
    (void)text;
    return 0;
}
