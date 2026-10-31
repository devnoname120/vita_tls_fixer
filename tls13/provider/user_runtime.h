#ifndef TLS_FIXER_USER_RUNTIME_H
#define TLS_FIXER_USER_RUNTIME_H

#include <stddef.h>
#include <stdarg.h>
#include <stdint.h>

/* Wrappers are local to the HTTP payload, not the application's libc.
 * The augmented backend borrows Sony's SSL pool; legacy runtimes are isolated. */
typedef struct TlsFixerRuntimeStats {
    uint32_t capacity;
    uint32_t peak;
    uint32_t used;
    uint32_t outstanding;
} TlsFixerRuntimeStats;

int tls_fixer_user_runtime_init(void);
int tls_fixer_user_runtime_destroy(void);
int tls_fixer_user_runtime_stats(TlsFixerRuntimeStats *stats);

/* Linker wrappers satisfy unmodified provider/dependency C calls. */
void *__wrap_malloc(size_t size);
void *__wrap_calloc(size_t count, size_t size);
void *__wrap_realloc(void *pointer, size_t size);
void __wrap_free(void *pointer);
void *__wrap_memchr(const void *source, int value, size_t size);
int __wrap_memcmp(const void *left, const void *right, size_t size);
void *__wrap_memcpy(void *destination, const void *source, size_t size);
void *__wrap_memmove(void *destination, const void *source, size_t size);
void *__wrap_memset(void *destination, int value, size_t size);
char *__wrap_strchr(const char *source, int value);
int __wrap_strcmp(const char *left, const char *right);
size_t __wrap_strlen(const char *source);
char *__wrap_strstr(const char *source, const char *needle);
int __wrap_printf(const char *format, ...) __attribute__((format(printf, 1, 2)));
int __wrap_puts(const char *source);
int __wrap_snprintf(char *output, size_t capacity, const char *format, ...)
    __attribute__((format(printf, 3, 4)));
int __wrap_vsnprintf(char *output, size_t capacity, const char *format, va_list args)
    __attribute__((format(printf, 3, 0)));

#endif
