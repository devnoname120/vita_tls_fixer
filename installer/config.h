#ifndef TLS_FIXER_INSTALLER_CONFIG_H
#define TLS_FIXER_INSTALLER_CONFIG_H
#include <stddef.h>

/* read returns a malloc-owned buffer. append/patch never replace or truncate
 * the active configuration. patch must compare the expected byte first. */
typedef struct {
    int (*read)(void *context, char **data, size_t *size);
    int (*append)(void *context, const char *data, size_t size);
    int (*patch)(void *context, size_t offset, char expected, char value);
    int (*sync)(void *context);
    void *context;
} TlsFixerConfigIo;

int tls_fixer_config_disable(const TlsFixerConfigIo *io);
int tls_fixer_config_check(const TlsFixerConfigIo *io);
int tls_fixer_config_enable(const TlsFixerConfigIo *io, const char *kernel_path);
int tls_fixer_config_enabled(const TlsFixerConfigIo *io, const char *kernel_path);

#endif
