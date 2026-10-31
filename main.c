/*
	Original installer code by SKGleba
	All Rights Reserved
*/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <psp2/ctrl.h>
#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#include <psp2/io/dirent.h>
#include <psp2/kernel/processmgr.h>
#include <psp2/kernel/modulemgr.h>
#include <psp2/sysmodule.h>
#include <psp2/power.h>
#include <psp2/vshbridge.h>

#include "graphics.h"
#include "installer/certificates.h"
#include "installer/network_vita.h"
#include "installer/options.h"
#include "installer/system_payloads.h"
#include "installer/config.h"
#include "installer/conflicts.h"
#include "kernel/self_disarm.h"

#define printf psvDebugScreenPrintf

#define COPY_BUFFER_SIZE 0x4000
#define CONFIG_MAX_SIZE 0x100000
#ifndef TLS_FIXER_INSTALL_AUGMENTED_HTTP
#define TLS_FIXER_INSTALL_AUGMENTED_HTTP 0
#endif
#ifndef TLS_FIXER_AUGMENTED_RELEASE
#define TLS_FIXER_AUGMENTED_RELEASE 0
#endif
#define TLS_FIXER_SYSTEM_TRIAL (TLS_FIXER_INSTALL_AUGMENTED_HTTP && !TLS_FIXER_AUGMENTED_RELEASE)
#if TLS_FIXER_SYSTEM_TRIAL
#define INSTALLER_KERNEL_PATH TLS_FIXER_REMOVABLE_KERNEL_PATH
static const enum TlsFixerOption menu_options[] = {TLS_FIXER_OPTION_SYSTEM, TLS_FIXER_OPTION_EXIT};
#else
#define INSTALLER_KERNEL_PATH "ur0:tai/tls_fixer.skprx"
static const enum TlsFixerOption menu_options[] = {TLS_FIXER_OPTION_FULL, TLS_FIXER_OPTION_BROWSER,
    TLS_FIXER_OPTION_SYSTEM, TLS_FIXER_OPTION_CERTIFICATES, TLS_FIXER_OPTION_EXIT};
#endif
#define MENU_COUNT ((int)(sizeof(menu_options) / sizeof(menu_options[0])))

unsigned int _newlib_heap_size_user = 8u * 1024u * 1024u;

#if !TLS_FIXER_INSTALL_AUGMENTED_HTTP
static const char tls_fixer_config_block[] =
    "# TLS_FIXER\n*KERNEL\nur0:tai/tls_fixer.skprx\n\n";
#endif
static const char browser_provider_global[] = "ur0:tai/tls_fixer-native/tls_fixer.suprx";

static const char *const new_modules[] = {
    "vs0:/data/external/tls_fixer/ScePsp2Compat.suprx",
    "vs0:/data/external/tls_fixer/libhttp.suprx",
    "vs0:/data/external/tls_fixer/libssl.suprx",
    "vs0:/data/external/tls_fixer/old_dns_fix.suprx",
    "vs0:/data/external/tls_fixer/np_commerce2.suprx",
    "vs0:/data/external/tls_fixer/native/tls_fixer_http.suprx",
    "vs0:/data/external/tls_fixer/native/tls_fixer.suprx",
    "vs0:/data/external/tls_fixer/native/tls_fixer_psn.suprx",
    "vs0:/data/external/tls_fixer/native/tls_fixer_store.suprx",
};

static const char *const install_menu[TLS_FIXER_OPTION_COUNT] = {
    " -> Install Full (browser plugin + system plugin + certs)",
    " -> Install browser plugin only",
    " -> Install system plugin only",
    " -> Install certs only",
    " -> Exit",
};

static const char *const uninstall_menu[TLS_FIXER_OPTION_COUNT] = {
    " -> Uninstall Full (browser plugin + system plugin + certs)",
    " -> Uninstall browser plugin only",
    " -> Uninstall system plugin only",
    " -> Uninstall certs only",
    " -> Exit",
};

static int selected_option;
static uint8_t installed[TLS_FIXER_OPTION_COUNT];

static int path_exists(const char *path) {
    SceIoStat status;

    return path != NULL && sceIoGetstat(path, &status) >= 0;
}

static int allowed_test_file(const char *path) {
    return !strncmp(path, TLS_FIXER_AUGMENTED_RUNTIME "/", strlen(TLS_FIXER_AUGMENTED_RUNTIME "/")) ||
        (!strncmp(path, INSTALLER_KERNEL_PATH, strlen(INSTALLER_KERNEL_PATH)) &&
         (path[strlen(INSTALLER_KERNEL_PATH)] == 0 || path[strlen(INSTALLER_KERNEL_PATH)] == '.'));
}

static int remove_if_exists(const char *path) {
#if TLS_FIXER_SYSTEM_TRIAL
    if (!allowed_test_file(path)) return -1;
#endif
    if (!path_exists(path)) {
        return 0;
    }
    return sceIoRemove(path);
}

static int write_all(SceUID descriptor, const void *data, SceSize size) {
    const uint8_t *cursor = data;
    SceSize remaining = size;

    while (remaining != 0) {
        SceSSize written = sceIoWrite(descriptor, cursor, remaining);
        if (written < 0) {
            return (int)written;
        }
        if (written == 0) {
            return -1;
        }
        cursor += (SceSize)written;
        remaining -= (SceSize)written;
    }
    return 0;
}

static int copy_file(const char *source, const char *destination) {
    uint8_t *buffer = NULL;
    SceUID source_fd = -1;
    SceUID destination_fd = -1;
    int result = 0;

    source_fd = sceIoOpen(source, SCE_O_RDONLY, 0);
    if (source_fd < 0) {
        return source_fd;
    }
    destination_fd = sceIoOpen(
        destination,
        SCE_O_WRONLY | SCE_O_TRUNC | SCE_O_CREAT,
        0777);
    if (destination_fd < 0) {
        result = destination_fd;
        goto cleanup;
    }

    buffer = malloc(COPY_BUFFER_SIZE);
    if (buffer == NULL) {
        result = -1;
        goto cleanup;
    }

    for (;;) {
        SceSSize read_size = sceIoRead(source_fd, buffer, COPY_BUFFER_SIZE);
        if (read_size < 0) {
            result = (int)read_size;
            break;
        }
        if (read_size == 0) {
            break;
        }
        result = write_all(destination_fd, buffer, (SceSize)read_size);
        if (result < 0) {
            break;
        }
    }

cleanup:
    free(buffer);
    if (destination_fd >= 0) {
        int close_result = sceIoClose(destination_fd);
        if (result >= 0 && close_result < 0) {
            result = close_result;
        }
    }
    if (source_fd >= 0) {
        int close_result = sceIoClose(source_fd);
        if (result >= 0 && close_result < 0) {
            result = close_result;
        }
    }
    if (result < 0) {
        (void)remove_if_exists(destination);
    }
    return result;
}

static int files_equal(const char *source, const char *destination) {
    SceIoStat a, b;
    if (sceIoGetstat(source, &a) < 0 || sceIoGetstat(destination, &b) < 0 || a.st_size != b.st_size) return 0;
    SceUID x = sceIoOpen(source, SCE_O_RDONLY, 0);
    if (x < 0) return 0;
    SceUID y = sceIoOpen(destination, SCE_O_RDONLY, 0);
    if (y < 0) { sceIoClose(x); return 0; }
    unsigned char *buffer = malloc(COPY_BUFFER_SIZE * 2);
    int equal = buffer != NULL;
    SceOff left = a.st_size;
    while (equal && left > 0) {
        unsigned n = left > COPY_BUFFER_SIZE ? COPY_BUFFER_SIZE : (unsigned)left;
        SceUID descriptors[] = {x, y};
        for (unsigned file = 0; file < 2 && equal; ++file) {
            unsigned read = 0;
            while (read < n) {
                int got = sceIoRead(descriptors[file], buffer + file * COPY_BUFFER_SIZE + read, n - read);
                if (got <= 0 || (unsigned)got > n - read) { equal = 0; break; }
                read += (unsigned)got;
            }
        }
        if (equal && memcmp(buffer, buffer + COPY_BUFFER_SIZE, n)) equal = 0;
        left -= n;
    }
    free(buffer);
    if (sceIoClose(x) < 0) equal = 0;
    if (sceIoClose(y) < 0) equal = 0;
    return equal;
}

static int replace_file(const char *source, const char *destination) {
    char temporary[256];
    char previous[256];
    int temporary_length;
    int previous_length;
    int had_previous;
    int result;

    if (TLS_FIXER_SYSTEM_TRIAL && !allowed_test_file(destination)) return -1;
    if (TLS_FIXER_INSTALL_AUGMENTED_HTTP && files_equal(source, destination)) return 0;

    temporary_length = snprintf(temporary, sizeof(temporary), "%s.tmp", destination);
    previous_length = snprintf(previous, sizeof(previous), "%s.tls_fixer-old", destination);
    if (temporary_length < 0 || (size_t)temporary_length >= sizeof(temporary) ||
        previous_length < 0 || (size_t)previous_length >= sizeof(previous)) {
        return -1;
    }

    (void)remove_if_exists(temporary);
    (void)remove_if_exists(previous);
    result = copy_file(source, temporary);
    if (result < 0) {
        return result;
    }

    had_previous = path_exists(destination);
    if (had_previous) {
        result = sceIoRename(destination, previous);
        if (result < 0) {
            (void)remove_if_exists(temporary);
            return result;
        }
    }

    result = sceIoRename(temporary, destination);
    if (result < 0) {
        if (had_previous) {
            (void)sceIoRename(previous, destination);
        }
        (void)remove_if_exists(temporary);
        return result;
    }

    if (TLS_FIXER_INSTALL_AUGMENTED_HTTP && !files_equal(source, destination)) {
        (void)remove_if_exists(destination);
        if (had_previous) (void)sceIoRename(previous, destination);
        return -1;
    }

    if (had_previous) {
        result = remove_if_exists(previous);
    }
    return result;
}

static int system_file_exists(void *context, const char *path) {
    (void)context; return path_exists(path);
}
static int system_file_replace(void *context, const char *source, const char *destination) {
    (void)context; return replace_file(source, destination);
}
static int system_file_remove(void *context, const char *path) {
    (void)context; return remove_if_exists(path);
}
static const TlsFixerSystemFiles system_files = {
    .exists = system_file_exists, .replace = system_file_replace, .remove = system_file_remove
};
static TlsFixerSystemBackend packaged_system_backend(void) {
    return TLS_FIXER_INSTALL_AUGMENTED_HTTP ? (TLS_FIXER_AUGMENTED_RELEASE ?
        TLS_FIXER_SYSTEM_AUGMENTED_RELEASE : TLS_FIXER_SYSTEM_AUGMENTED) : TLS_FIXER_SYSTEM_HOOKED;
}

static int read_file(const char *path, char **data, SceSize *size) {
    SceUID descriptor;
    SceOff file_size;
    char *buffer;
    SceSize total = 0;
    int result = 0;

    if (data == NULL || size == NULL) {
        return -1;
    }
    *data = NULL;
    *size = 0;

    descriptor = sceIoOpen(path, SCE_O_RDONLY, 0);
    if (descriptor < 0) {
        return descriptor;
    }
    file_size = sceIoLseek(descriptor, 0, SCE_SEEK_END);
    if (file_size < 0 || file_size > CONFIG_MAX_SIZE ||
        sceIoLseek(descriptor, 0, SCE_SEEK_SET) < 0) {
        result = file_size < 0 ? (int)file_size : -1;
        (void)sceIoClose(descriptor);
        return result;
    }

    buffer = malloc((size_t)file_size + 1);
    if (buffer == NULL) {
        (void)sceIoClose(descriptor);
        return -1;
    }

    while (total < (SceSize)file_size) {
        SceSSize read_size = sceIoRead(
            descriptor,
            buffer + total,
            (SceSize)file_size - total);
        if (read_size < 0) {
            result = (int)read_size;
            break;
        }
        if (read_size == 0) {
            result = -1;
            break;
        }
        total += (SceSize)read_size;
    }

    if (sceIoClose(descriptor) < 0 && result >= 0) {
        result = -1;
    }
    if (result < 0) {
        free(buffer);
        return result;
    }

    buffer[total] = '\0';
    *data = buffer;
    *size = total;
    return 0;
}

#if !TLS_FIXER_INSTALL_AUGMENTED_HTTP
static int plugin_configured(void) {
    char *config = NULL;
    SceSize config_size = 0;
    int configured = 0;

    if (read_file("ur0:tai/config.txt", &config, &config_size) >= 0) {
        (void)config_size;
        configured = strstr(config, tls_fixer_config_block) != NULL;
    }
    free(config);
    return configured;
}
#endif

typedef struct { const char *path, *mount; } ConfigFile;
static ConfigFile config_files[] = {{"ur0:tai/config.txt", "ur0:"}, {"ux0:tai/config.txt", "ux0:"}};
static int config_read(void *context, char **data, size_t *size) {
    ConfigFile *f = context; SceSize length = 0;
    int rc = read_file(f->path, data, &length); *size = length; return rc;
}
static int config_append(void *context, const char *data, size_t size) {
    ConfigFile *f = context; SceUID fd = sceIoOpen(f->path, SCE_O_WRONLY | SCE_O_APPEND, 0);
    if (fd < 0) return fd;
    int rc = write_all(fd, data, (SceSize)size), closed = sceIoClose(fd);
    return rc < 0 ? rc : closed;
}
static int config_patch(void *context, size_t at, char expected, char value) {
    ConfigFile *f = context; SceUID fd = sceIoOpen(f->path, SCE_O_RDWR, 0);
    if (fd < 0) return fd;
    char actual = 0; int rc = -1;
    if (sceIoLseek(fd, (SceOff)at, SCE_SEEK_SET) == (SceOff)at && sceIoRead(fd, &actual, 1) == 1 && actual == expected &&
        sceIoLseek(fd, (SceOff)at, SCE_SEEK_SET) == (SceOff)at && sceIoWrite(fd, &value, 1) == 1) rc = 0;
    if (sceIoClose(fd) < 0) rc = -1;
    return rc;
}
static int config_sync(void *context) { return sceIoSync(((ConfigFile *)context)->mount, 0); }
static TlsFixerConfigIo config_io(unsigned index) {
    TlsFixerConfigIo io = {config_read, config_append, config_patch, config_sync, &config_files[index]}; return io;
}
#if TLS_FIXER_INSTALL_AUGMENTED_HTTP
static int alternate_config(void) {
    SceIoStat info; int rc = sceIoGetstat(config_files[1].path, &info);
    return rc >= 0 ? 1 : (uint32_t)rc == UINT32_C(0x80010002) ? 0 : -1;
}
static int disarm_installer_entries(void) {
    int alternate = alternate_config();
    if (alternate < 0) return -1;
    for (unsigned i = 0; i <= (unsigned)alternate; ++i) {
        TlsFixerConfigIo io = config_io(i); if (tls_fixer_config_check(&io) < 0) return -1;
    }
    for (unsigned i = 0; i <= (unsigned)alternate; ++i) {
        TlsFixerConfigIo io = config_io(i); if (tls_fixer_config_disable(&io) < 0) return -1;
    }
    return 0;
}
static int enable_installer_entry(void) {
    if (disarm_installer_entries() < 0) return -1;
    int alternate = alternate_config(); if (alternate < 0) return -1;
    TlsFixerConfigIo io = config_io((unsigned)alternate);
    return tls_fixer_config_enable(&io, INSTALLER_KERNEL_PATH);
}
static int installer_entry_enabled(void) {
    int alternate = alternate_config(); if (alternate < 0) return 0;
    TlsFixerConfigIo io = config_io((unsigned)alternate);
    return tls_fixer_config_enabled(&io, INSTALLER_KERNEL_PATH);
}
static int test_payloads_active(void) {
    if (sceSysmoduleIsLoaded(SCE_SYSMODULE_HTTP) < 0 && sceSysmoduleLoadModule(SCE_SYSMODULE_HTTP) < 0) return -1;
    SceUID modules[128]; SceSize count = sizeof(modules) / sizeof(modules[0]);
    if (sceKernelGetModuleList(0xff, modules, &count) < 0 || count >= sizeof(modules) / sizeof(modules[0])) return -1;
    for (SceSize i = 0; i < count; ++i) {
        SceKernelModuleInfo info = {0}; info.size = sizeof(info);
        if (sceKernelGetModuleInfo(modules[i], &info) < 0) return -1;
        if (!strcmp(info.module_name, "SceLibHttp") &&
            !strncmp(info.path, TLS_FIXER_AUGMENTED_RUNTIME "/", strlen(TLS_FIXER_AUGMENTED_RUNTIME "/"))) return 1;
    }
    return 0;
}
#endif

static int conflict_exists(void *context, const char *path) {
    (void)context;
    SceIoStat info;
    int rc = sceIoGetstat(path, &info);
    return rc >= 0 ? 1 : (uint32_t)rc == UINT32_C(0x80010002) ? 0 : rc;
}
static int conflict_config_read(void *context, char **data, size_t *size) {
    int rc = config_read(context, data, size);
    if ((uint32_t)rc == UINT32_C(0x80010002)) {
        *data = calloc(1, 1); *size = 0; return *data ? 0 : -1;
    }
    return rc;
}
static int remove_conflict_tree(const char *path) {
    int exists = conflict_exists(NULL, path);
    if (exists <= 0) return exists;
    SceUID directory = sceIoDopen(path);
    if (directory < 0) return directory;
    int result = 0;
    for (;;) {
        SceIoDirent entry = {0};
        int rc = sceIoDread(directory, &entry);
        if (rc <= 0) { result = rc; break; }
        if (!strcmp(entry.d_name, ".") || !strcmp(entry.d_name, "..")) continue;
        char child[512];
        int n = snprintf(child, sizeof(child), "%s/%s", path, entry.d_name);
        if (n < 0 || (size_t)n >= sizeof(child)) { result = -1; break; }
        rc = SCE_S_ISDIR(entry.d_stat.st_mode) ? remove_conflict_tree(child) : sceIoRemove(child);
        if (rc < 0) { result = rc; break; }
    }
    if (sceIoDclose(directory) < 0) result = -1;
    return result < 0 ? result : sceIoRmdir(path);
}
static int conflict_remove(void *context, const char *path, int directory) {
    (void)context;
    if (directory) return remove_conflict_tree(path);
    int exists = conflict_exists(NULL, path);
    if (exists <= 0) return exists;
    int rc = sceIoRemove(path);
    if (rc < 0) return rc;
    char mount[16]; const char *colon = strchr(path, ':');
    if (!colon || (size_t)(colon - path) + 2 > sizeof(mount)) return -1;
    size_t length = (size_t)(colon - path) + 1;
    memcpy(mount, path, length); mount[length] = 0;
    return sceIoSync(mount, 0);
}
static int conflict_sync(void *context) {
    (void)context;
    const char *const mounts[] = {"ur0:", "ux0:", "vs0:"};
    for (unsigned i = 0; i < sizeof(mounts) / sizeof(mounts[0]); ++i) {
        int rc = sceIoSync(mounts[i], 0); if (rc < 0) return rc;
    }
    return 0;
}
static int conflicting_plugins(int removing) {
    TlsFixerConfigIo configs[2] = {config_io(0), config_io(1)};
    for (unsigned i = 0; i < 2; ++i) configs[i].read = conflict_config_read;
    TlsFixerConflictFiles files = {conflict_exists, conflict_remove, conflict_sync, NULL};
    return removing ? tls_fixer_remove_conflicts(configs, 2, &files) :
        tls_fixer_conflicts_present(configs, 2, &files);
}

#if !TLS_FIXER_INSTALL_AUGMENTED_HTTP
static int install_plugin_config(void) {
    static const char config_path[] = "ur0:tai/config.txt";
    static const char backup_path[] = "ur0:tai/config_pretls_fixer.txt";
    static const char temporary_path[] = "ur0:tai/config_tls_fixer.tmp";
    char *config = NULL;
    SceSize config_size = 0;
    SceUID descriptor;
    int result;

    result = read_file(config_path, &config, &config_size);
    if (result < 0) {
        return result;
    }
    if (strstr(config, tls_fixer_config_block) != NULL) {
        free(config);
        return 0;
    }

    (void)remove_if_exists(temporary_path);
    descriptor = sceIoOpen(
        temporary_path,
        SCE_O_WRONLY | SCE_O_TRUNC | SCE_O_CREAT,
        0777);
    if (descriptor < 0) {
        free(config);
        return descriptor;
    }

    result = write_all(
        descriptor,
        tls_fixer_config_block,
        (SceSize)(sizeof(tls_fixer_config_block) - 1));
    if (result >= 0) {
        result = write_all(descriptor, config, config_size);
    }
    if (sceIoClose(descriptor) < 0 && result >= 0) {
        result = -1;
    }
    free(config);
    if (result < 0) {
        (void)remove_if_exists(temporary_path);
        return result;
    }

    result = remove_if_exists(backup_path);
    if (result < 0) {
        (void)remove_if_exists(temporary_path);
        return result;
    }
    result = sceIoRename(config_path, backup_path);
    if (result < 0) {
        (void)remove_if_exists(temporary_path);
        return result;
    }
    result = sceIoRename(temporary_path, config_path);
    if (result < 0) {
        (void)sceIoRename(backup_path, config_path);
        (void)remove_if_exists(temporary_path);
    }
    return result;
}

static int uninstall_plugin_config(void) {
    static const char config_path[] = "ur0:tai/config.txt";
    static const char temporary_path[] = "ur0:tai/config_tls_fixer.tmp";
    static const char rollback_path[] = "ur0:tai/config_tls_fixer-remove.old";
    char *config = NULL;
    char *match;
    SceSize config_size = 0;
    SceSize before_size;
    SceSize after_offset;
    SceUID descriptor;
    int result;

    if (!path_exists(config_path)) {
        return 0;
    }
    result = read_file(config_path, &config, &config_size);
    if (result < 0) {
        return result;
    }
    match = strstr(config, tls_fixer_config_block);
    if (match == NULL) {
        free(config);
        return 0;
    }

    before_size = (SceSize)(match - config);
    after_offset = before_size + (SceSize)(sizeof(tls_fixer_config_block) - 1);
    (void)remove_if_exists(temporary_path);
    (void)remove_if_exists(rollback_path);
    descriptor = sceIoOpen(
        temporary_path,
        SCE_O_WRONLY | SCE_O_TRUNC | SCE_O_CREAT,
        0777);
    if (descriptor < 0) {
        free(config);
        return descriptor;
    }

    result = write_all(descriptor, config, before_size);
    if (result >= 0) {
        result = write_all(
            descriptor,
            config + after_offset,
            config_size - after_offset);
    }
    if (sceIoClose(descriptor) < 0 && result >= 0) {
        result = -1;
    }
    free(config);
    if (result < 0) {
        (void)remove_if_exists(temporary_path);
        return result;
    }

    result = sceIoRename(config_path, rollback_path);
    if (result < 0) {
        (void)remove_if_exists(temporary_path);
        return result;
    }
    result = sceIoRename(temporary_path, config_path);
    if (result < 0) {
        (void)sceIoRename(rollback_path, config_path);
        (void)remove_if_exists(temporary_path);
        return result;
    }
    return remove_if_exists(rollback_path);
}

#endif

static void show_menu(void) {
    int index;

    psvDebugScreenClear(COLOR_BLACK);
    psvDebugScreenSetFgColor(COLOR_CYAN);
    printf("                       tls_fixer " TLS_FIXER_VERSION "\n");
    printf("                       By devnoname120\n");
    printf("        Thanks to SKGleba for the initial iTLS plugin!\n\n");
    if (packaged_system_backend() == TLS_FIXER_SYSTEM_AUGMENTED)
        printf("Experimental System plugin test: enabled for one boot.\n");
    psvDebugScreenSetFgColor(COLOR_WHITE);
    printf("Modern, secure Mbed TLS (2026) brings TLS 1.3 to PS Vita.\n");
    printf("Replaces legacy RSA BSAFE Micro Edition Suite 3.2.1 (2014)\n");
    printf("TLS transport in supported system HTTPS, plus browser TLS.\n\n");
    printf("iTLS and vitals are incompatible with tls_fixer.\n");
    printf("Installing any option automatically removes both plugins.\n\n");
    psvDebugScreenSetFgColor(COLOR_RED);
    for (index = 0; index < MENU_COUNT; ++index) {
        if (selected_option == index) {
            psvDebugScreenSetFgColor(COLOR_GREEN);
        }
        unsigned option = menu_options[index];
        printf("%s\n", installed[option] == 0 ? install_menu[option] : uninstall_menu[option]);
        psvDebugScreenSetFgColor(COLOR_RED);
    }
    psvDebugScreenSetFgColor(COLOR_GREEN);
    printf("\nCROSS: install/uninstall  SQUARE: refresh selected option\n");
}

static int install_plugin(int requested_state) {
    int result;
    int had_previous = path_exists(INSTALLER_KERNEL_PATH);
    int removing = requested_state == 1;

    if (removing) {
        printf("Removing the tls_fixer plugin... \n");
#if TLS_FIXER_INSTALL_AUGMENTED_HTTP
        result = disarm_installer_entries();
#else
        result = uninstall_plugin_config();
#endif
        if (result < 0) {
            return result;
        }
        result = remove_if_exists(INSTALLER_KERNEL_PATH);
        if (result >= 0 && TLS_FIXER_INSTALL_AUGMENTED_HTTP)
            result = sceIoSync(TLS_FIXER_SYSTEM_TRIAL ? "ux0:" : "ur0:", 0);
        return result;
    }

    printf("Installing the tls_fixer plugin... \n");
    result = replace_file("app0:tls_fixer.skprx", INSTALLER_KERNEL_PATH);
    if (result < 0) {
        return result;
    }
#if TLS_FIXER_INSTALL_AUGMENTED_HTTP
    result = sceIoSync("ux0:", 0);
    if (result >= 0 && TLS_FIXER_AUGMENTED_RELEASE) result = sceIoSync("vs0:", 0);
    if (result >= 0 && TLS_FIXER_AUGMENTED_RELEASE) result = sceIoSync("ur0:", 0);
    if (result >= 0) result = enable_installer_entry();
#else
    (void)remove_if_exists("ux0:tai/config_pretls_fixer.txt");
    result = install_plugin_config();
#endif
    if (result < 0 && !had_previous) {
        (void)remove_if_exists(INSTALLER_KERNEL_PATH);
    }
    return result;
}

static int install_compat(int requested_state) {
    int result = remove_if_exists("vs0:/data/external/webcore/ScePsp2Compat.supr0");
    int removing = requested_state == 1;

    if (result < 0) return result;
    if (removing) {
        printf("Removing browser compatibility and TLS 1.3 modules... \n");
        result = remove_if_exists(browser_provider_global);
        if (result >= 0) result = remove_if_exists(new_modules[6]);
        if (result >= 0) result = remove_if_exists(new_modules[0]);
        return result;
    }

    printf("Installing browser compatibility and TLS 1.3 modules... \n");
    if (!path_exists("ur0:tai/tls_fixer-native")) {
        result = sceIoMkdir("ur0:tai/tls_fixer-native", 0777);
        if (result < 0) return result;
    }
    if (!path_exists("vs0:/data/external/tls_fixer/native")) {
        result = sceIoMkdir("vs0:/data/external/tls_fixer/native", 0777);
        if (result < 0) return result;
    }
    result = replace_file("app0:tls_fixer.suprx", browser_provider_global);
    if (result >= 0) result = replace_file("app0:tls_fixer.suprx", new_modules[6]);
    if (result >= 0) result = replace_file("app0:compat.suprx", new_modules[0]);
    return result;
}

static int install_psn_redirect(int requested_state) {
    int result;
    const char *psn = packaged_system_backend() == TLS_FIXER_SYSTEM_AUGMENTED ? TLS_FIXER_AUGMENTED_PSN_MODULE_PATH : new_modules[7];
    const char *store = packaged_system_backend() == TLS_FIXER_SYSTEM_AUGMENTED ? TLS_FIXER_AUGMENTED_STORE_MODULE_PATH : new_modules[8];
    if (requested_state == 1) {
        result = remove_if_exists(psn);
        if (result >= 0) result = remove_if_exists(store);
    } else {
        printf("Installing the PSN sign-in redirect... \n");
        result = replace_file("app0:tls_fixer_psn.suprx", psn);
        if (result >= 0) result = replace_file("app0:tls_fixer_store.suprx", store);
        if (packaged_system_backend() == TLS_FIXER_SYSTEM_AUGMENTED) return result;
        if (result >= 0 && !path_exists("ux0:data/tls_fixer"))
            result = sceIoMkdir("ux0:data/tls_fixer", 0777);
        /* An upgrade or reinstall must preserve the user's host mappings. */
        if (result >= 0 && !path_exists("ux0:data/tls_fixer/redirects.txt"))
            result = replace_file("app0:redirects.txt", "ux0:data/tls_fixer/redirects.txt");
    }
    if (packaged_system_backend() == TLS_FIXER_SYSTEM_AUGMENTED) return result;
    /* Superseded Shell helper and prepatched Store library from older packages. */
    if (result >= 0) result = remove_if_exists(new_modules[3]);
    if (result >= 0) result = remove_if_exists(new_modules[4]);
    return result;
}

static int install_http_modules(int requested_state) {
    SceKernelFwInfo firmware;
    int result;
    int removing = requested_state == 1;

    result = packaged_system_backend() == TLS_FIXER_SYSTEM_AUGMENTED ? 0 : remove_if_exists("vs0:sys/external/libhttp.supr0");
    if (result < 0) {
        return result;
    }
    memset(&firmware, 0, sizeof(firmware));
    firmware.size = sizeof(firmware);
    result = _vshSblGetSystemSwVersion(&firmware);
    if (result < 0) {
        return result;
    }
    if (removing) {
        printf("Removing the tls_fixer HTTP, SSL, and TLS 1.3 modules... \n");
        result = tls_fixer_update_system_payloads(packaged_system_backend(), 1, &system_files);
    } else {
        printf("Installing the tls_fixer HTTP, SSL, and TLS 1.3 modules... \n");
        if (packaged_system_backend() != TLS_FIXER_SYSTEM_AUGMENTED && !path_exists("vs0:/data/external/tls_fixer/native")) {
            result = sceIoMkdir("vs0:/data/external/tls_fixer/native", 0777);
            if (result < 0) return result;
        }
        result = tls_fixer_update_system_payloads(packaged_system_backend(), 0, &system_files);
    }

    if (result >= 0) result = install_psn_redirect(requested_state);
    return result;
}

static int install_certificates(int requested_state) {
    static const char certificate_path[] = "vs0:/data/external/cert/CA_LIST.cer";
    static const char backup_path[] = "vs0:/data/external/cert/CA_LIST.cer_old";
    static const char temporary_path[] = "vs0:/data/external/cert/CA_LIST.cer.prepared";
    static const char rollback_path[] = "vs0:/data/external/cert/CA_LIST.cer.tls_fixer-remove";
    int result;
    int removing = requested_state == 1;

    if (removing) {
        int had_current;

        printf("Removing tls_fixer CA certs... \n");
        if (!path_exists(backup_path)) {
            printf("No CA backup; leaving the current certificate file unchanged.\n");
            return 0;
        }
        result = remove_if_exists(rollback_path);
        if (result < 0) {
            return result;
        }
        had_current = path_exists(certificate_path);
        if (had_current) {
            result = sceIoRename(certificate_path, rollback_path);
            if (result < 0) {
                return result;
            }
        }
        result = sceIoRename(backup_path, certificate_path);
        if (result < 0) {
            if (had_current) {
                (void)sceIoRename(rollback_path, certificate_path);
            }
            return result;
        }
        return had_current ? remove_if_exists(rollback_path) : 0;
    }

    TlsFixerCertificateBundle bundle;
    TlsFixerInstallerNetwork network;
    printf("Fetching latest curl/Mozilla certificates...\n");
    int online = tls_fixer_installer_network_start(&network) == 0;
    result = tls_fixer_prepare_certificates("app0:sony-certs.pem", "app0:mozilla-certs.pem",
        online ? TLS_FIXER_CA_UPDATE_URL : NULL, 30, &bundle);
    tls_fixer_installer_network_stop(&network);
    if (result < 0) {
        printf("Certificate preparation failed: %s\n", bundle.failure_stage != NULL ? bundle.failure_stage : "invalid input");
        printf("errno=%d crypto=0x%08lX\n", bundle.failure_errno, bundle.failure_crypto_error);
        return result;
    }
    printf(bundle.downloaded ? "Using downloaded Mozilla certificates.\n" :
        "Download unavailable; using embedded Mozilla certificates.\n");
    printf("Sony: %u, Mozilla: %u, combined: %u certificates.\n",
        (unsigned int)bundle.sony_count, (unsigned int)bundle.mozilla_count,
        (unsigned int)bundle.combined_count);
    (void)remove_if_exists(temporary_path);
    SceUID descriptor = sceIoOpen(temporary_path, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0777);
    result = descriptor < 0 ? descriptor : write_all(descriptor, bundle.data, (SceSize)bundle.size);
    if (descriptor >= 0) {
        int close_result = sceIoClose(descriptor);
        if (result >= 0 && close_result < 0) result = close_result;
    }
    tls_fixer_free_certificates(&bundle);
    if (result >= 0) result = sceIoSync("vs0:", 0);
    if (result < 0) { (void)remove_if_exists(temporary_path); return result; }
    if (path_exists(backup_path)) {
        result = replace_file(temporary_path, certificate_path);
        (void)remove_if_exists(temporary_path);
        return result;
    }
    result = remove_if_exists(backup_path);
    if (result >= 0) {
        result = sceIoRename(certificate_path, backup_path);
    }
    if (result >= 0) {
        result = sceIoRename(temporary_path, certificate_path);
    }
    if (result < 0) {
        if (!path_exists(certificate_path) && path_exists(backup_path)) {
            (void)sceIoRename(backup_path, certificate_path);
        }
        (void)remove_if_exists(temporary_path);
    }
    return result;
}

static int browser_payload_present(void) {
    return path_exists(new_modules[0]) || path_exists(new_modules[6]) ||
        path_exists(browser_provider_global);
}
static int system_payload_present(void) {
    return tls_fixer_system_payloads_present(packaged_system_backend(), &system_files);
}
static int apply_component(void *context, unsigned component, int removing) {
    (void)context;
    if (component == TLS_FIXER_COMPONENT_CONFLICTS) {
        /* Diagnostic packages must not modify an existing installation. */
        if (packaged_system_backend() == TLS_FIXER_SYSTEM_AUGMENTED) return 0;
        printf("Removing incompatible iTLS and vitals plugins...\n");
        return conflicting_plugins(1);
    }
    if (packaged_system_backend() == TLS_FIXER_SYSTEM_AUGMENTED &&
        component != TLS_FIXER_COMPONENT_SYSTEM && component != TLS_FIXER_COMPONENT_COORDINATOR) return -1;
    switch (component) {
    case TLS_FIXER_COMPONENT_COORDINATOR: return install_plugin(removing);
    case TLS_FIXER_COMPONENT_BROWSER: return install_compat(removing);
    case TLS_FIXER_COMPONENT_SYSTEM: return install_http_modules(removing);
    case TLS_FIXER_COMPONENT_CERTIFICATES: return install_certificates(removing);
    default: return -1;
    }
}

static int perform_selected_operation(int refresh_selected) {
    uint8_t mount_data[0x100] = {0};
    int result;

    enum TlsFixerOption option = menu_options[selected_option];
    int removing = !refresh_selected && installed[option];
    if (option == TLS_FIXER_OPTION_EXIT) {
        sceKernelExitProcess(0);
        return 0;
    }

    if (packaged_system_backend() == TLS_FIXER_SYSTEM_AUGMENTED) {
#if TLS_FIXER_INSTALL_AUGMENTED_HTTP
        int active = test_payloads_active();
        if (active != 0) {
            printf(active > 0 ? "Restart your Vita before changing this test installation.\n" :
                "Could not verify that the test is inactive.\n");
            result = -1; goto failed;
        }
        result = disarm_installer_entries();
        if (result < 0) goto failed;
#endif
        const char *const directories[] = {TLS_FIXER_AUGMENTED_RUNTIME, "ux0:/data/tls_fixer-one-shot"};
        for (unsigned i = 0; i < sizeof(directories) / sizeof(directories[0]); ++i) {
            if (!path_exists(directories[i])) {
                result = sceIoMkdir(directories[i], 0777); if (result < 0) goto failed;
            }
        }
    } else {
    (void)vshIoUmount(0x300, 0, 0, 0);
    (void)vshIoUmount(0x300, 1, 0, 0);
    result = _vshIoMount(0x300, 0, 2, mount_data);
    if (result < 0) {
        goto failed;
    }
    if (!path_exists("vs0:/data/external/tls_fixer")) {
        result = sceIoMkdir("vs0:/data/external/tls_fixer", 0777);
        if (result < 0) {
            goto failed;
        }
    }
    }

    TlsFixerInstallPlan plan;
    result = tls_fixer_plan_option(option, removing,
        packaged_system_backend() == TLS_FIXER_SYSTEM_AUGMENTED ? 0 : browser_payload_present(), system_payload_present(), &plan);
#if TLS_FIXER_AUGMENTED_RELEASE
    /* Disable the old entry before replacing any files needed by the new
     * coordinator. Activation is the last successful installation step. */
    if (result >= 0 && (plan.components & TLS_FIXER_COMPONENT_COORDINATOR))
        result = disarm_installer_entries();
#endif
    if (result >= 0) {
        printf("Working...\n");
        result = tls_fixer_execute_plan(&plan, apply_component, NULL);
    }

    if (result < 0) {
        goto failed;
    }
    if (packaged_system_backend() == TLS_FIXER_SYSTEM_AUGMENTED) {
        printf("Done. Restart your Vita to apply this one-boot test.\n");
        sceKernelDelayThread(3 * 1000 * 1000); sceKernelExitProcess(0); return 0;
    }
    printf("Done, rebooting in 3 seconds\n");
    sceKernelDelayThread(3 * 1000 * 1000);
    scePowerRequestColdReset();
    sceKernelExitProcess(0);
    return 0;

failed:
    psvDebugScreenSetFgColor(COLOR_RED);
    printf("Operation failed: 0x%08X\n", (unsigned int)result);
    printf("No reboot was requested.\n");
    sceKernelDelayThread(5 * 1000 * 1000);
    return result;
}

static void refresh_installed_state(uint32_t firmware_version) {
    (void)firmware_version;
    memset(installed, 0, sizeof(installed));
    if (!path_exists("vs0:sys/external/libhttp.supr0") &&
        !path_exists("vs0:/data/external/webcore/ScePsp2Compat.supr0")) {
        int coordinator = path_exists(INSTALLER_KERNEL_PATH) &&
#if TLS_FIXER_INSTALL_AUGMENTED_HTTP
            (TLS_FIXER_SYSTEM_TRIAL || installer_entry_enabled());
#else
            plugin_configured();
#endif
        installed[TLS_FIXER_OPTION_BROWSER] = (uint8_t)(coordinator &&
            path_exists(new_modules[0]) && path_exists(new_modules[6]) &&
            path_exists(browser_provider_global));
        installed[TLS_FIXER_OPTION_SYSTEM] = (uint8_t)(coordinator &&
            tls_fixer_system_payloads_complete(packaged_system_backend(), &system_files));
        installed[TLS_FIXER_OPTION_CERTIFICATES] = (uint8_t)path_exists("vs0:/data/external/cert/CA_LIST.cer_old");
        installed[TLS_FIXER_OPTION_FULL] = installed[TLS_FIXER_OPTION_BROWSER] &&
            installed[TLS_FIXER_OPTION_SYSTEM] && installed[TLS_FIXER_OPTION_CERTIFICATES];
    }
    /* The certificate backup is shared with the older installers. It must
     * not make Cross uninstall certificates when the user is migrating. */
    if (packaged_system_backend() != TLS_FIXER_SYSTEM_AUGMENTED && conflicting_plugins(0) > 0)
        memset(installed, 0, sizeof(installed));
}

int main(void) {
    SceCtrlData pad;
    SceKernelFwInfo firmware;
    uint32_t firmware_version = 0;

    psvDebugScreenInit();
    psvDebugScreenClear(COLOR_BLACK);
    psvDebugScreenSetFgColor(COLOR_GREEN);

    memset(&firmware, 0, sizeof(firmware));
    firmware.size = sizeof(firmware);
    if (_vshSblGetSystemSwVersion(&firmware) >= 0) {
        firmware_version = firmware.version;
    }

    refresh_installed_state(firmware_version);

    show_menu();
    for (;;) {
        sceCtrlPeekBufferPositive(0, &pad, 1);
        if (pad.buttons == SCE_CTRL_CROSS) {
            (void)perform_selected_operation(0);
            refresh_installed_state(firmware_version);
            show_menu();
            sceKernelDelayThread(350 * 1000);
        } else if (pad.buttons == SCE_CTRL_SQUARE) {
            (void)perform_selected_operation(1);
            refresh_installed_state(firmware_version);
            show_menu();
            sceKernelDelayThread(350 * 1000);
        } else if (pad.buttons == SCE_CTRL_UP) {
            if (selected_option != 0) {
                --selected_option;
            }
            show_menu();
            sceKernelDelayThread(300 * 1000);
        } else if (pad.buttons == SCE_CTRL_DOWN) {
            if (selected_option + 1 < MENU_COUNT) {
                ++selected_option;
            }
            show_menu();
            sceKernelDelayThread(300 * 1000);
        }
    }
}
