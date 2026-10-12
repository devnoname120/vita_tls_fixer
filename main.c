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
#include <psp2/kernel/processmgr.h>
#include <psp2/power.h>
#include <psp2/vshbridge.h>

#include "graphics.h"

#define printf psvDebugScreenPrintf

#define MENU_COUNT 6
#define COPY_BUFFER_SIZE 0x4000
#define CONFIG_MAX_SIZE 0x100000

static const char tls_fixer_config_block[] =
    "# TLS_FIXER\n*KERNEL\nur0:tai/tls_fixer.skprx\n\n";

static const char *const new_modules[] = {
    "vs0:/data/external/tls_fixer/ScePsp2Compat.suprx",
    "vs0:/data/external/tls_fixer/libhttp.suprx",
    "vs0:/data/external/tls_fixer/libssl.suprx",
    "vs0:/data/external/tls_fixer/old_dns_fix.suprx",
    "vs0:/data/external/tls_fixer/np_commerce2.suprx",
    "vs0:/data/external/tls_fixer/tls_fixer_http.suprx",
    "vs0:/data/external/tls_fixer/tls_fixer.suprx",
};

static const char *const install_menu[MENU_COUNT] = {
    " -> Install the full tls_fixer package",
    " -> Install the tls_fixer plugin",
    " -> Install browser compatibility and TLS 1.3 modules",
    " -> Install the tls_fixer HTTP, SSL, and TLS 1.3 modules",
    " -> Install the tls_fixer CA certs",
    " -> Exit",
};

static const char *const uninstall_menu[MENU_COUNT] = {
    " -> Uninstall the full tls_fixer package",
    " -> Uninstall the tls_fixer plugin",
    " -> Uninstall browser compatibility and TLS 1.3 modules",
    " -> Uninstall the tls_fixer HTTP, SSL, and TLS 1.3 modules",
    " -> Uninstall the tls_fixer CA certs",
    " -> Exit",
};

static int selected_option;
static uint8_t installed[MENU_COUNT];

static int path_exists(const char *path) {
    SceIoStat status;

    return path != NULL && sceIoGetstat(path, &status) >= 0;
}

static int remove_if_exists(const char *path) {
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

static int replace_file(const char *source, const char *destination) {
    char temporary[256];
    char previous[256];
    int temporary_length;
    int previous_length;
    int had_previous;
    int result;

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

    if (had_previous) {
        result = remove_if_exists(previous);
    }
    return result;
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

static void show_menu(void) {
    int index;

    psvDebugScreenClear(COLOR_BLACK);
    psvDebugScreenSetFgColor(COLOR_CYAN);
    printf("                       tls_fixer 3.3.0                           \n");
    printf("                         By SKGleba                              \n");
    psvDebugScreenSetFgColor(COLOR_RED);
    for (index = 0; index < MENU_COUNT; ++index) {
        if (selected_option == index) {
            psvDebugScreenSetFgColor(COLOR_GREEN);
        }
        printf("%s\n", installed[index] == 0 ? install_menu[index] : uninstall_menu[index]);
        psvDebugScreenSetFgColor(COLOR_RED);
    }
    psvDebugScreenSetFgColor(COLOR_GREEN);
    printf("SQUARE: refresh the full package; keep original CA backup\n");
}

static int install_plugin(int requested_state) {
    int result;
    int had_previous = path_exists("ur0:tai/tls_fixer.skprx");
    int removing = requested_state == 69 ? installed[1] : requested_state == 1;

    if (removing) {
        printf("Removing the tls_fixer plugin... \n");
        result = uninstall_plugin_config();
        if (result < 0) {
            return result;
        }
        return remove_if_exists("ur0:tai/tls_fixer.skprx");
    }

    printf("Installing the tls_fixer plugin... \n");
    result = replace_file("app0:tls_fixer.skprx", "ur0:tai/tls_fixer.skprx");
    if (result < 0) {
        return result;
    }
    (void)remove_if_exists("ux0:tai/config_pretls_fixer.txt");
    result = install_plugin_config();
    if (result < 0 && !had_previous) {
        (void)remove_if_exists("ur0:tai/tls_fixer.skprx");
    }
    return result;
}

static int install_compat(int requested_state) {
    int result = remove_if_exists("vs0:/data/external/webcore/ScePsp2Compat.supr0");
    int removing = requested_state == 69 ? installed[2] : requested_state == 1;

    if (result < 0) return result;
    if (removing) {
        printf("Removing browser compatibility and TLS 1.3 modules... \n");
        result = remove_if_exists(new_modules[6]);
        if (result >= 0) result = remove_if_exists(new_modules[0]);
        return result;
    }

    printf("Installing browser compatibility and TLS 1.3 modules... \n");
    result = replace_file("app0:tls_fixer.suprx", new_modules[6]);
    if (result >= 0) result = replace_file("app0:compat.suprx", new_modules[0]);
    return result;
}

static int install_dns_fix(int requested_state) {
    int result;
    int removing = requested_state == 69 ? installed[3] : requested_state == 1;

    if (removing) {
        printf("Removing the 3.60 DNS fix... \n");
        result = remove_if_exists(new_modules[3]);
        if (result >= 0) {
            result = remove_if_exists(new_modules[4]);
        }
        return result;
    }

    printf("Installing the 3.60 DNS fix... \n");
    result = replace_file("app0:dnsfix.suprx", new_modules[3]);
    if (result >= 0) {
        result = replace_file("app0:comm2.suprx", new_modules[4]);
    }
    return result;
}

static int install_http_modules(int requested_state) {
    SceKernelFwInfo firmware;
    int result;
    int removing = requested_state == 69 ? installed[3] : requested_state == 1;

    result = remove_if_exists("vs0:sys/external/libhttp.supr0");
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
        result = remove_if_exists(new_modules[5]);
        if (result >= 0) {
            result = remove_if_exists(new_modules[1]);
        }
        if (result >= 0) {
            result = remove_if_exists(new_modules[2]);
        }
    } else {
        printf("Installing the tls_fixer HTTP, SSL, and TLS 1.3 modules... \n");
        result = replace_file("app0:tls_fixer_http.suprx", new_modules[5]);
        if (result >= 0) {
            result = replace_file("app0:lhttp.suprx", new_modules[1]);
        }
        if (result >= 0) {
            result = replace_file("app0:lssl.suprx", new_modules[2]);
        }
    }

    if (result >= 0 && firmware.version == UINT32_C(0x03600000)) {
        result = install_dns_fix(requested_state);
    }
    return result;
}

static int install_certificates(int requested_state) {
    static const char certificate_path[] = "vs0:/data/external/cert/CA_LIST.cer";
    static const char backup_path[] = "vs0:/data/external/cert/CA_LIST.cer_old";
    static const char temporary_path[] = "vs0:/data/external/cert/CA_LIST.cer.tmp";
    static const char rollback_path[] = "vs0:/data/external/cert/CA_LIST.cer.tls_fixer-remove";
    int result;
    int removing = requested_state == 69 ? installed[4] : requested_state == 1;

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

    printf("Adding tls_fixer CA certs... \n");
    if (path_exists(backup_path)) {
        return replace_file("app0:certs.cer", certificate_path);
    }
    (void)remove_if_exists(temporary_path);
    result = copy_file("app0:certs.cer", temporary_path);
    if (result < 0) {
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

static int perform_selected_operation(int refresh_all) {
    uint8_t mount_data[0x100] = {0};
    int result;

    if (selected_option == 5) {
        sceKernelExitProcess(0);
    }

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

    printf("Working...\n");
    switch (selected_option) {
        case 0:
            if (refresh_all || installed[0] == 0) {
                printf("Installing tls_fixer... \n");
                result = install_plugin(0);
                if (result >= 0) {
                    result = install_compat(0);
                }
                if (result >= 0) {
                    result = install_http_modules(0);
                }
                if (result >= 0) {
                    result = install_certificates(0);
                }
            } else {
                printf("Uninstalling tls_fixer... \n");
                result = install_plugin(1);
                if (result >= 0) {
                    result = install_compat(1);
                }
                if (result >= 0) {
                    result = install_http_modules(1);
                }
                if (result >= 0) {
                    result = install_certificates(1);
                }
            }
            break;
        case 1:
            result = install_plugin(69);
            break;
        case 2:
            result = install_compat(69);
            break;
        case 3:
            result = install_http_modules(69);
            break;
        case 4:
            result = install_certificates(69);
            break;
        default:
            result = -1;
            break;
    }

    if (result < 0) {
        goto failed;
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

    if (!path_exists("vs0:sys/external/libhttp.supr0") &&
        !path_exists("vs0:/data/external/webcore/ScePsp2Compat.supr0")) {
        installed[1] = (uint8_t)(
            path_exists("ur0:tai/tls_fixer.skprx") && plugin_configured());
        installed[2] = (uint8_t)(path_exists(new_modules[0]) && path_exists(new_modules[6]));
        installed[3] = (uint8_t)(
            path_exists(new_modules[1]) &&
            path_exists(new_modules[2]) &&
            path_exists(new_modules[5]) &&
            (firmware_version != UINT32_C(0x03600000) ||
             (path_exists(new_modules[3]) && path_exists(new_modules[4]))));
        installed[4] = (uint8_t)path_exists("vs0:/data/external/cert/CA_LIST.cer_old");
        installed[0] = installed[1] & installed[2] & installed[3] & installed[4];
    }

    show_menu();
    for (;;) {
        sceCtrlPeekBufferPositive(0, &pad, 1);
        if (pad.buttons == SCE_CTRL_CROSS) {
            (void)perform_selected_operation(0);
            selected_option = 0;
            show_menu();
            sceKernelDelayThread(350 * 1000);
        } else if (pad.buttons == SCE_CTRL_SQUARE) {
            selected_option = 0;
            (void)perform_selected_operation(1);
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
