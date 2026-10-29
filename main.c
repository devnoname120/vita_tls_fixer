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
#include "installer/certificates.h"
#include "installer/network_vita.h"
#include "installer/options.h"

#define printf psvDebugScreenPrintf

#define MENU_COUNT TLS_FIXER_OPTION_COUNT
#define COPY_BUFFER_SIZE 0x4000
#define CONFIG_MAX_SIZE 0x100000

unsigned int _newlib_heap_size_user = 8u * 1024u * 1024u;

static const char tls_fixer_config_block[] =
    "# TLS_FIXER\n*KERNEL\nur0:tai/tls_fixer.skprx\n\n";
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

static const char *const install_menu[MENU_COUNT] = {
    " -> Install Full (browser plugin + system plugin + certs)",
    " -> Install browser plugin only",
    " -> Install system plugin only",
    " -> Install certs only",
    " -> Exit",
};

static const char *const uninstall_menu[MENU_COUNT] = {
    " -> Uninstall Full (browser plugin + system plugin + certs)",
    " -> Uninstall browser plugin only",
    " -> Uninstall system plugin only",
    " -> Uninstall certs only",
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
    printf("                       tls_fixer " TLS_FIXER_VERSION "\n");
    printf("                       By devnoname120\n");
    printf("        Thanks to SKGleba for the initial iTLS plugin!\n\n");
    psvDebugScreenSetFgColor(COLOR_WHITE);
    printf("Modern, secure Mbed TLS (2026) brings TLS 1.3 to PS Vita.\n");
    printf("Replaces legacy RSA BSAFE Micro Edition Suite 3.2.1 (2014)\n");
    printf("TLS transport in supported system HTTPS, plus browser TLS.\n\n");
    psvDebugScreenSetFgColor(COLOR_RED);
    for (index = 0; index < MENU_COUNT; ++index) {
        if (selected_option == index) {
            psvDebugScreenSetFgColor(COLOR_GREEN);
        }
        printf("%s\n", installed[index] == 0 ? install_menu[index] : uninstall_menu[index]);
        psvDebugScreenSetFgColor(COLOR_RED);
    }
    psvDebugScreenSetFgColor(COLOR_GREEN);
    printf("\nCROSS: install/uninstall  SQUARE: refresh selected option\n");
}

static int install_plugin(int requested_state) {
    int result;
    int had_previous = path_exists("ur0:tai/tls_fixer.skprx");
    int removing = requested_state == 1;

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
    if (requested_state == 1) {
        result = remove_if_exists(new_modules[7]);
        if (result >= 0) result = remove_if_exists(new_modules[8]);
    } else {
        printf("Installing the PSN sign-in redirect... \n");
        result = replace_file("app0:tls_fixer_psn.suprx", new_modules[7]);
        if (result >= 0) result = replace_file("app0:tls_fixer_store.suprx", new_modules[8]);
        if (result >= 0 && !path_exists("ux0:data/tls_fixer"))
            result = sceIoMkdir("ux0:data/tls_fixer", 0777);
        /* An upgrade or reinstall must preserve the user's host mappings. */
        if (result >= 0 && !path_exists("ux0:data/tls_fixer/redirects.txt"))
            result = replace_file("app0:redirects.txt", "ux0:data/tls_fixer/redirects.txt");
    }
    /* Superseded Shell helper and prepatched Store library from older packages. */
    if (result >= 0) result = remove_if_exists(new_modules[3]);
    if (result >= 0) result = remove_if_exists(new_modules[4]);
    return result;
}

static int install_http_modules(int requested_state) {
    SceKernelFwInfo firmware;
    int result;
    int removing = requested_state == 1;

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
        if (!path_exists("vs0:/data/external/tls_fixer/native")) {
            result = sceIoMkdir("vs0:/data/external/tls_fixer/native", 0777);
            if (result < 0) return result;
        }
        result = replace_file("app0:tls_fixer_http.suprx", new_modules[5]);
        if (result >= 0) {
            result = replace_file("app0:lhttp.suprx", new_modules[1]);
        }
        if (result >= 0) {
            result = replace_file("app0:lssl.suprx", new_modules[2]);
        }
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
    if (path_exists(new_modules[7]) || path_exists(new_modules[8])) return 1;
    for (unsigned i = 1; i <= 5; ++i)
        if (path_exists(new_modules[i])) return 1;
    return 0;
}
static int apply_component(void *context, unsigned component, int removing) {
    (void)context;
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

    if (selected_option == TLS_FIXER_OPTION_EXIT) {
        sceKernelExitProcess(0);
        return 0;
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

    TlsFixerInstallPlan plan;
    int removing = !refresh_selected && installed[selected_option];
    result = tls_fixer_plan_option((enum TlsFixerOption)selected_option, removing,
        browser_payload_present(), system_payload_present(), &plan);
    if (result >= 0) {
        printf("Working...\n");
        result = tls_fixer_execute_plan(&plan, apply_component, NULL);
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

static void refresh_installed_state(uint32_t firmware_version) {
    memset(installed, 0, sizeof(installed));
    if (!path_exists("vs0:sys/external/libhttp.supr0") &&
        !path_exists("vs0:/data/external/webcore/ScePsp2Compat.supr0")) {
        int coordinator = path_exists("ur0:tai/tls_fixer.skprx") && plugin_configured();
        installed[TLS_FIXER_OPTION_BROWSER] = (uint8_t)(coordinator &&
            path_exists(new_modules[0]) && path_exists(new_modules[6]) &&
            path_exists(browser_provider_global));
        installed[TLS_FIXER_OPTION_SYSTEM] = (uint8_t)(coordinator &&
            path_exists(new_modules[1]) &&
            path_exists(new_modules[2]) &&
            path_exists(new_modules[5]) &&
            ((firmware_version & UINT32_C(0xffff0000)) != UINT32_C(0x03600000) ||
             (path_exists(new_modules[3]) && path_exists(new_modules[4]))));
        installed[TLS_FIXER_OPTION_CERTIFICATES] = (uint8_t)path_exists("vs0:/data/external/cert/CA_LIST.cer_old");
        installed[TLS_FIXER_OPTION_FULL] = installed[TLS_FIXER_OPTION_BROWSER] &&
            installed[TLS_FIXER_OPTION_SYSTEM] && installed[TLS_FIXER_OPTION_CERTIFICATES];
    }
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
