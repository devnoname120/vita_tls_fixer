#include "provider.h"
#include "cert_hooks.h"
#include "diagnostics.h"
#include "transport.h"

#include <psp2/kernel/modulemgr.h>
#include <psp2common/kernel/modulemgr.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

static const uint8_t g_create_bytes[] = {
    0x2D, 0xE9, 0xF0, 0x41, 0x88, 0xB0, 0x49, 0xF6, 0x00,
    0x18, 0xC8, 0xF2, 0x01, 0x18, 0xD8, 0xF8, 0x00, 0x20,
};
static const uint8_t g_connect_bytes[] = {
    0x70, 0xB5, 0x04, 0x1C, 0x06, 0xF0, 0x77, 0xFE,
};
static const uint8_t g_map_io_bytes[] = {
    0x70, 0xB5, 0x04, 0x1C, 0x20, 0x6C,
};
static const uint8_t g_read_bytes[] = {
    0x2D, 0xE9, 0xF0, 0x41, 0x14, 0x1C, 0x0D, 0x1C, 0x06, 0x1C, 0x10,
    0xF0, 0x84, 0xE9, 0x07, 0x1C, 0x00, 0x2F, 0x1E, 0xDB, 0x40, 0xF2,
    0xDC, 0x50, 0x22, 0x1C, 0x82, 0x42, 0x01, 0xD9, 0x40, 0xF2, 0xDC,
    0x52, 0x30, 0x6C, 0x29, 0x1C, 0x10, 0xF0, 0x86, 0xE9,
};
static const uint8_t g_write_bytes[] = {
    0x2D, 0xE9, 0xF0, 0x41, 0x14, 0x1C, 0x0D, 0x1C, 0x06, 0x1C, 0x10,
    0xF0, 0x58, 0xE9, 0x07, 0x1C, 0x00, 0x2F, 0x1E, 0xDB, 0x40, 0xF2,
    0xDC, 0x50, 0x22, 0x1C, 0x82, 0x42, 0x01, 0xD9, 0x40, 0xF2, 0xDC,
    0x52, 0x30, 0x6C, 0x29, 0x1C, 0x10, 0xF0, 0x7A, 0xEA,
};
static const uint8_t g_shutdown_bytes[] = {
    0x10, 0xB5, 0x04, 0x1C, 0x10, 0xF0, 0x2E, 0xE9,
};

static const TlsFixerMaskedSignature g_libhttp_signatures[] = {
    {
        .name = "create",
        .offset = TLS_FIXER_HOOK_CREATE_OFFSET,
        .bytes = g_create_bytes,
        .mask = "???xxx???????x???x",
        .length = sizeof(g_create_bytes),
    },
    {
        .name = "connect",
        .offset = TLS_FIXER_HOOK_CONNECT_OFFSET,
        .bytes = g_connect_bytes,
        .mask = "xxxx???x",
        .length = sizeof(g_connect_bytes),
    },
    {
        .name = "map_io",
        .offset = TLS_FIXER_HOOK_MAP_IO_OFFSET,
        .bytes = g_map_io_bytes,
        .mask = "xxxxxx",
        .length = sizeof(g_map_io_bytes),
    },
    {
        .name = "read",
        .offset = TLS_FIXER_HOOK_READ_OFFSET,
        .bytes = g_read_bytes,
        .mask = "???xxxxxxx???xxxxxxx???xxxxxxx???xxxxx???x",
        .length = sizeof(g_read_bytes),
    },
    {
        .name = "write",
        .offset = TLS_FIXER_HOOK_WRITE_OFFSET,
        .bytes = g_write_bytes,
        .mask = "???xxxxxxx???xxxxxxx???xxxxxxx???xxxxx???x",
        .length = sizeof(g_write_bytes),
    },
    {
        .name = "shutdown",
        .offset = TLS_FIXER_HOOK_SHUTDOWN_OFFSET,
        .bytes = g_shutdown_bytes,
        .mask = "xxxx???x",
        .length = sizeof(g_shutdown_bytes),
    },
};

static const TlsFixerModuleDescriptor g_libhttp_descriptor = {
    .text_size = TLS_FIXER_LIBHTTP_TEXT_SIZE,
    .signatures = g_libhttp_signatures,
    .signature_count = sizeof(g_libhttp_signatures) / sizeof(g_libhttp_signatures[0]),
};

enum {
    HOOK_CREATE = 0,
    HOOK_CONNECT,
    HOOK_MAP_IO,
    HOOK_READ,
    HOOK_WRITE,
    HOOK_SHUTDOWN,
};

TlsFixerProviderGlobal g_tls_fixer_http;

typedef int (*TlsFixerCreateContinuation)(void *request, int socket);
typedef int (*TlsFixerConnectContinuation)(void *request);
typedef int (*TlsFixerMapIoContinuation)(void *connection, int result);
typedef int (*TlsFixerReadContinuation)(void *connection, void *buffer, unsigned int length);
typedef int (*TlsFixerWriteContinuation)(void *connection, const void *buffer, unsigned int length);
typedef int (*TlsFixerShutdownContinuation)(void *connection);

static void *next_hook_function(tai_hook_ref_t reference) {
    struct _tai_hook_user *current = (struct _tai_hook_user *)reference;
    struct _tai_hook_user *next = (struct _tai_hook_user *)current->next;

    return next == NULL ? current->old : next->func;
}

static int hook_create(void *request, int socket) {
    int handled;
    int result = tls_fixer_transport_create(request, socket, &handled);

    if (handled) {
        return result;
    }
    return ((TlsFixerCreateContinuation)next_hook_function(
        g_tls_fixer_http.hook_refs[HOOK_CREATE]))(request, socket);
}

static int hook_connect(void *request) {
    int handled;
    int result = tls_fixer_transport_connect(request, &handled);

    if (handled) {
        return result;
    }
    return ((TlsFixerConnectContinuation)next_hook_function(
        g_tls_fixer_http.hook_refs[HOOK_CONNECT]))(request);
}

static int hook_map_io(void *connection, int result) {
    int handled;
    int mapped = tls_fixer_transport_map_io(connection, result, &handled);

    if (handled) {
        return mapped;
    }
    return ((TlsFixerMapIoContinuation)next_hook_function(
        g_tls_fixer_http.hook_refs[HOOK_MAP_IO]))(connection, result);
}

static int hook_read(void *connection, void *buffer, unsigned int length) {
    int handled;
    int result = tls_fixer_transport_read(connection, buffer, length, &handled);

    if (handled) {
        return result;
    }
    return ((TlsFixerReadContinuation)next_hook_function(
        g_tls_fixer_http.hook_refs[HOOK_READ]))(connection, buffer, length);
}

static int hook_write(void *connection, const void *buffer, unsigned int length) {
    int handled;
    int result = tls_fixer_transport_write(connection, buffer, length, &handled);

    if (handled) {
        return result;
    }
    return ((TlsFixerWriteContinuation)next_hook_function(
        g_tls_fixer_http.hook_refs[HOOK_WRITE]))(connection, buffer, length);
}

static int hook_shutdown(void *connection) {
    int handled;
    int result = tls_fixer_transport_shutdown(connection, &handled);

    if (handled) {
        return result;
    }
    return ((TlsFixerShutdownContinuation)next_hook_function(
        g_tls_fixer_http.hook_refs[HOOK_SHUTDOWN]))(connection);
}

typedef struct TlsFixerHookInstallDescriptor {
    size_t offset;
    const void *function;
} TlsFixerHookInstallDescriptor;

static const TlsFixerHookInstallDescriptor g_hook_install_descriptors[] = {
    {TLS_FIXER_HOOK_CREATE_OFFSET, hook_create},
    {TLS_FIXER_HOOK_CONNECT_OFFSET, hook_connect},
    {TLS_FIXER_HOOK_MAP_IO_OFFSET, hook_map_io},
    {TLS_FIXER_HOOK_READ_OFFSET, hook_read},
    {TLS_FIXER_HOOK_WRITE_OFFSET, hook_write},
    {TLS_FIXER_HOOK_SHUTDOWN_OFFSET, hook_shutdown},
};

int tls_fixer_http_validate_start_args(SceSize argc, const void *args, TlsFixerStartArgs *out) {
    if (args == NULL || out == NULL || argc != sizeof(*out)) {
        return -1;
    }

    memcpy(out, args, sizeof(*out));
    if (out->magic != TLS_FIXER_START_MAGIC ||
        out->version != TLS_FIXER_START_VERSION ||
        out->libhttp_modid < 0 ||
        out->reserved != 0) {
        memset(out, 0, sizeof(*out));
        return -1;
    }

    return 0;
}

int tls_fixer_http_validate_module(
    int32_t modid,
    uintptr_t *text_address,
    size_t *text_size,
    uintptr_t *data_address,
    size_t *data_size) {
    SceKernelModuleInfo info;
    size_t failed_signature = SIZE_MAX;
    size_t failed_byte = SIZE_MAX;
    int result;

    if (modid < 0 || text_address == NULL || text_size == NULL ||
        data_address == NULL || data_size == NULL) {
        return -1;
    }

    memset(&info, 0, sizeof(info));
    info.size = sizeof(info);
    result = sceKernelGetModuleInfo(modid, &info);
    if (result < 0 || strcmp(info.module_name, "SceLibHttp") != 0) {
        return -1;
    }
    if (info.segments[0].vaddr == NULL ||
        info.segments[0].filesz != TLS_FIXER_LIBHTTP_TEXT_SIZE ||
        info.segments[0].memsz != TLS_FIXER_LIBHTTP_TEXT_SIZE) {
        return -1;
    }
    if (info.segments[1].vaddr == NULL ||
        info.segments[1].filesz != TLS_FIXER_LIBHTTP_DATA_FILE_SIZE ||
        info.segments[1].memsz != TLS_FIXER_LIBHTTP_DATA_MEMORY_SIZE) {
        return -1;
    }

    result = tls_fixer_validate_module_text(
        (const uint8_t *)info.segments[0].vaddr,
        info.segments[0].filesz,
        &g_libhttp_descriptor,
        &failed_signature,
        &failed_byte);
    if (result != TLS_FIXER_MODULE_GATE_OK) {
        return result;
    }

    if (tls_fixer_cert_policy_bind(&g_tls_fixer_http.cert_policy,
                               info.segments[0].vaddr, info.segments[0].filesz) != 0) {
        TLS_FIXER_LOG("certificate callback policy import mismatch");
        return -1;
    }

    *text_address = (uintptr_t)info.segments[0].vaddr;
    *text_size = info.segments[0].filesz;
    *data_address = (uintptr_t)info.segments[1].vaddr;
    *data_size = info.segments[1].memsz;
    return 0;
}

int tls_fixer_http_install_hooks(void) {
    size_t index;

    for (index = 0; index < TLS_FIXER_HOOK_COUNT; ++index) {
        const TlsFixerHookInstallDescriptor *descriptor = &g_hook_install_descriptors[index];
        int hook_id = taiHookFunctionOffset(
            &g_tls_fixer_http.hook_refs[index],
            g_tls_fixer_http.libhttp_modid,
            0,
            descriptor->offset,
            1,
            descriptor->function);
        if (hook_id < 0) {
            tls_fixer_http_release_hooks();
            return hook_id;
        }
        g_tls_fixer_http.hook_ids[index] = hook_id;
    }

    return 0;
}

void tls_fixer_http_release_hooks(void) {
    size_t index = TLS_FIXER_HOOK_COUNT;

    while (index > 0) {
        --index;
        if (g_tls_fixer_http.hook_ids[index] >= 0) {
            taiHookRelease(
                g_tls_fixer_http.hook_ids[index],
                g_tls_fixer_http.hook_refs[index]);
            g_tls_fixer_http.hook_ids[index] = -1;
            memset(&g_tls_fixer_http.hook_refs[index], 0, sizeof(g_tls_fixer_http.hook_refs[index]));
        }
    }
}

int module_start(SceSize argc, const void *args) {
    TlsFixerStartArgs start_args;
    size_t index;

    memset(&g_tls_fixer_http, 0, sizeof(g_tls_fixer_http));
    for (index = 0; index < TLS_FIXER_HOOK_COUNT; ++index) {
        g_tls_fixer_http.hook_ids[index] = -1;
    }
    g_tls_fixer_http.state = TLS_FIXER_PROVIDER_STARTING;

    if (tls_fixer_http_validate_start_args(argc, args, &start_args) < 0) {
        TLS_FIXER_LOG("invalid start arguments");
        g_tls_fixer_http.state = TLS_FIXER_PROVIDER_STOPPED;
        return SCE_KERNEL_START_FAILED;
    }

    g_tls_fixer_http.libhttp_modid = start_args.libhttp_modid;
    if (tls_fixer_http_validate_module(
            start_args.libhttp_modid,
            &g_tls_fixer_http.text_address,
            &g_tls_fixer_http.text_size,
            &g_tls_fixer_http.data_address,
            &g_tls_fixer_http.data_size) < 0) {
        TLS_FIXER_LOG("mapped libhttp validation failed: modid=0x%08X", start_args.libhttp_modid);
        g_tls_fixer_http.state = TLS_FIXER_PROVIDER_STOPPED;
        return SCE_KERNEL_START_FAILED;
    }
    g_tls_fixer_http.global_https_options_address =
        g_tls_fixer_http.data_address + TLS_FIXER_LIBHTTP_GLOBAL_HTTPS_OPTIONS_OFFSET;

    {
        int result = tls_fixer_transport_global_init();
        if (result != 0) {
            TLS_FIXER_LOG("global TLS initialization failed: 0x%08X", result);
            g_tls_fixer_http.state = TLS_FIXER_PROVIDER_STOPPED;
            return SCE_KERNEL_START_FAILED;
        }
    }

    {
        int result = tls_fixer_cert_hooks_install();
        if (result < 0) {
            TLS_FIXER_LOG("certificate hook installation failed: 0x%08X", result);
            (void)tls_fixer_transport_global_destroy();
            g_tls_fixer_http.state = TLS_FIXER_PROVIDER_STOPPED;
            return SCE_KERNEL_START_FAILED;
        }
    }

    {
        int result = tls_fixer_http_install_hooks();
        if (result < 0) {
            TLS_FIXER_LOG("transport hook installation failed: 0x%08X", result);
            tls_fixer_cert_hooks_release();
            (void)tls_fixer_transport_global_destroy();
            g_tls_fixer_http.state = TLS_FIXER_PROVIDER_STOPPED;
            return SCE_KERNEL_START_FAILED;
        }
    }

    TLS_FIXER_LOG(
        "active: libhttp=0x%08X text=0x%08X data=0x%08X",
        g_tls_fixer_http.libhttp_modid,
        (unsigned int)g_tls_fixer_http.text_address,
        (unsigned int)g_tls_fixer_http.data_address);
    g_tls_fixer_http.state = TLS_FIXER_PROVIDER_ACTIVE;
    return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize argc, const void *args) {
    (void)argc;
    (void)args;
    /* Empty registries do not exclude threads entering hooks or executing their continuations. */
    TLS_FIXER_LOG("hot unload rejected; provider is resident until process exit");
    return SCE_KERNEL_STOP_FAIL;
}

int _start(SceSize argc, const void *args) __attribute__((weak, alias("module_start")));
