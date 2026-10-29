/* SPDX-License-Identifier: 0BSD */
#include "cover.h"
#include "fetch.h"
#include "firmware.h"
#include "../tls13/provider/private_mapping.h"
#include <psp2/appmgr.h>
#include <psp2/kernel/clib.h>
#include <psp2/kernel/modulemgr.h>
#include <psp2/kernel/processmgr.h>
#include <psp2/kernel/sysmem.h>
#include <psp2/kernel/threadmgr.h>
#include <taihen.h>

#if STORE_COVER_DIAGNOSTICS
#include <psp2/io/fcntl.h>
void store_cover_note(const char *phase, int value, const char *id) {
    int fd = sceIoOpen("ux0:/data/tls_fixer-store-cover.log", SCE_O_WRONLY | SCE_O_CREAT | SCE_O_APPEND, 0777);
    if (fd < 0) return;
    char line[192];
    int n = sceClibSnprintf(line, sizeof(line), "%s rc=0x%08X id=%.36s thread=0x%08X\n", phase,
        (unsigned)value, id ? id : "", (unsigned)sceKernelGetThreadId());
    if (n > 0 && (size_t)n < sizeof(line)) (void)sceIoWrite(fd, line, (SceSize)n);
    (void)sceIoClose(fd);
}
#define note store_cover_note
#else
#define note(phase, value, id) ((void)0)
#endif

typedef struct {
    unsigned char header[0x60];
    const char *id;
    unsigned char identity[0x0c];
    const char *name;
    const char *description;
    const char *image;
    unsigned char remainder[0x64];
} StoreProduct;
_Static_assert(offsetof(StoreProduct, id) == 0x60, "Commerce product ID ABI");
_Static_assert(offsetof(StoreProduct, image) == 0x78, "Commerce image ABI");
_Static_assert(sizeof(StoreProduct) == 224, "Commerce product ABI");

typedef struct CachePage {
    struct CachePage *next;
    size_t used;
} CachePage;
static CachePage *g_cache_pages;
static void *cache_allocate(void *context, size_t size) {
    (void)context;
    const size_t page_size = 4096;
    size = (size + sizeof(void *) - 1) & ~(sizeof(void *) - 1);
    if (size > page_size - sizeof(CachePage)) return NULL;
    if (!g_cache_pages || size > page_size - g_cache_pages->used) {
        void *base = NULL;
        SceUID block = sceKernelAllocMemBlock("tls_fixer artwork cache", SCE_KERNEL_MEMBLOCK_TYPE_USER_RW, page_size, NULL);
        if (block < 0) return NULL;
        if (sceKernelGetMemBlockBase(block, &base) < 0 || !base) {
            sceKernelFreeMemBlock(block); return NULL;
        }
        CachePage *page = base;
        page->next = g_cache_pages; page->used = sizeof(*page); g_cache_pages = page;
    }
    void *result = (unsigned char *)g_cache_pages + g_cache_pages->used;
    g_cache_pages->used += size;
    return result;
}
/* Pages belong to Store and are reclaimed with its process. Published URLs
 * remain stable; the temporary TLS heap is still freed after every lookup. */
static StoreCoverCache g_cache = {.allocate = cache_allocate};
static SceUID g_mutex = -1;
static SceUID g_hooks[2] = {-1, -1};
static tai_hook_ref_t g_refs[2];
#if STORE_COVER_DIAGNOSTICS
static tai_hook_ref_t g_paf_open_ref;
static tai_hook_ref_t g_paf_read_ref;
static int (*g_paf_status)(void *, unsigned short *);
static void *g_image_file;
typedef struct { const char *text; unsigned length, capacity; } PafString;
typedef struct {
    unsigned file_type; PafString scheme, host; unsigned port;
    PafString method, uri;
} PafOpenPrefix;
static int paf_open_hook(void *file, const PafOpenPrefix *arg) {
    int rc = TAI_CONTINUE(int, g_paf_open_ref, file, arg);
    if (arg && arg->host.text &&
        (!sceClibStrcmp(arg->host.text,"image.api.playstation.com") || !sceClibStrcmp(arg->host.text,"apollo2.dl.playstation.net")))
    {
        g_image_file = file;
        note("image.open",rc,arg->uri.text);
        unsigned short code = 0;
        if (g_paf_status) { int queried = g_paf_status(file,&code); note("image.status.query",queried,NULL); note("image.http",code,NULL); }
    }
    else if (file == g_image_file) g_image_file = NULL;
    return rc;
}
static int paf_read_hook(void *file, void *buffer, unsigned size) {
    int rc = TAI_CONTINUE(int,g_paf_read_ref,file,buffer,size);
    if (file == g_image_file) {
        note("image.read",rc,NULL);
        if (rc >= 4) { unsigned magic; sceClibMemcpy(&magic,buffer,4); note("image.magic",(int)magic,NULL); }
    }
    return rc;
}
#endif
static struct {
    char id[STORE_COVER_ID_SIZE];
    char url[STORE_COVER_URL_SIZE];
    int result;
} g_job;
static int g_worker_unresolved;

static int fetch_worker(SceSize argc, void *args) {
    (void)argc; (void)args;
    g_job.result = store_cover_fetch(NULL, g_job.id, g_job.url);
    return sceKernelExitThread(0);
}
static int fetch_on_worker(void *unused, const char *id, char *url) {
    (void)unused;
    if (g_worker_unresolved) return -1;
    sceClibMemcpy(g_job.id, id, STORE_COVER_ID_SIZE); g_job.url[0] = 0; g_job.result = -1;
    /* Crypto runs on its own temporary stack, never a small native Store job's
     * stack. The cache mutex serializes requests and keeps the job stable. */
    SceUID worker = sceKernelCreateThread("tls_fixer artwork fetch", fetch_worker, 0x10000100, 64 * 1024, 0, 0, NULL);
    if (worker < 0) return -1;
    if (sceKernelStartThread(worker, 0, NULL) < 0) { sceKernelDeleteThread(worker); return -1; }
    if (sceKernelWaitThreadEnd(worker, NULL, NULL) < 0) {
        /* Do not reuse job storage or unload a potentially running worker. */
        g_worker_unresolved = 1;
        return -1;
    }
    (void)sceKernelDeleteThread(worker);
    if (g_job.result == 0) sceClibMemcpy(url, g_job.url, STORE_COVER_URL_SIZE);
    return g_job.result;
}

static int fill_product(int rc, StoreProduct *product) {
    if (rc < 0 || !product || (product->image && product->image[0]) || !store_cover_valid_id(product->id)) return rc;
    note("missing", rc, product->id);
    /* The Store calls this decoder from its catalog job after the native
     * request completes. Concurrent jobs keep their original placeholder. */
    if (sceKernelTryLockMutex(g_mutex, 1) < 0) return rc;
    int filled = store_cover_fill(&g_cache, rc, product->id, &product->image,
        sceKernelGetSystemTimeWide(), fetch_on_worker, NULL);
    note(filled ? "filled" : "unchanged", rc, product->id);
    (void)filled;
    (void)sceKernelUnlockMutex(g_mutex, 1);
    return rc;
}
static int category_product_hook(const void *content, StoreProduct *product) {
    return fill_product(TAI_CONTINUE(int, g_refs[0], content, product), product);
}
static int detail_product_hook(const void *content, StoreProduct *product) {
    return fill_product(TAI_CONTINUE(int, g_refs[1], content, product), product);
}

static int private_importer(tai_module_info_t *tai) {
    SceKernelModuleInfo m = {0}; m.size = sizeof(m);
    if (sceKernelGetModuleInfo(tai->modid, &m) < 0 || m.state != 6 || sceClibStrcmp(m.module_name, "SceStoreBrowser")) return 0;
    int imports_inside = 0;
    for (unsigned i = 0; i < 2; ++i) {
        SceKernelMemBlockInfo b = {0}; b.size = sizeof(b);
        uintptr_t start = (uintptr_t)m.segments[i].vaddr; size_t size = m.segments[i].memsz;
        if (sceKernelGetMemBlockInfoByAddr(m.segments[i].vaddr, &b) < 0 ||
            !tls_fixer_private_mapping_contains(start, size, (uintptr_t)b.mappedBase, b.mappedSize, b.type, b.access, i == 0)) return 0;
        if (tai->imports_end > tai->imports_start && tai->imports_start >= start &&
            tai->imports_start - start < size && tai->imports_end - tai->imports_start <= size - (tai->imports_start - start)) imports_inside = 1;
    }
    return imports_inside;
}

static int setup(SceSize argc, void *args) {
    (void)argc; (void)args;
    sceKernelDelayThread(20000);
    char title[32] = {0};
    if (sceAppMgrGetNameById(sceKernelGetProcessId(), title) < 0 || sceClibStrcmp(title, "NPXS10002")) goto done;
    for (unsigned attempt = 0; attempt < 150; ++attempt) {
        tai_module_info_t target = {0}; target.size = sizeof(target);
        if (taiGetModuleInfo("SceStoreBrowser", &target) >= 0 && private_importer(&target)) {
            tai_module_info_t commerce = {0}; commerce.size = sizeof(commerce);
            if (taiGetModuleInfo("SceNpCommerce2", &commerce) < 0 || !store_cover_commerce_supported(commerce.module_nid)) {
                note("commerce.unsupported", (int)commerce.module_nid, title);
                goto done;
            }
            g_mutex = sceKernelCreateMutex("tls_fixer artwork", 0, 0, NULL);
            if (g_mutex < 0) goto done;
            g_hooks[0] = taiHookFunctionImport(&g_refs[0], "SceStoreBrowser", 0x40120dc3, 0xec09ff89, category_product_hook);
            g_hooks[1] = taiHookFunctionImport(&g_refs[1], "SceStoreBrowser", 0x40120dc3, 0xf988a255, detail_product_hook);
            note("hook.category", g_hooks[0], title);
            note("hook.detail", g_hooks[1], title);
#if STORE_COVER_DIAGNOSTICS
            tai_module_info_t paf = {0}; paf.size = sizeof(paf);
            if (taiGetModuleInfo("ScePaf", &paf) == 0 && paf.module_nid == 0xcd679177) {
                SceKernelModuleInfo m = {0}; m.size = sizeof(m);
                if (sceKernelGetModuleInfo(paf.modid,&m) == 0 && m.segments[0].memsz > 0x1ef50)
                    g_paf_status = (void *)((uintptr_t)m.segments[0].vaddr + 0x1eefc + 1);
                note("hook.image.open",taiHookFunctionImport(&g_paf_open_ref,"SceStoreBrowser",0x3d643ce8,0xd2221e7b,paf_open_hook),title);
                note("hook.image.read",taiHookFunctionImport(&g_paf_read_ref,"SceStoreBrowser",0x3d643ce8,0xfd8d09e7,paf_read_hook),title);
            }
#endif
            if (g_hooks[0] < 0 && g_hooks[1] < 0) { sceKernelDeleteMutex(g_mutex); g_mutex = -1; }
            goto done;
        }
        sceKernelDelayThread(200000);
    }
    note("store.unavailable", -1, title);
done:
    return sceKernelExitDeleteThread(0);
}
int module_start(SceSize argc, const void *args) {
    (void)argc; (void)args;
    /* Kernel loader already gates NPXS10002; repeat identity checks after the
     * loader has returned, before publishing any hooks in this process. */
    SceUID worker = sceKernelCreateThread("tls_fixer artwork setup", setup, 0x10000100, 16 * 1024, 0, 0, NULL);
    if (worker < 0) return SCE_KERNEL_START_NO_RESIDENT;
    if (sceKernelStartThread(worker, 0, NULL) < 0) { sceKernelDeleteThread(worker); return SCE_KERNEL_START_NO_RESIDENT; }
    return SCE_KERNEL_START_SUCCESS;
}
int module_stop(SceSize argc, const void *args) {
    (void)argc; (void)args;
    /* Published borrowed URLs and hook callbacks remain live until Store exits.
     * Refuse manual unload rather than freeing memory a Store job may retain. */
    return SCE_KERNEL_STOP_CANCEL;
}
