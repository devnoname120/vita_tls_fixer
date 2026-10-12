# TLS 1.3 Browser Transport Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and package a Mbed TLS provider that supplies TLS 1.2/1.3 transport behind the six verified TLS functions in the exact `libhttp.suprx` bundled by tls_fixer. This adapter alone does not add browser TLS 1.3.

**Architecture:** The kernel plugin validates the exact bundled `libhttp.suprx`, redirects it as before, and injects `tls_fixer_http.suprx` into each process after that module loads. The user provider validates the mapped module, transactionally hooks the six transport functions, and keeps Mbed TLS state in an external connection registry keyed by Sony's connection pointer. Connections without provider state continue through the original BSAFE functions.

**Tech Stack:** C11, CMake/CTest, VitaSDK hard-float GCC 15.2, taiHEN, source-built Mbed TLS 4.2.0 / TF-PSA-Crypto 1.2.0, SceNet, SceKernelUtils SHA-256, Python 3 validation scripts.

## Execution revision: 2026-10-07

This is a historical task breakdown, not a current checklist of completed browser support. The original prebuilt-3.6.5 steps, name-wrapper lifetime, permissive callback acceptance and hot-unload assumptions were superseded during executable regression testing and IDA verification. Read the controlling revision in the corresponding design and `TLS13_PROGRESS.md` sections 20 onward before following any old step literally.

Implemented in the worktree: pinned current-engine source build and fetch tests, explicit Vita crypto platform, real TLS loopback tests, certificate inspection/export wrappers, Sony post-callback permission checks, retained-name ownership, stable write retries, registry cleanup accounting, kernel/libhttp integration and packaging. No commit/push is implied by the historical commit steps below.

The browser-specific extension is now implemented in `tls13/browser/`, separately specified in `docs/tls13-browser-path.md`, and integrated into kernel loading and installer packaging. It reuses the crypto engine, not SceHttp offsets or errors. Browser module activation, 22 real TLS loopback scenarios, kernel UID/namespace handoff and installation refresh are covered by source/build verification. Native tests and cross-builds remain separate from device execution and browser process coverage.

---

## File Map

### Shared, host-testable core

- `tls13/include/tls_fixer/sony_abi.h`: exact Sony constants, offsets, hook offsets, provider start ABI, and request/connection accessors.
- `tls13/include/tls_fixer/error_map.h`: provider-neutral operation/error classes and translation declarations.
- `tls13/include/tls_fixer/module_gate.h`: masked-signature descriptor and validation interface.
- `tls13/include/tls_fixer/registry.h`: bounded connection registry interface and slot lifecycle.
- `tls13/src/error_map.c`: Mbed-TLS-independent Sony error/detail translation.
- `tls13/src/module_gate.c`: bounds-safe masked byte validation.
- `tls13/src/registry.c`: fixed-capacity registry with injectable lock/cleanup callbacks.
- `tls13/tests/test_main.c`: standalone host test runner covering core invariants.
- `tls13/CMakeLists.txt`: host tests and Vita target dispatch.

### Static binary validation

- `tools/validate_libhttp.py`: parses the supported ELF payload, checks program-header shape and hook masks, and optionally checks the compressed SELF hash.
- `tls13/supported_libhttp.json`: machine-readable exact hash, segment shape, offsets, bytes, and masks.

### Vita provider

- `tls13/provider/tls_fixer_http.yml`: provider module metadata and exports.
- `tls13/provider/provider.h`: provider-global state and start/stop declarations.
- `tls13/provider/provider.c`: module lifecycle, module gate, process-global initialization, transactional hook installation, rollback, and cleanup.
- `tls13/provider/transport.h`: provider connection type and six hook declarations.
- `tls13/provider/transport.c`: create, handshake, read, write, map, shutdown, Mbed TLS lifecycle, and Sony result storage.
- `tls13/provider/vita_net.c`: SceNet BIO callbacks and raw network error capture.
- `tls13/provider/trust_store.c`: CA bundle read/parse and process-global entropy/CTR-DRBG initialization.
- `tls13/provider/cert_compat.h`: provider certificate/name wrapper ABI.
- `tls13/provider/cert_compat.c`: application callback bridge and public `sceSslGet*` compatibility hooks.
- `tls13/provider/CMakeLists.txt`: hard-float provider build and Mbed TLS version/config checks.

### Kernel injection and installer

- `kernel/main.c`: exact-file hash gate, provider existence gate, post-`libhttp` injection, recursion guard, and cleanup.
- `kernel/CMakeLists.txt`: add `SceKernelUtilsForDriver_stub` and warning-hardening flags.
- `main.c`: install/uninstall provider alongside HTTP/SSL modules and make file operations fail visibly.
- `Makefile`: build provider and package `tls_fixer_http.suprx` in the VPK.
- `README.md`: scope, TLS 1.3 behavior, exact-module gate, fallback behavior, and hardware-validation status.

## Task 1: Encode the Exact Sony ABI and Supported Module

**Files:**
- Create: `tls13/include/tls_fixer/sony_abi.h`
- Create: `tls13/supported_libhttp.json`
- Create: `tools/validate_libhttp.py`
- Test: `tls13/tests/test_main.c`

- [ ] **Step 1: Add the provider start ABI and constants**

Define:

```c
#define TLS_FIXER_START_MAGIC UINT32_C(0x49544C53)
#define TLS_FIXER_START_VERSION UINT32_C(1)

typedef struct TlsFixerStartArgs {
    uint32_t magic;
    uint32_t version;
    int32_t libhttp_modid;
    uint32_t reserved;
} TlsFixerStartArgs;
```

Add the public Sony error values recovered from the official SDK, the six hook offsets, request pointer offsets `0x130`/`0x134`, and connection offsets `0x24`, `0x48`, `0x104`, `0x108`, `0x160`, and `0x164`.

- [ ] **Step 2: Add bounds-safe field helpers**

Implement inline `memcpy`-based pointer/integer accessors rather than type-punning unknown Sony objects. Add:

```c
void *tls_fixer_resolve_connection(void *request);
int tls_fixer_connection_socket(const void *connection);
const char *tls_fixer_connection_hostname(const void *connection);
void tls_fixer_store_ssl_error(void *connection, int error, uint32_t detail);
```

- [ ] **Step 3: Record the supported module descriptor**

The JSON descriptor must include:

```json
{
  "compressed_sha256": "42bc7e34077964ac7edc4365abad8af9bf41793a34d2c7efd631976f7d2739c1",
  "text_filesz": 119120,
  "text_memsz": 119120,
  "hooks": [
    {"name":"create","offset":33072,"bytes":"2de9f04188b0...","mask":"..."}
  ]
}
```

Use `0x1D150` as 119120 decimal and include all six exact offsets/masks.

- [ ] **Step 4: Implement the validator script**

`tools/validate_libhttp.py` must:

1. read an ELF32 little-endian file;
2. validate ARM machine type and program-header bounds;
3. locate executable `PT_LOAD` segment zero;
4. check `filesz == memsz == 0x1D150`;
5. compare every masked hook signature at its module offset;
6. assert each signature is unique in the executable segment;
7. optionally hash a supplied SELF and compare the known SHA-256;
8. emit a nonzero exit code and specific error text for every mismatch.

- [ ] **Step 5: Run positive and negative static checks**

Run:

```bash
python3 tools/validate_libhttp.py \
  --descriptor tls13/supported_libhttp.json \
  --elf .reverse-tmp/lhttp-3.73-fresh.elf \
  --self misc/lhttp.suprx
```

Expected: `supported libhttp: OK`.

Copy the ELF, flip one fixed signature byte, and rerun. Expected: nonzero exit with the exact hook name.

- [ ] **Step 6: Commit the ABI/gate descriptor**

```bash
git add tls13/include/tls_fixer/sony_abi.h tls13/supported_libhttp.json tools/validate_libhttp.py

git commit -m "tls13: encode supported libhttp boundary"
```

## Task 2: Implement and Test Error Translation

**Files:**
- Create: `tls13/include/tls_fixer/error_map.h`
- Create: `tls13/src/error_map.c`
- Modify: `tls13/tests/test_main.c`

- [ ] **Step 1: Define provider-neutral outcomes**

Use an enum independent of Mbed TLS headers:

```c
typedef enum TlsFixerOutcome {
    TLS_FIXER_OUTCOME_OK,
    TLS_FIXER_OUTCOME_WANT_READ,
    TLS_FIXER_OUTCOME_WANT_WRITE,
    TLS_FIXER_OUTCOME_CLOSE_NOTIFY,
    TLS_FIXER_OUTCOME_EOF,
    TLS_FIXER_OUTCOME_TIMEOUT,
    TLS_FIXER_OUTCOME_CERTIFICATE,
    TLS_FIXER_OUTCOME_HANDSHAKE,
    TLS_FIXER_OUTCOME_IO,
    TLS_FIXER_OUTCOME_NO_MEMORY,
    TLS_FIXER_OUTCOME_INTERNAL
} TlsFixerOutcome;
```

Define a result containing the hook return, stored HTTPS error, and detail.

- [ ] **Step 2: Write failing table-driven tests**

Cover WANT_READ, WANT_WRITE, close-notify, cert detail combinations, handshake failure, I/O failure, timeout, no-memory, and internal failure. Assert WANT outcomes return `SCE_HTTP_ERROR_EAGAIN` without a stored fatal error.

- [ ] **Step 3: Implement the mapping**

Certificate detail bits are ORed from provider-neutral flags:

```c
TLS_FIXER_CERT_INVALID    -> 0x02
TLS_FIXER_CERT_HOSTNAME   -> 0x04
TLS_FIXER_CERT_EXPIRED    -> 0x08
TLS_FIXER_CERT_FUTURE     -> 0x10
TLS_FIXER_CERT_UNKNOWN_CA -> 0x20
```

- [ ] **Step 4: Run host tests**

Run:

```bash
cmake -S tls13 -B build/tls13-host -DTLS_FIXER_BUILD_HOST_TESTS=ON
cmake --build build/tls13-host
ctest --test-dir build/tls13-host --output-on-failure
```

Expected: all tests pass.

- [ ] **Step 5: Commit error mapping**

```bash
git add tls13/include/tls_fixer/error_map.h tls13/src/error_map.c tls13/tests/test_main.c tls13/CMakeLists.txt

git commit -m "tls13: add Sony error translation"
```

## Task 3: Implement and Test the Connection Registry

**Files:**
- Create: `tls13/include/tls_fixer/registry.h`
- Create: `tls13/src/registry.c`
- Modify: `tls13/tests/test_main.c`

- [ ] **Step 1: Define explicit slot states**

Use:

```c
typedef enum TlsFixerSlotState {
    TLS_FIXER_SLOT_FREE,
    TLS_FIXER_SLOT_INITIALIZING,
    TLS_FIXER_SLOT_ACTIVE,
    TLS_FIXER_SLOT_REMOVING
} TlsFixerSlotState;
```

Each slot stores key, generation, references, state, and an opaque provider payload pointer.

- [ ] **Step 2: Inject lock and cleanup operations**

The shared registry must not include Vita headers. Initialize it with callbacks for lock, unlock, and payload cleanup so host tests can use no-op locks and the provider can use a lightweight mutex.

- [ ] **Step 3: Write failing lifecycle tests**

Cover:

- create/acquire/release/remove;
- duplicate create;
- capacity exhaustion;
- remove with in-flight reference;
- repeated remove;
- cleanup on registry destroy;
- generation change after slot reuse;
- null key rejection.

- [ ] **Step 4: Implement registry transitions**

Never call payload cleanup while holding the structural lock. Removal makes the slot unavailable immediately and defers cleanup until references reach zero.

- [ ] **Step 5: Run tests and sanitizers**

Use host compiler warnings plus AddressSanitizer and UndefinedBehaviorSanitizer when supported:

```bash
cmake -S tls13 -B build/tls13-host-san \
  -DTLS_FIXER_BUILD_HOST_TESTS=ON \
  -DTLS_FIXER_ENABLE_SANITIZERS=ON
cmake --build build/tls13-host-san
ctest --test-dir build/tls13-host-san --output-on-failure
```

- [ ] **Step 6: Commit registry**

```bash
git add tls13/include/tls_fixer/registry.h tls13/src/registry.c tls13/tests/test_main.c tls13/CMakeLists.txt

git commit -m "tls13: add bounded connection registry"
```

## Task 4: Build a Transactional Vita Provider Skeleton

**Files:**
- Create: `tls13/provider/tls_fixer_http.yml`
- Create: `tls13/provider/provider.h`
- Create: `tls13/provider/provider.c`
- Create: `tls13/provider/CMakeLists.txt`
- Modify: `tls13/CMakeLists.txt`

- [ ] **Step 1: Define module lifecycle and start validation**

`module_start` must reject wrong argument size, magic, version, and module ID. It initializes a global state enum and never reports resident success after partial initialization.

- [ ] **Step 2: Validate the mapped module**

Call `sceKernelGetModuleInfo`, require module name `SceLibHttp`, segment zero size at least `0x1D150`, and apply all six masked signatures against `segments[0].vaddr`.

- [ ] **Step 3: Add transactional hook installation**

Install hooks in a fixed array. On failure at index N, release indices `N-1` down to zero. Keep separate `tai_hook_ref_t` values for `TAI_CONTINUE`.

Initially every hook simply forwards to the original function. This proves the exact boundary and produces a loadable probe without changing behavior.

- [ ] **Step 4: Add stop cleanup**

Mark provider stopping, release hooks in reverse order, destroy provider globals, and return stop success. Reject stop if active references cannot be drained safely.

- [ ] **Step 5: Build the forwarding provider**

Run in the hard-float image:

```bash
docker run --rm -v "$PWD":/src -w /src vitasdk/vitasdk:latest \
  sh -lc 'cmake -S tls13 -B build/tls13-vita \
    -DTLS_FIXER_BUILD_VITA_PROVIDER=ON \
    -DCMAKE_TOOLCHAIN_FILE="$VITASDK/share/vita.toolchain.cmake" && \
    cmake --build build/tls13-vita --verbose'
```

Expected: `tls_fixer_http.suprx` and no unresolved symbol failure.

- [ ] **Step 6: Inspect the provider**

Use `arm-vita-eabi-readelf`, `arm-vita-eabi-size`, and Vita tools to record imports, segment sizes, hard-float attributes, and module metadata.

- [ ] **Step 7: Commit provider skeleton**

```bash
git add tls13/provider tls13/CMakeLists.txt

git commit -m "tls13: add validated forwarding provider"
```

## Task 5: Implement Trust Store, Entropy, and Vita BIO

**Files:**
- Create: `tls13/provider/trust_store.c`
- Create: `tls13/provider/vita_net.c`
- Create: `tls13/provider/transport.h`
- Modify: `tls13/provider/provider.h`
- Modify: `tls13/provider/provider.c`
- Modify: `tls13/provider/CMakeLists.txt`

- [ ] **Step 1: Enforce Mbed TLS 3.6.5 and TLS 1.3**

At compile time require:

```c
MBEDTLS_VERSION_NUMBER == 0x03060500
MBEDTLS_SSL_PROTO_TLS1_3
```

Fail the build rather than silently compiling against a different ABI/configuration.

- [ ] **Step 2: Load the PEM bundle once**

Read `vs0:/data/external/cert/CA_LIST.cer` with bounded growth and parse it using `mbedtls_x509_crt_parse`. Require at least one parsed certificate and reject any fatal parse result.

- [ ] **Step 3: Initialize entropy and CTR-DRBG**

Use Mbed TLS entropy and CTR-DRBG with a provider/process personalization string. Unwind in reverse order on any failure.

- [ ] **Step 4: Implement SceNet callbacks**

The callback context is the provider connection. Preserve the raw negative SceNet result before converting EAGAIN, reset, and generic send/receive failures to Mbed TLS values.

- [ ] **Step 5: Build and inspect**

Confirm TLS 1.3 client symbols are retained in the provider link and record binary growth.

- [ ] **Step 6: Commit platform TLS initialization**

```bash
git add tls13/provider

git commit -m "tls13: initialize Vita Mbed TLS platform"
```

## Task 6: Implement Create, Handshake, Read, Write, and Shutdown

**Files:**
- Create: `tls13/provider/transport.c`
- Modify: `tls13/provider/transport.h`
- Modify: `tls13/provider/provider.c`
- Modify: `tls13/provider/CMakeLists.txt`
- Modify: `tls13/tests/test_main.c`

- [ ] **Step 1: Define the provider connection owner**

Include Mbed TLS SSL/config objects, socket, copied hostname, lifecycle state, operation mutex, raw/provider/Sony diagnostics, and callback-wrapper state. Use one cleanup routine valid after every partial initialization point.

- [ ] **Step 2: Implement create with legacy fallback**

Resolve the Sony connection, copy the hostname, initialize per-connection config/context, set TLS 1.2 minimum and TLS 1.3 maximum, set CA/DRBG/BIO/hostname, and activate the registry slot. If failure occurs before TLS bytes are emitted, remove the slot and call the original BSAFE create function.

- [ ] **Step 3: Implement incremental handshake**

Call `mbedtls_ssl_handshake`. Map both WANT results to `SCE_HTTP_ERROR_EAGAIN`. On success, check verification flags and transition to active. On fatal error, store phase-specific diagnostics at Sony offsets `0x160`/`0x164` and return `SCE_HTTP_ERROR_SSL`.

- [ ] **Step 4: Implement read/write**

Cap each engine call to 1500 bytes. Preserve positive partial transfers. Map WANT to HTTP EAGAIN, close-notify to zero, and fatal errors to stored `SCE_HTTPS_ERROR_IO` plus detail.

- [ ] **Step 5: Implement map hook**

For provider connections, return the already translated result without invoking BSAFE classification. For all other connections, call the original mapper.

- [ ] **Step 6: Implement shutdown**

Atomically remove the registry entry, attempt close-notify once, free provider state, and return zero. Duplicate shutdown without an entry forwards to the original BSAFE function.

- [ ] **Step 7: Add host tests for pure lifecycle decisions**

Extract phase/result decisions into host-testable functions. Cover fallback-before-wire, no-fallback-after-wire, WANT preservation, partial I/O, clean close, and duplicate teardown.

- [ ] **Step 8: Build and run all tests**

Run host sanitizer tests and the hard-float provider build.

- [ ] **Step 9: Commit transport implementation**

```bash
git add tls13/provider tls13/tests

git commit -m "tls13: implement Mbed TLS transport hooks"
```

## Task 7: Implement Application Certificate Callback Compatibility

**Files:**
- Create: `tls13/provider/cert_compat.h`
- Create: `tls13/provider/cert_compat.c`
- Modify: `tls13/provider/transport.c`
- Modify: `tls13/provider/provider.c`
- Modify: `tls13/provider/CMakeLists.txt`
- Modify: `tls13/tests/test_main.c`

- [ ] **Step 1: Verify the original callback return convention**

Finish tracing the original `fun_http_tls_verify_callback` invocation of connection fields `0x104` and `0x108`. Record the exact accept and reject return values in `TLS13_PROGRESS.md` and constants in `cert_compat.h`.

- [ ] **Step 2: Define wrapper magic/version types**

Provider cert and name wrappers must be distinguishable from BSAFE pointers without dereferencing arbitrary memory beyond a guarded provider-owned address set.

- [ ] **Step 3: Hook public certificate inspection exports**

Resolve the eight public function NIDs from VitaSDK metadata. Each hook handles provider wrappers and forwards non-provider objects via `TAI_CONTINUE`.

- [ ] **Step 4: Convert Mbed TLS certificate data**

Implement serial number, subject/issuer names, validity ticks, and name entry enumeration. Match Sony buffer-length and error semantics, including explicit name-wrapper free.

- [ ] **Step 5: Invoke the application callback**

Build a temporary wrapper array over the retained peer chain, pass translated verification bits and user argument, honor the verified return convention, and invalidate/free wrappers on exit.

- [ ] **Step 6: Test wrapper lifetime and dispatch**

Host tests cover provider-vs-foreign pointer dispatch, invalid/stale wrapper rejection, entry counts, buffer truncation, repeated free, and callback cleanup.

- [ ] **Step 7: Commit callback compatibility**

```bash
git add tls13/provider tls13/tests TLS13_PROGRESS.md

git commit -m "tls13: bridge Vita certificate callbacks"
```

## Task 8: Add Kernel Hash Gate and Provider Injection

**Files:**
- Modify: `kernel/main.c`
- Modify: `kernel/CMakeLists.txt`
- Create: `kernel/tls13_loader.h`
- Create: `kernel/tls13_loader.c`

- [ ] **Step 1: Fix path handling before extending it**

Replace suffix arithmetic that can evaluate `path + len - 27` for short paths with a checked suffix helper. Preserve existing redirects exactly.

- [ ] **Step 2: Implement streaming SHA-256**

Open the installed `libhttp.suprx`, read fixed-size chunks, update `SceSha256Context`, and compare the final 32-byte digest to the known compressed hash. Zero temporary buffers and close/free on every path.

- [ ] **Step 3: Add provider activation flags**

Require exact `libhttp`, existing `libssl`, and existing `tls_fixer_http.suprx`. Provider failure disables only TLS 1.3 injection, not existing module redirection.

- [ ] **Step 4: Inject after successful `libhttp` load**

After `TAI_CONTINUE` returns a nonnegative module ID for the redirected `libhttp`, call `ksceKernelLoadStartModuleForPid` with `TlsFixerStartArgs`. Use a recursion guard and prevent duplicate provider injection for the same immediate load path.

- [ ] **Step 5: Preserve 3.60 DNS-fix behavior**

Retain the current `np_commerce2`/`old_dns_fix` load order and verify that the new provider branch cannot alter its conditions.

- [ ] **Step 6: Build kernel plugin with strict warnings**

Add `SceKernelUtilsForDriver_stub` and compile with `-Wall -Wextra -Werror` after resolving all warnings in touched code.

- [ ] **Step 7: Commit loader integration**

```bash
git add kernel

git commit -m "tls13: inject provider for exact libhttp"
```

## Task 9: Package and Install the Provider

**Files:**
- Modify: `main.c`
- Modify: `Makefile`
- Modify: `README.md`

- [ ] **Step 1: Add provider file installation**

Copy `app0:tls_fixer_http.suprx` to `vs0:/data/external/tls_fixer/tls_fixer_http.suprx` with the HTTP/SSL package. Remove it on the corresponding uninstall path.

- [ ] **Step 2: Make copy failures observable**

The existing file-copy helpers ignore open, allocation, read, and write failures. Replace them with bounded buffered copies returning real errors, and abort reboot/install success reporting on failure.

- [ ] **Step 3: Build provider before VPK packaging**

Add dependencies so `make` builds kernel, DNS fix, provider, and installer before `vita-pack-vpk`. Package the provider at the expected app path.

- [ ] **Step 4: Preserve existing installations**

Detection logic must distinguish legacy TLS 1.2 installation from TLS 1.3-complete installation and offer repair/install rather than treating a missing provider as fully installed.

- [ ] **Step 5: Document scope and fallback**

State that TLS 1.3 applies to the exact bundled `SceLibHttp` HTTPS path; unknown modules remain on BSAFE TLS 1.2. Mark real-hardware validation status explicitly.

- [ ] **Step 6: Commit packaging**

```bash
git add main.c Makefile README.md

git commit -m "tls13: package and install provider"
```

## Task 10: End-to-End Build and Static Verification

**Files:**
- Modify as required by build findings.
- Update: `TLS13_PROGRESS.md`

- [ ] **Step 1: Run host tests**

Run normal and sanitizer CTest suites. Record compiler, test count, and output.

- [ ] **Step 2: Run exact binary validation**

Validate the descriptor against the unpacked ELF and compressed repository SELF.

- [ ] **Step 3: Build all Vita artifacts**

Use the cached hard-float VitaSDK image and perform a clean build. Do not use the soft-float image.

- [ ] **Step 4: Inspect outputs**

Record sizes, SHA-256 hashes, ELF attributes, imports, exports, and VPK contents for:

- `tls_fixer.skprx`;
- `tls_fixer_http.suprx`;
- installer `eboot.bin`;
- final VPK.

- [ ] **Step 5: Check licenses and notices**

Ensure Mbed TLS Apache-2.0 notice requirements are satisfied by repository documentation/package metadata.

- [ ] **Step 6: Review fail-open paths**

Statically verify that unknown hash, absent provider, provider start failure, gate failure, and partial hook failure all retain the original BSAFE path.

- [ ] **Step 7: Update persistent progress**

Record exact commands/results, remaining hardware-only validation, produced artifact hashes, and all implementation limitations in `TLS13_PROGRESS.md`.

- [ ] **Step 8: Show and review the complete diff**

Use the project diff tool once after all related changes. Check for generated files, reverse-engineering databases, secrets, accidental proprietary SDK content, and unrelated changes.

- [ ] **Step 9: Commit verified implementation**

```bash
git add -A
git commit -m "feat: add TLS 1.3 browser transport"
```

Do not push or open a pull request unless the user explicitly requests it.

## Task 11: Real-Hardware Validation Protocol

**Files:**
- Create: `docs/tls13-hardware-validation.md`
- Update after hardware runs: `TLS13_PROGRESS.md`

- [ ] **Step 1: Define controlled endpoints**

Specify TLS-1.3-only, TLS-1.2-only, invalid-chain, wrong-hostname, expired, slow-handshake, abrupt-EOF, close-notify, redirect, and proxy endpoints. Record expected browser-visible and API results.

- [ ] **Step 2: Add provider diagnostics**

Use bounded debug logging that records PID, module gate result, connection lifecycle, negotiated version/cipher, provider error, Sony error, and detail without logging traffic, secrets, or certificate private data.

- [ ] **Step 3: Validate process coverage**

Record which browser/WebKit processes load `libhttp` and receive the provider. Verify duplicate loads do not install duplicate hooks.

- [ ] **Step 4: Validate transport behavior**

Test TLS 1.3, TLS 1.2 fallback, nonblocking retries, timeouts, abort, redirects, connection reuse, and repeated browser launches.

- [ ] **Step 5: Validate certificate compatibility**

Exercise the public callback and every wrapped `sceSslGet*` function against provider and legacy BSAFE certificates.

- [ ] **Step 6: Measure resources**

Record provider code/data size, process memory increase, peak handshake allocation, latency, and repeated-connection stability.

- [ ] **Step 7: Promote validation status**

Only after evidence is captured may README wording change from “build-complete, hardware validation required” to “TLS 1.3 validated on hardware.”
