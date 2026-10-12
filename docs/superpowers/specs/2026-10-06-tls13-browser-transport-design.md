# TLS 1.3 Browser Transport Design

## Status

Historical design for the `SceLibHttp` adapter, revised on 2026-10-07. The six libhttp hooks do not intercept the browser's separate libcurl/OpenSSL backend. Its implemented extension is specified in `docs/tls13-browser-path.md` and `tls13/browser/`; this historical document must be read together with that extension.

### Controlling revision: 2026-10-07

The following decisions supersede inconsistent statements in the initial design below:

- Engine: checksum-pinned **Mbed TLS 4.2.0 / TF-PSA-Crypto 1.2.0**, source-built with the provider's exact configuration. No VitaSDK-prebuilt Mbed TLS ABI or CRT/pthread shim dependencies remain.
- Platform: explicit PSA initialization, 64-byte-bounded Vita kernel entropy requests, Vita mutex/condition ALT callbacks, monotonic milliseconds and 64-bit UTC. CA parsing uses bounded SceIo reads.
- Scope: both `SceHttp` and default-browser transports are implemented and exercised natively, with separate exact-module gates and error models. Host socket tests do not validate device injection or hooks.
- Callback acceptance: negative application results reject; invalid-certificate acceptance additionally obeys Sony's recovered post-callback process/version/system-parameter policy, encoded in `cert_policy.c` and bound to the exact module's existing import veneers.
- Certificate lifetime: borrowed certificates expire when the callback returns. Subject/issuer names are independently copied and live until explicitly freed. Their generation-tagged handles cannot alias a later allocation in the same callback.
- Lifetime: registry cleanup remains counted until destruction finishes. An owned/retiring connection never silently selects the legacy engine because its operation lock is busy. Reentrant callbacks receive a provider retry rather than deadlocking.
- Write retries: a connection-owned 1500-byte buffer preserves arguments across WANT results. Changed retry data is rejected. Incoming TLS 1.3 ticket notifications are handled without discarding application data.
- Unload: the activated provider is resident until process exit. Hot unload is rejected; an empty registry is insufficient proof that no thread is entering a hook or executing a continuation. Startup rollback remains supported.
- Verification: the native suite executes production transport, crypto-platform, trust-store and certificate-hook code against real TLS 1.2/1.3 loopback servers. It mocks only the Vita/taiHEN surface; no Vita runtime success is claimed.

The remainder preserves the original design rationale and planned steps. Current code, this revision, and the later sections of `TLS13_PROGRESS.md` take precedence over the old 3.6.5/configuration, name-lifetime, hot-unload and browser-routing assumptions.

## Problem Statement

Applications using Sony's `SceHttp` stack negotiate HTTPS through a statically integrated RSA BSAFE MES 3.2.1 / SSL-C 2.8.1 engine in `libssl.suprx`. The repository bundles Sony's later 3.73 `libhttp.suprx` and `libssl.suprx`, which add TLS 1.2 but not TLS 1.3. The browser's separately embedded TLS backend must be handled independently.

Reimplementing all of `SceHttp` would discard substantial working behavior. Reimplementing the entire private `SceSslInternal` ABI would couple the project to dozens of BSAFE object operations that are irrelevant to browser transport. Patching the existing BSAFE record and handshake implementation into TLS 1.3 would effectively require replacing its protocol engine in place.

The first deliverable is therefore narrowly defined:

> Add TLS 1.2/1.3 client transport to HTTPS requests made through the exact 3.73 `libhttp.suprx` distributed by tls_fixer, while preserving Sony's HTTP state machine and retaining the existing BSAFE path as a fail-open compatibility fallback.

This is not a general TLS 1.3 implementation of every public or private Vita SSL API.

## Binary Facts and Compatibility Boundary

The exact replacement `libhttp.suprx` has compressed SHA-256:

```text
42bc7e34077964ac7edc4365abad8af9bf41793a34d2c7efd631976f7d2739c1
```

Its unpacked first executable segment has:

```text
virtual address: 0x81000000 in the analysis image
file size:       0x1D150
memory size:     0x1D150
permissions:     R-X
```

The six transport functions are located at offsets from executable segment zero:

| Function | Offset | Recovered prototype |
| --- | ---: | --- |
| Create provider session | `0x8130` | `int create(void *request, int socket)` |
| Drive handshake | `0x8362` | `int connect(void *request)` |
| Classify legacy I/O result | `0x85FE` | `int map_io(void *connection, int result)` |
| Read TLS application data | `0x869C` | `int read(void *connection, void *buffer, unsigned int length)` |
| Write TLS application data | `0x86F4` | `int write(void *connection, const void *buffer, unsigned int length)` |
| Close and destroy session | `0x874C` | `int shutdown(void *connection)` |

The request object resolves its active connection by reading pointer offset `0x134` and falling back to pointer offset `0x130`. The relevant connection layout is stable between the annotated 3.60 binary and the exact 3.73 binary:

| Offset | Meaning used by this design |
| ---: | --- |
| `0x14` | Sony connection state |
| `0x1C` | HTTPS mode marker |
| `0x24` | socket descriptor in the Sony connection object |
| `0x40` | legacy BSAFE SSL/session pointer |
| `0x44` | legacy BSAFE context pointer |
| `0x48` | hostname string used by Sony's own SAN/CN verifier |
| `0x60` | legacy callback/BIO metadata pointer |
| `0x104` | application `SceHttpsCallback` |
| `0x108` | application callback user argument |
| `0x114` | Sony allocator context |
| `0x118` | Sony free/pool context |
| `0x138` | connection TLS mode/options selector |
| `0x160` | stored HTTPS error returned by `sceHttpsGetSslError` |
| `0x164` | stored error detail returned by `sceHttpsGetSslError` |

Provider-owned objects must not be placed in the legacy BSAFE fields. They are unknown-layout Sony objects and other code assumes BSAFE semantics. The provider instead owns an external registry keyed by the resolved Sony connection pointer.

## Chosen Architecture

```text
Browser / application
        |
        v
exact bundled Sony libhttp.suprx
        |
        | six offset hooks
        v
tls_fixer_http.suprx user provider
        |
        v
Mbed TLS 3.6.5 client engine
        |
        v
sceNetSend / sceNetRecv
```

The existing `libssl.suprx` remains loaded. It continues to satisfy imports, serves all unhooked users, and provides the legacy fallback path when the provider is not active for a connection.

### Rejected Alternatives

#### Full `SceSslInternal` compatibility facade

This would need to reproduce a broad BSAFE object model, error stack, certificate store, BIO behavior, method tables, and private ownership rules before a browser request could work. It is substantially larger than the browser transport boundary and has more unknown semantics.

#### Replace `libhttp`

Sony's module already provides URL parsing, proxies, redirects, authentication, cookies, gzip, request sequencing, connection reuse, timeout handling, and the public `SceHttp` ABI. Replacing it would create a much larger compatibility project.

#### Patch BSAFE to implement TLS 1.3

TLS 1.3 changes the handshake transcript, key schedule, record protection transition, cipher-suite model, resumption, certificate authentication, and state machine. Retrofitting those changes into stripped SSL-C code is less defensible than substituting a modern engine at the established transport boundary.

#### Proprietary MES 5.0 or TLS-C

Neither is redistributable open source, and neither is ABI-compatible with Vita's private SSL-C 2.8.1 integration merely because of BSAFE lineage.

## Components

### 1. Kernel Loader Extension

The existing kernel plugin remains responsible for replacing Sony module paths. It gains four responsibilities:

1. Verify the installed replacement `libhttp.suprx` against the known compressed SHA-256 using `SceKernelUtilsForDriver` SHA-256 APIs.
2. Track whether `tls_fixer_http.suprx` exists and whether exact TLS 1.3 activation is permitted.
3. After the original module-loader call successfully loads the redirected `libhttp.suprx`, inject `tls_fixer_http.suprx` into the same PID with `ksceKernelLoadStartModuleForPid`.
4. Pass a versioned start-argument structure containing a magic value, ABI version, and the newly loaded `libhttp` module ID.

The injection is performed after `TAI_CONTINUE` returns. Loading the provider recurses through the loader hook but cannot re-enter the `libhttp` branch because its path is distinct. A per-thread or global recursion guard remains prudent for defensive containment, but a worker thread is not required by the current evidence.

Failure to hash, locate, or load the provider must not prevent `libhttp` or the existing BSAFE TLS 1.2 path from loading.

### 2. User Provider Module

`tls_fixer_http.suprx` receives the exact `libhttp` module ID. Before installing a hook, it must:

- validate the start-argument magic and version;
- call `sceKernelGetModuleInfo` for the supplied module ID;
- verify the module name is `SceLibHttp`;
- verify executable segment zero is at least `0x1D150` bytes;
- compare masked invariant bytes at all six hook offsets;
- initialize process-global provider state;
- install every hook transactionally.

If validation or initialization fails, the provider returns without installing hooks. If hook installation fails partway through, it releases every hook already installed. No mixed provider/BSAFE hook set is allowed.

The module remains resident only after successful activation. Its stop path releases hooks, destroys all provider connections, frees the trust store and PRNG state, and deletes synchronization primitives.

### 3. Module Identity Gate

The gate has two layers because neither layer is sufficient alone:

- **On-disk exact hash in the kernel plugin.** This proves the installer-selected SELF artifact is the supported file before redirection/injection is enabled.
- **Runtime shape and masked code bytes in the provider.** This proves the supplied module ID and mapped code match the expected hook boundary before code is modified.

Hashing mapped text is deliberately avoided: loader relocations and import processing can legitimately change bytes. The runtime gate uses function-entry masks derived from the exact binary and excludes relocation-sensitive operands.

### 4. Connection Registry

The registry maps a Sony connection pointer to one provider-owned connection object. It is protected by a Vita lightweight mutex and exposes a small API:

```c
int tls_fixer_registry_init(void);
void tls_fixer_registry_destroy(void);
TlsFixerConnection *tls_fixer_registry_create(void *sony_connection, int socket);
TlsFixerConnection *tls_fixer_registry_acquire(void *sony_connection);
void tls_fixer_registry_release(TlsFixerConnection *connection);
int tls_fixer_registry_remove(void *sony_connection, TlsFixerConnection **removed);
```

Each slot has explicit states and a generation counter. Removal prevents new acquisitions and waits only for bounded in-flight references. The registry must tolerate duplicate shutdown, create failure, and stale Sony pointers without double-freeing Mbed TLS objects.

The initial capacity is fixed and compile-time bounded. This makes allocation behavior predictable and gives the host tests deterministic exhaustion cases. The capacity can be raised after hardware observation without changing the interface.

### 5. Provider Connection Object

A provider connection contains:

- Sony connection pointer;
- socket descriptor;
- copied hostname;
- lifecycle state;
- Mbed TLS SSL context;
- per-connection Mbed TLS configuration;
- last Mbed TLS error;
- last raw network error;
- translated Sony HTTPS error and detail mask;
- close-notify state;
- reference/removal metadata;
- certificate wrapper bookkeeping needed while invoking an application callback.

Mbed TLS structures are initialized and freed in a single owner routine so partially initialized connections can always be unwound safely.

### 6. Process-Global TLS State

The provider initializes once per process:

- `mbedtls_x509_crt` trust chain;
- `mbedtls_entropy_context`;
- `mbedtls_ctr_drbg_context`;
- registry mutex and storage;
- certificate-wrapper hook state;
- six `libhttp` hook references.

The CA bundle is loaded from:

```text
vs0:/data/external/cert/CA_LIST.cer
```

It is an ordinary PEM bundle. Parsing is done once at provider start. Failure to parse all roots is fatal to provider activation; silently proceeding with an empty trust store would turn a compatibility failure into a security failure.

The DRBG personalization string includes a fixed provider label and process identity. Entropy uses the platform entropy support available to the VitaSDK Mbed TLS build; any missing platform hook is treated as provider-initialization failure, not replaced with predictable input.

### 7. Mbed TLS Configuration

The first implementation links against the hard-float VitaSDK Mbed TLS 3.6.5 archives and enforces that version at compile time.

Each connection is configured as:

- client endpoint;
- stream transport;
- preset default;
- minimum TLS 1.2;
- maximum TLS 1.3;
- required certificate verification by default;
- process-global CA chain;
- process-global CTR-DRBG callback;
- custom send/receive callbacks using the existing socket;
- hostname via `mbedtls_ssl_set_hostname`, which supplies both SNI and hostname verification.

The packaged configuration already contains TLS 1.3 client code. The initial build intentionally uses that known configuration. A source-built, reduced configuration is deferred until the functional build has measured code size, RAM, and compatibility.

### 8. Socket BIO Adapter

The send callback calls `sceNetSend`; the receive callback calls `sceNetRecv`.

Mappings are directional:

| Vita result | Mbed TLS callback result |
| --- | --- |
| positive byte count | same byte count |
| zero receive | zero / EOF |
| `SCE_NET_ERROR_EAGAIN` on receive | `MBEDTLS_ERR_SSL_WANT_READ` |
| `SCE_NET_ERROR_EAGAIN` on send | `MBEDTLS_ERR_SSL_WANT_WRITE` |
| interrupted operation where retry is valid | corresponding WANT result |
| connection reset | `MBEDTLS_ERR_NET_CONN_RESET` |
| other receive failure | `MBEDTLS_ERR_NET_RECV_FAILED` |
| other send failure | `MBEDTLS_ERR_NET_SEND_FAILED` |

The raw Vita result is retained in the provider connection before returning a generic Mbed TLS network error. This preserves diagnostic detail for `sceHttpsGetSslError`.

The callbacks do not change blocking mode or socket timeouts. Sony's HTTP layer already owns those policies.

## Hook Semantics

### Create Hook

1. Resolve the actual connection pointer from request offsets `0x134` and `0x130`.
2. If provider global state is unavailable, call the original function.
3. If a provider entry already exists, reject the duplicate safely or remove only a provably dead entry.
4. Read and copy the hostname from connection offset `0x48`.
5. Create the registry entry and initialize Mbed TLS objects.
6. Configure the socket, trust store, authentication mode, and hostname.
7. Return zero on success.

If setup fails before any TLS bytes are sent, remove the entry and call the original create function. That preserves TLS 1.2 service instead of turning local provider resource failure into an outage.

### Connect/Handshake Hook

1. Resolve the actual connection pointer.
2. If no provider entry exists, call the original function.
3. Drive `mbedtls_ssl_handshake`.
4. On WANT_READ or WANT_WRITE, return `SCE_HTTP_ERROR_EAGAIN` and preserve state.
5. On success, verify the Mbed TLS verification result, store the negotiated version/cipher for diagnostics, and return zero.
6. On verification failure, translate certificate detail bits, optionally invoke the application callback, and either accept or fail according to the callback result.
7. On fatal failure, store `SCE_HTTPS_ERROR_HANDSHAKE` or `SCE_HTTPS_ERROR_CERT`, store detail, and return `SCE_HTTP_ERROR_SSL`.

Once a provider handshake emits bytes, failure never falls back to BSAFE on the same socket.

### Read Hook

1. Look up the provider entry; otherwise call the original function.
2. Limit one engine call to 1500 bytes to retain Sony's observed wrapper behavior.
3. Call `mbedtls_ssl_read`.
4. Return positive data directly.
5. Return `SCE_HTTP_ERROR_EAGAIN` for WANT_READ or WANT_WRITE.
6. Return zero for close-notify.
7. Translate raw EOF, reset, alert, timeout, and internal failures to stored `SCE_HTTPS_ERROR_IO` plus detail, then return `SCE_HTTP_ERROR_SSL`.

### Write Hook

The write hook mirrors read semantics, including the 1500-byte cap, partial positive writes, and WANT_READ/WANT_WRITE mapping to `SCE_HTTP_ERROR_EAGAIN`.

### Legacy I/O Mapper Hook

The provider does not require Sony's BSAFE `SSL_get_error` classifier for provider-owned connections. The map hook remains installed to preserve a coherent boundary and returns provider state only when a matching connection exists; otherwise it calls the original function.

Where read/write hooks already return final Sony results, map hook behavior must be idempotent and must not overwrite provider diagnostics.

### Shutdown Hook

1. If no provider entry exists, call the original function.
2. Atomically remove the entry from the registry so no new operation can acquire it.
3. Attempt `mbedtls_ssl_close_notify` once; WANT results are not allowed to stall Sony teardown.
4. Free per-connection wrappers and Mbed TLS objects.
5. Return zero.

Repeated shutdown is harmless. The socket remains owned and closed by Sony's HTTP layer.

## Error Contract

Public constants come from Sony's 3.570 SDK headers.

```c
#define TLS_FIXER_SCE_NET_EAGAIN          ((int)0x80410123)
#define TLS_FIXER_SCE_HTTP_ERROR_SSL      ((int)0x80431075)
#define TLS_FIXER_SCE_HTTP_ERROR_EAGAIN   ((int)0x80431082)
#define TLS_FIXER_SCE_HTTP_ERROR_TIMEOUT  ((int)0x80431068)
#define TLS_FIXER_SCE_HTTP_ERROR_NOMEM    ((int)0x80431022)
#define TLS_FIXER_SCE_HTTPS_ERROR_CERT    ((int)0x80435060)
#define TLS_FIXER_SCE_HTTPS_ERROR_HANDSHAKE ((int)0x80435061)
#define TLS_FIXER_SCE_HTTPS_ERROR_IO      ((int)0x80435062)
#define TLS_FIXER_SCE_HTTPS_ERROR_INTERNAL ((int)0x80435063)
```

The provider stores the public HTTPS error at connection offset `0x160` and the detail at `0x164`. `sceHttpsGetSslError` reads those fields and leaves already-public values unchanged.

Certificate detail translation targets:

- internal failure: `0x01`;
- malformed/untrusted certificate: `0x02`;
- hostname mismatch: `0x04`;
- expired: `0x08`;
- not yet valid: `0x10`;
- unknown CA: `0x20`.

Multiple conditions are ORed. Mbed TLS errors not representable in this mask are retained as provider diagnostics but reported publicly as internal, handshake, or I/O failure according to phase.

## HTTPS Options

Sony permits six verification flags. The provider reads the effective connection flags established by `libhttp`; it does not bypass the public option API.

The default is required verification. Disabling verification checks through Sony APIs must be reproduced only where the existing binary permits it. Firmware policy may reject disabling specific checks for non-system applications; the provider must not create a new bypass around those restrictions.

The exact effective flag field is validated during implementation. Until proven, provider activation uses secure defaults rather than inferring that a zero or unknown field means verification disabled.

## Application Certificate Callback Compatibility

Sony stores the callback function and user argument at connection offsets `0x104` and `0x108`. The callback receives:

```c
int callback(
    unsigned int verify_error,
    SceSslCert *const certificates[],
    int certificate_count,
    void *user_arg);
```

The provider invokes this callback only when configured and only after constructing a stable peer-chain view.

### Certificate Wrappers

A provider certificate wrapper contains a magic/version tag and a pointer to one Mbed TLS certificate in the retained peer chain. A provider certificate-name wrapper contains a separate magic/version tag, wrapper ownership, and subject/issuer selection.

The provider hooks the public certificate inspection exports used by callbacks:

- `sceSslGetSerialNumber`;
- `sceSslGetSubjectName`;
- `sceSslGetIssuerName`;
- `sceSslGetNotBefore`;
- `sceSslGetNotAfter`;
- `sceSslGetNameEntryCount`;
- `sceSslGetNameEntryInfo`;
- `sceSslFreeSslCertName`.

Each hook recognizes the provider magic. Provider objects are served from Mbed TLS data; all other pointers are forwarded through `TAI_CONTINUE` to the original BSAFE implementation.

Wrappers are valid only for the duration of the application callback. Name wrappers allocated during the callback remain tracked until explicitly freed or until callback teardown, whichever comes first. A stale wrapper is rejected rather than dereferenced.

### Callback Result

The callback's observed Sony convention must be preserved: a result accepting the chain allows the handshake to continue; rejection returns certificate failure. The exact accepted value is verified against the original main verification callback before enabling this path. Until verified, the provider does not reinterpret arbitrary nonzero values as acceptance.

## Lifetime and Concurrency

Sony may call create, handshake, read, write, and shutdown from different request-state iterations and potentially different threads. The design therefore separates:

- registry structural lock;
- per-connection operation lock;
- global trust/PRNG state, immutable after activation;
- certificate callback temporary state.

The registry lock is never held while calling Mbed TLS, network APIs, an application callback, or the original hooked function. This avoids lock inversion and callback reentrancy deadlocks.

Only one Mbed TLS operation may execute on a connection at a time. A concurrent operation receives a retry/error result consistent with Sony's existing state machine rather than racing the SSL context.

Provider stop marks global state as stopping, prevents new creates, removes all entries, waits for bounded references, then frees globals. Process termination may not run every cleanup callback; leaked process-local memory at final process destruction is preferable to dereferencing dead Sony objects.

## Installer Changes

The VPK adds `tls_fixer_http.suprx` and installs it as:

```text
vs0:/data/external/tls_fixer/tls_fixer_http.suprx
```

The full package and HTTP/SSL package options install it alongside `libhttp.suprx` and `libssl.suprx`. Uninstall removes it. The kernel plugin activates TLS 1.3 only when both the exact `libhttp` and provider files exist and the exact hash gate passes.

Existing installations without the provider continue using the current TLS 1.2 behavior.

## Build Structure

A new `tls13/` CMake subtree builds:

- host unit-test library containing platform-independent registry, error mapping, and module-mask logic;
- Vita user provider `tls_fixer_http.suprx`;
- optional standalone Vita TLS probe application when useful for separating engine/platform failures from hook failures.

The kernel CMake target adds `SceKernelUtilsForDriver_stub` for streaming SHA-256.

The provider links the hard-float VitaSDK libraries required by taiHEN, networking, threading, I/O, RTC/time, libc, and Mbed TLS. The build fails at compile time unless Mbed TLS reports version 3.6.5 for the initial implementation.

Generated binaries and reverse-engineering work files are not committed. Source, tests, build metadata, license notices, and reproducibility metadata are committed.

## Verification Strategy

### Host Tests

Host tests cover logic that does not require Vita binaries or hardware:

- registry creation, lookup, exhaustion, removal, and duplicate operations;
- generation/stale-handle behavior;
- partial connection initialization cleanup;
- Mbed TLS-to-Sony error mapping;
- Mbed TLS verification flag-to-Sony detail mapping;
- module-mask positive, mismatch, truncation, and wrong-offset cases;
- request-to-connection pointer resolution;
- callback-wrapper magic and lifetime checks;
- repeated shutdown and rollback behavior.

### Build-Time Validation

The build verifies:

- hard-float compiler target;
- Mbed TLS 3.6.5 compile-time version;
- TLS 1.3 configuration macro;
- provider exports/module metadata;
- no unresolved imports;
- expected SELF/VPK artifacts;
- final binary sizes.

### Static Binary Validation

A repository script extracts or reads the supported `libhttp` payload and confirms:

- compressed SHA-256;
- executable segment size;
- all six masked signatures at exact offsets;
- signatures are unique in the text segment.

### Real-Hardware Validation

Hardware validation is required for claims concerning:

- provider injection in browser and WebKit processes;
- hook installation and release;
- TLS 1.3 negotiation against a controlled endpoint;
- TLS 1.2 fallback negotiation;
- SNI and hostname verification;
- certificate failure detail bits;
- nonblocking handshake/read/write behavior;
- request timeout and abort;
- redirects and connection reuse;
- application callbacks and certificate inspection;
- proxy behavior;
- process shutdown and repeated browser sessions;
- peak memory and performance.

No hardware-only behavior is reported as tested until captured on a Vita.

## Security Properties

- Provider activation is tied to one exact distributed `libhttp` artifact and validated mapped code.
- Verification remains required by default.
- CA parse failure fails provider activation rather than disabling verification.
- Application options are not allowed to bypass firmware policy.
- Entropy initialization failure fails provider activation.
- No foreign object is written into BSAFE-owned fields.
- No fallback occurs after provider TLS bytes are emitted on a socket.
- Partial hook installation is rolled back.
- Unknown binaries retain the existing TLS 1.2 implementation.

## Explicit Non-Goals for the First Implementation

- General TLS 1.3 support for consumers that bypass `SceHttp`.
- Full implementation of all private `SceSslInternal` NIDs.
- TLS servers or DTLS.
- QUIC or HTTP/2.
- Replacing Sony's HTTP parser/state machine.
- Matching proprietary BSAFE session-cache internals.
- Source-level integration of MES 5.0 or TLS-C.
- Reducing Mbed TLS to a custom minimal build before functional measurements exist.

## Success Criteria

The source implementation is complete when:

1. Host tests pass.
2. The hard-float VitaSDK image builds the kernel plugin, provider, installer, and VPK.
3. Static validation proves the expected exact `libhttp` boundary.
4. Provider failure leaves the existing TLS 1.2 path functional.
5. The code contains no claim of successful browser TLS 1.3 negotiation until real-hardware evidence exists.

The runtime feature is validated when a real Vita browser negotiates TLS 1.3 with a controlled endpoint, negotiates TLS 1.2 with a fallback endpoint, rejects invalid certificates with correct public diagnostics, and remains stable across nonblocking operations and repeated browser process lifecycles.
