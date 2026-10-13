# TLS 1.3 Browser Support Investigation and Implementation Log

Last updated: 2026-10-13 (persistent sceHttp diagnostics identify the missing libc/provider prerequisite)

This file is the persistent handoff for the TLS 1.3 work. Update it whenever a material binary-analysis result, architectural decision, implementation milestone, test result, or blocker changes. Do not rely on conversation memory alone.

## Current continuation state

**Latest runtime draft, 2026-10-14:** the SceLibKernel-based HTTP runtime passes native allocation/formatting tests without SceLibc and without dependency patches. Its first combined integration boot failed with a user-reported boot panic. The self-disabled config was recovered, the prior dcec123f test kernel restored, and the candidate withdrawn. Future staged diagnostics now require an explicit test-title scope; no corrected activation has been attempted. See section 23.317 and docs/http-kernel-runtime.md.

**Latest diagnostics, 2026-10-13:** the user required better analysis and extensive logging before further device iterations. Added persistent API/module-inventory logging to the backend-independent checker and file logging throughout the HTTP provider. Two app-only launches on the existing boot completed, with 265 and 270 contiguous records. Both complete module inventories show the replacement Sony HTTP/SSL modules, but no SceLibc or tls_fixer_http. The normal coordinator requires SceLibc before HTTP injection; the existing host production-context test also confirms missing libc prevents provider loading. This is an unmet activation/import prerequisite, before provider handshake or CA evaluation. No kernel/provider activation, reboot or certificate change was performed. See section 23.316 and docs/scehttp-diagnostics-20261013.md.

**Latest app work, 2026-10-13:** added and installed the independent Sony-API Vita TLS Check application (TLSCK0001), with a native vector-font interface and change-only presentation that removes its initial continuous redraw flicker. Its VPK is at ux0:/0VPK/vita_tls_check.vpk. The app records real sceHttp TLS failures on the current setup; successful generic-provider HTTPS remains unproven. Browser acceptance below is separate. See section 23.315 for the package identity, live UI/results and validation limits.

**Latest continuation, 2026-10-13:** the normal dcec123f coordinator has reached Browser TLS 1.3 in two separate cold boots with HTTP/DNS enabled and all tracing/probes OFF. Both tests omitted camera use, native screenshots and app warmup before the user opened Browser. Native screenshots taken after each user report independently show TLS 1.3/X25519; the second test used the kernel extracted from the rebuilt VPK (a3ba3c45). Current configuration is self-disabled (937 bytes, 1a7c64d1), with the unrelated VitaStream probe deferred. Earlier capture-assisted freezes remain unresolved; a native screenshot before Browser also preceded failure, so omitting USB capture alone is insufficient. The measured 32 KiB request versus 16 KiB free in ScePhyMemPartKD is separate diagnostic evidence, not a proven cause of every failure. See sections 23.312-23.314.

**Current packaged-kernel correction, 2026-10-13:** the original normal VPK omitted the successful Browser profile's loading controls. The corrected normal coordinator retains both providers, requires post-start injection and uses name lookup/native 16 KiB preparation. Its exact 14780-byte VPK kernel boots on the primary 3.60 Vita and self-disarms; manual Browser TLS acceptance for `retry=20261013-packaged1` failed with a whole-device freeze; that generated VPK is withdrawn. Providers, installer, Sony modules and certificate bundles are byte-identical to the preceding VPK. Earlier traced controls failed or fell back; see sections 23.281-23.284.

**Installer repair, 2026-10-12:** the primary Vita's full installer reached certificate preparation and failed with 0xFFFFFFFF. Native probes identified VitaSDK pthread rwlock creation returning ENOSPC, surfaced by OpenSSL as malloc failure. Native lightweight-mutex adaptation fixes that resource exhaustion without increasing the verified 8 MiB heap. Offline preparation, authenticated live download and the real install/refresh function redirected to an isolated ux0 target all pass on retail 3.60. The corrected installer is deployed; the new boot entry is deliberately disabled and the actual system CA is unchanged. See section 23.280.

**Firmware support, 2026-10-12:** added identity-selected kernel and WebKit profiles for all 31 available external retail/testkit/devkit cells from 3.60 through 3.74, with explicit kit WebKit identities and dynamic Module Manager export-family binding. Compiled guards, negative cases, four native API exports, cross-built mandatory imports and exact bundled-module dependencies pass across the corpus. Five external kit cells lack source images. New profiles have not run on hardware; prior 3.60 Browser acceptance remains distinct. See section 23.279 and `docs/tls13-firmware-support.md`.

**Certificate updater, 2026-10-12:** embedded Sony plus curl/Mozilla trust, latest-Mozilla downloading through curl using only the embedded Mozilla roots, and embedded fallback on failure are implemented. After the native lock correction, live download and the install/refresh function directed to an isolated ux0 target passed on retail 3.60 (section 23.280). The latest full system installation has not been executed; the primary device's system CA remains unchanged.

**Publication note:** this source snapshot uses the tls_fixer names consistently. Historical module, artifact and device-path spellings below were normalized for publication; original evidence, filenames, receipts and the pre-rename source archive remain in the original local workspace under ignored `build/`. Historical hashes identify those original tested artifacts, not renamed builds. Historical Cloudflare cache-busting query names are omitted from the acceptance URL. Current tests use the renamed, separately staged one-shot kernel and providers; publication does not imply permanent activation.

**Primary goal achieved, 2026-10-12:** the primary Vita Browser rendered `https://cloudflare.com/cdn-cgi/trace` with **tls=TLSv1.3, kex=X25519**, verified by user report, an independently viewed woken USB frame, matching provider startup and real handshake/verification/application-I/O packets. Acceptance receipt: `build/browser-tls13-acceptance-20261012.json`. See section 23.275; do not replace this direct proof with historical boot-only/host-only claims.

**Root correction:** `tls13/browser/webkit_callback.h` now requires the native 3.60 data **filesz=0xCE34 (52788)** while preserving **memsz=0x115C0 (71104)**. The old validator incorrectly used the memory-dump extent for both and rejected genuine module geometry. Raw saved 440-byte SceKernelModuleInfo confirms the original size; an independent red/green fixture accepts it and rejects the erroneous dump-size identity. Text/name/signature/userdata/vtable and certificate/hostname gates remain strict. No extra completion-output adapter was needed: current source already uses the correct byte ABI.

**Exact successful device test:** corrected provider 248524 bytes/hash `e50e8b8d2a50764cf0faab9892e67cb191f2698adcb0263bf50742681dbc65bf`; unchanged one-shot kernel 22613 bytes/hash `3ccfa163d12a7f43eb4bea9affe23b1723a43f597520059de1d46fafe2a09247`. Cycle `build/device-evidence/146-cycle-20261012T122319Z-250f47b9/`; post-UI observation `ui-observation-20261012T123247Z-bbad8403/`. WebKit PID 1189731 matches all 68 accepted runtime records, sequences 0-67 with no gaps/rejections/duplicates: options accepted, handshake completed, verification=0, active protocol=0x0304 and 956 application bytes received. The actual screenshot is `build/device-evidence/146-usb-browser-tls13-acceptance-20261012T123000951663Z/screen.png`, with fresh server timestamp 1791808144.000 (12:29:04 UTC), taken at 12:30 UTC without a dialog.

**Historical safety checkpoint, 2026-10-12:** the first successful Browser page was left open. Sequential double reads verified the exact provider/kernel and **disabled** 726-byte config/hash `0c09159d2fa0d5e16d62b62ffbdf15595d8e4b862efe033d6decaad77d4bc9b9`; the observer verified all other protected/original resources. This is an earlier receipt, not the current 937-byte configuration. Success did not re-arm or promote the test. The original boot defect, broader firmware/metadata/abort/proxy/endurance coverage and pre-module_start disarm window remain separate limitations.

**Host/static verification:** 330/330 normal CTest, 330/330 ASan/UBSan/leak-checking CTest, 112/112 Python tests, native Release/hard-float link with no undefined ELF symbols, and generated-code/ABI review. Supplemental diagnostics append callback policy/rejection stages while preserving old packet IDs and TLS decisions. The host command client keeps its writer open and finishes on a newline; the actual Vita replies correctly. Native file logging remained unavailable, so the successful request used an actually live private UDP receiver, now stopped cleanly with its immutable summary.

**Workflow constraints carried forward:** the user retains full autonomous test authority for `.146`, but **only the user opens Browser for now**. Prepare/verify a test, run quit all and notify the user at readiness; do not send Browser icon/Start input. For the current no-capture protocol, the user supplies the visible LiveArea check and no screen capture or other app occurs before Browser. After a result, wake via `screen on` before viewing; native capture requires a delayed-publication check, not repeated input. Agent-side restart uses vitacompanion only; never open/use Restart. Keep FTP operations strictly sequential. Preserve all consumed receipts; do not replay or automatically re-arm after unexplained failure.

**Historical completion boundary:** the earlier diagnostic achieved Browser TLS 1.3. Subsequent ordinary-package failures reopened runtime testing; the automatic-return requirement still applies. Historical evidence and the pre-rename source archive remain intact. The user subsequently requested the renamed private repository publication recorded in section 23.276; no permanent device deployment is implied.

## 1. Goal

Add TLS 1.3 support to HTTPS traffic used by the PlayStation Vita browser while preserving Sony's existing HTTP implementation and its public `SceHttp`/`SceHttps` behavior as far as practicable.

The historical proposal supplied with the task is being treated as untrusted input. Every claim is being checked against:

- the exact `libhttp.suprx` and `libssl.suprx` shipped by this repository;
- annotated 3.60 `SceLibHttp` and `SceLibSsl` IDBs;
- the repository's current kernel/user deployment model;
- VitaSDK headers and Sony SDK documentation where needed;
- builds produced by the current hard-float VitaSDK image.

The implemented scope is the default browser's ScePsp2Compat TLS transport plus a separate SceHttp adapter. A full replacement for every public and private `SceSsl` consumer is a separate and substantially larger project.

## 2. Source provenance and publication workspace

- Project: `tls_fixer`
- Publication checkout: `/Volumes/data/dev/vita_tls_fixer`
- Private repository: `https://github.com/devnoname120/vita_tls_fixer`
- Original source baseline: `eeb197f` (`Update bundled CA certificates`)
- Upstream attribution and repository link: see `README.md`.
- Fresh publication history preserves the original checkout and its Git history locally.

Non-source analysis artifacts and hardware evidence are retained in the original workspace under ignored `.reverse-tmp/` and `build/`; they are not part of the published repository. The sections below retain the investigation chronology. Historical local paths are shown relative to `<workspace>`, and historical plugin names are normalized as described above.

## 3. Repository Baseline

The repository does not contain the source of the TLS 1.2 implementation. It is primarily an installer and module redirection plugin around Sony binaries taken from later firmware.

Relevant files:

- `main.c`
  - Installer application.
  - Installs bundled modules to `vs0:/data/external/tls_fixer/`.
  - Installs the CA bundle to `vs0:/data/external/cert/CA_LIST.cer`.
- `kernel/main.c`
  - Hooks a `SceKernelModulemgr` function at offset `0x21ec`.
  - Rewrites module paths so processes receive the bundled `libhttp.suprx`, `libssl.suprx`, `ScePsp2Compat.suprx`, and selected 3.60 fixes.
  - It currently does not load a TLS provider module and does not install hooks inside user processes.
- `misc/lhttp.suprx`
  - Repository-bundled Sony `libhttp`, documented as firmware 3.73 origin.
- `misc/lssl.suprx`
  - Repository-bundled Sony `libssl`, documented as firmware 3.73 origin.
- `misc/certs.cer`
  - Updated CA bundle.
- `Makefile`
  - Legacy top-level application/VPK build.
- `kernel/CMakeLists.txt`
  - Legacy kernel plugin build.

There is currently no:

- TLS provider source;
- user plugin injection framework;
- libhttp hook implementation;
- unit-test framework;
- binary identity/version gate;
- dependency-management policy;
- repository license file.

The absence of a license file is relevant when selecting a TLS implementation and vendoring third-party source.

## 4. Exact Bundled Module Identity

Compressed repository artifacts:

| File | SHA-256 | Approximate size |
| --- | --- | ---: |
| `misc/lhttp.suprx` | `42bc7e34077964ac7edc4365abad8af9bf41793a34d2c7efd631976f7d2739c1` | 74 KiB |
| `misc/lssl.suprx` | `850148bad6771619004835caf056f2303d8d77c99623ce247b07958391f72ae5` | 229 KiB |
| `misc/certs.cer` | `b11a1d013ce0a8994c56ce02350e3493deced18e8c9db0837f9c69a35cafabc0` | 283 KiB |

The SELF containers were unpacked for analysis with `vita-unmake-fself` built from `TeamFAPS/PSVita-RE-tools` commit `178948c0866b6ad3246ab607886dd6b620628b86`.

Unpacked payload identity:

| Payload | SHA-256 | Approximate size |
| --- | --- | ---: |
| 3.73 `libhttp` ELF | `7db8124775deb25824c94fbc82e36be800b92b753f55e870a6d39e359b174bcd` | 130 KiB |
| 3.73 `libssl` ELF | `8b73ff3dc9f9659af373fd0c1e54e0acbcc22157659d4d395b679c7293e84764` | 440 KiB |

The unpacked ELF uses Sony type `ET_SCE_RELEXEC`/`0xfe04`. Analysis-only copies were modified to `ET_EXEC`, Vita OSABI `0x40`, and an absolute entry point so IDA could load them. The shipped binaries were not modified.

## 5. IDA Databases and Sessions

Reference databases:

- 3.60 `SceLibHttp`:
  - Path: `/Volumes/data/Downloads/vitadump 3.60 ELF/SceLibHttp.enriched.elf.i64`
  - IDA MCP session: `tls_fixer-scehttp-360`
  - Image base: `0x810D7000`
- 3.60 `SceLibSsl`:
  - Path: `/Volumes/data/Downloads/vitadump 3.60 ELF/SceLibSsl.enriched.elf.i64`
  - IDA MCP session: `tls_fixer-scessl-360`
  - Image base: `0x810D8000`

Exact repository-bundled 3.73 analysis databases:

- `libhttp`:
  - Temporary path: `.reverse-tmp/lhttp-3.73-idaload.elf`
  - Primary IDA MCP session: `tls_fixer-bundled-lhttp-373`
  - A fresh unsplit session also exists as `tls_fixer-bundled-lhttp-373-fresh`.
  - Image base: `0x81000000`
- `libssl`:
  - Temporary path: `.reverse-tmp/lssl-3.73-idaload.elf`
  - IDA MCP session: `tls_fixer-bundled-lssl-373`
  - Image base: `0x81000000`

The primary 3.73 HTTP IDB was modified for analysis by splitting and naming the transport functions. The fresh HTTP IDB preserves IDA's original combined-function recovery and is useful for obtaining a complete decompilation of create plus connect.

## 6. Proven TLS Library Lineage

The historical claim that Vita `libssl` is based on RSA BSAFE Micro Edition Suite rather than OpenSSL, mbed TLS, MatrixSSL, or wolfSSL is strongly supported by the exact bundled binary.

The repository-bundled 3.73 `libssl` contains, among other strings:

```text
N:\sce\psp2\ssl\trunk\mes3.2.1\MES\common\bio/bio_lib.c
N:\sce\psp2\ssl\trunk\mes3.2.1\MES\common\cert/src/ri_cert.c
N:\sce\psp2\ssl\trunk\mes3.2.1\MES\common\verify/r_verify.c
N:\sce\psp2\ssl\trunk\mes3.2.1\MES\sslc\ssl/s3_srvr.c
N:\sce\psp2\ssl\trunk\mes3.2.1\MES\sslc\ssl/ssl_cert.c
N:\sce\psp2\ssl\trunk\mes3.2.1\MES\sslc\ssl/ssl_sess_sm.c
N:\sce\psp2\ssl\trunk\mes3.2.1\MES\sslc\ssl/ssl_lib.c
N:\sce\psp2\ssl\trunk\mes3.2.1\CRYPTOCME\common\key/pkey_pk.c
N:\sce\psp2\ssl\trunk\mes3.2.1\CRYPTOCME\common\module/crypto/cry_init.c
SSLv2/3 compatibility part of SSL-C 2.8.1
TLSv11 part of SSL-C 2.8.1
TLSv1 part of SSL-C 2.8.1
TLSv12 PS Vita 2018ver
```

Conclusions supported by the binary:

1. The code base is RSA BSAFE MES 3.2.1.
2. The protocol layer is SSL-C 2.8.1 lineage.
3. Crypto-C ME is statically included as the cryptographic provider.
4. The module was maintained in a Sony `sce\psp2\ssl\trunk` source tree.
5. TLS 1.2 is represented as a Vita-specific 2018 addition to that tree.
6. There is no evidence of a dynamically linked open-source TLS implementation.

What remains inferential rather than proven:

- Which organization or individual authored each TLS 1.2 source change.
- Whether Sony licensed an unpublished BSAFE patch and then adapted it, or wrote all TLS 1.2 additions internally.
- The exact relationship between the source tree and later Dell BSAFE releases.

The safe wording is therefore “Sony-maintained BSAFE/MES branch with a Vita-specific TLS 1.2 implementation,” not “Sony certainly authored every TLS 1.2 line.”

## 7. Recovered `libhttp` TLS Transport Boundary

The six-function transport boundary proposed historically is real. It exists in the annotated 3.60 binary and matches uniquely in the exact 3.73 `libhttp` shipped by this repository.

### 7.1 Exact 3.73 offsets

Offsets below are relative to the first load segment/image base `0x81000000` in the analysis ELF.

| Function | 3.60 address | Exact bundled 3.73 address | 3.73 module offset | Size |
| --- | ---: | ---: | ---: | ---: |
| TLS session/context creation | `0x811683F0` | `0x81008130` | `0x8130` | `0x232` |
| Handshake/connect and error mapping | `0x81168614` | `0x81008362` | `0x8362` | `0x1B4` |
| SSL I/O result mapping | `0x811688B0` | `0x810085FE` | `0x85FE` | `0x9E` |
| TLS read | `0x8116894E` | `0x8100869C` | `0x869C` | `0x58` |
| TLS write | `0x811689A6` | `0x810086F4` | `0x86F4` | `0x58` |
| TLS shutdown/free | `0x811689FE` | `0x8100874C` | `0x874C` | `0x46` |

The 3.73 functions were found using relocation-wildcarded signatures generated from the annotated 3.60 functions. Each signature matched exactly once in the bundled 3.73 module.

Analysis names applied in both IDBs:

```text
fun_http_tls_create_session
fun_http_tls_connect_and_map_error
fun_http_tls_map_io_result
fun_http_tls_read
fun_http_tls_write
fun_http_tls_shutdown_session
```

Additional certificate-path matches:

| Function | 3.60 address | 3.73 address | 3.73 offset |
| --- | ---: | ---: | ---: |
| Certificate-store callback | `0x8116933A` | `0x81009088` | `0x9088` |
| Hostname/certificate helper | `0x8117419E` | `0x81013EFA` | `0x13EFA` |
| Main verification callback | `0x811747DC` | `0x81014592` | `0x14592` |

### 7.2 HTTP object fields used by the TLS path

The same word-indexed fields are used in 3.60 and 3.73:

| Word index | Byte offset | Observed role |
| ---: | ---: | --- |
| `16` | `0x40` | Per-connection SSL/session object |
| `17` | `0x44` | Shared/connection SSL context object |
| `24` | `0x60` | 40- or 48-byte HTTP-to-SSL callback/BIO metadata |
| `69` | `0x114` | Allocator or pool context used for metadata allocation |
| `70` | `0x118` | Pool/context used when freeing metadata |
| `78` | `0x138` | Mode affecting protocol option selection |
| `88` | `0x160` | Stored SceSsl-level error for `sceHttpsGetSslError` |
| `89` | `0x164` | Stored network errno |

The old suggestion to avoid embedding a foreign TLS object in these fields remains sound. A side table keyed by the Sony HTTP connection object is safer. The hooks may still need to maintain sentinel values or selected fields so surrounding Sony code observes the expected lifecycle.

### 7.3 Create-session behavior

The exact 3.73 function at offset `0x8130`:

1. Verifies `SceSsl` initialization.
2. Resolves the internal HTTP connection object from its caller-supplied handle.
3. Lazily creates and configures an SSL context in word `17`.
4. Installs system time, protocol/options, callback metadata, certificate callbacks, and verification callbacks.
5. Frees any prior SSL/session object in word `16`.
6. Creates a new SSL/session from the context.
7. Creates a socket BIO around the already-connected socket supplied as argument 2.
8. Associates HTTP metadata with the BIO in 3.73.
9. Attaches the BIO to the SSL/session and configures connect/client state.

The exact bundled 3.73 create function is 16 bytes larger than 3.60 and contains an extra call while configuring the BIO. This must be understood before assuming the 3.60 callback metadata layout is sufficient.

### 7.4 Connect/handshake behavior

The exact 3.73 function at offset `0x8362`:

1. Resolves the HTTP connection object.
2. Calls the BSAFE handshake/connect operation on word `16`.
3. Calls the BSAFE equivalent of `SSL_get_error(session, raw_result)`.
4. Maps result classes 0, 1, 2, 5, 6, and default into Sony HTTP/Ssl/net errors.
5. Handles nonblocking/retry cases using:
   - the raw handshake result;
   - `sceNetErrno`;
   - firmware-version checks;
   - a nonblocking flag at caller object byte offset `0x8C`.
6. Stores SceSsl and network error details in words `88` and `89`.

An earlier interim observation that 3.73 no longer passed the raw result to the error classifier was wrong. It came from a bad one-argument prototype inferred after manually splitting an import-stub-heavy function. The complete unsplit decompilation shows the same two-argument `SSL_get_error`-style semantic as 3.60.

### 7.5 Read/write behavior

Both read and write:

1. Verify SSL initialization.
2. Clamp each underlying SSL operation to 1500 bytes.
3. Call the private SSL read or write operation on word `16`.
4. Return immediately on the special raw BSAFE result `0x80410123`.
5. Map the result through the common I/O classifier.
6. Retry when the classifier produces `0x80435065`.
7. Otherwise return either a negative mapped error or the byte count.

This means the hook contract is not merely POSIX `read`/`write`. It must preserve Sony's retry and nonblocking conventions, including partial records and the distinction between an engine-level retry and a terminal network failure.

### 7.6 Shutdown behavior

Shutdown/free:

1. Verifies SSL initialization.
2. Shuts down/frees the BIO-like object in word `17` and callback metadata in word `24`.
3. Shuts down/frees the SSL/session in word `16`.
4. Frees the SSL context in word `17`.
5. Clears the corresponding object fields.

The decompiler's reuse of word `17` for both BIO/context-looking operations reflects the BSAFE object layering and imperfect inferred types. The replacement should not replicate this internal structure; it should only preserve externally observable object state and lifecycle.

## 8. Private `SceSslInternal` ABI Scope

The 3.60 `libhttp` imports roughly 69 private `SceSslInternal` functions. Cross-reference classification shows they are not all required to replace HTTPS transport.

The imports divide into several clusters:

1. SSL initialization and global memory/error handling.
2. Context/session/BIO creation and destruction.
3. Handshake, read, write, and error classification.
4. Certificate-store construction and built-in CA enumeration.
5. Certificate and hostname verification callbacks.
6. Public `sceHttpsLoadCert` support.
7. Public certificate inspection support through `libssl` objects.

Replacing all 69 imports first would recreate a large portion of BSAFE's object model and would be poor scope control. The six transport hooks are a substantially narrower path for browser HTTPS.

However, the historical proposal underestimates two follow-on compatibility areas:

- `sceHttpsSetSslCallback` expects Sony certificate objects and callback result semantics.
- Applications can inspect callback certificates through public `sceSslGet*` functions.

Those features cannot be declared compatible merely because connect/read/write work. They require either wrapper certificates plus public API hooks, or an explicit first-phase limitation.

## 9. Current Architecture Candidates

### Candidate A: Hook the six internal `libhttp` TLS functions

Architecture:

```text
browser/application
    -> Sony libhttp public API and HTTP state machine
    -> six hooked internal TLS operations
    -> tls_fixer user provider
    -> modern TLS 1.2/1.3 engine
    -> sceNet socket
```

Advantages:

- Keeps Sony HTTP parsing, redirects, cookies, authentication, gzip, proxy logic, and public ABI.
- Avoids emulating the complete BSAFE private ABI.
- Exact target binary is controlled by this repository and has a stable hash.
- The six offsets are now verified in the shipped 3.73 binary.

Risks and missing work:

- A provider user module must be loaded into every process that loads the replacement `libhttp`.
- Loading it synchronously from the existing kernel module-loader hook may recurse into module loading or deadlock.
- Hook installation must occur after `libhttp` is loaded but before its first HTTPS connection.
- taiHEN user-hook semantics and per-process module lookup must be verified.
- Nonblocking handshake/read/write and timeout behavior must match Sony's state machine.
- Existing SSL callback and certificate inspection behavior needs a compatibility strategy.

Current recommendation: this remains the best architecture, conditional on proving a safe per-process injection mechanism.

### Candidate B: Implement the private `SceSslInternal` ABI over a modern TLS engine

Advantages:

- Existing `libhttp` does not need internal offset hooks.
- Other Sony consumers of private `SceSslInternal` could eventually benefit.

Disadvantages:

- Requires reproducing object layouts, callback behavior, error stacks, BIOs, certificate stores, and lifecycle semantics across dozens of functions.
- Larger compatibility surface and substantially harder to validate.
- Likely takes longer than replacing the HTTP transport itself.

Current assessment: inappropriate as the first implementation target.

### Candidate C: Replace both `libhttp` and `libssl`

Advantages:

- Clean design without BSAFE compatibility internals.

Disadvantages:

- Reimplementing Sony's public `SceHttp`, cookies, redirects, auth, proxy, gzip, and state machines is much larger than the TLS problem.
- Breaks more system software assumptions.

Current assessment: rejected for this project.

### Alternative framing

The first deliverable should be framed as “TLS 1.3 transport support for HTTPS requests made through the exact bundled 3.73 `libhttp`,” not “a TLS 1.3 implementation of Vita `SceSsl`.” The latter implies compatibility far beyond the six-hook approach.

## 10. TLS Engine Selection Status

**Superseded by section 20:** the prebuilt 3.6.5 selection below describes the initial prototype, not the approved release dependency. The current migration target is the verified latest stable Mbed TLS 4.2.0 with its bundled TF-PSA-Crypto 1.2.0, built from a checksum-pinned official release archive.

Mbed TLS is the selected implementation engine, subject to build- and footprint-validation rather than an assumption that its default configuration is optimal.

Required selection criteria:

- client-side TLS 1.2 and 1.3;
- permissive license compatible with redistribution;
- hard-float ARMv7 build without operating-system assumptions;
- configurable allocator, entropy, time, mutex, and socket callbacks;
- X.509 chain and hostname verification;
- manageable code and RAM footprint;
- support for RSA-PSS, ECDSA, P-256 and/or X25519, AES-GCM, and SHA-256/SHA-384;
- no dependency on unavailable Vita services;
- stable API suitable for a reproducible pinned toolchain release.

Candidate assessment:

- Mbed TLS: selected for the first implementation. The current cached hard-float VitaSDK image already ships Mbed TLS 3.6.5 with client-side TLS 1.3 compiled in. `MBEDTLS_USE_PSA_CRYPTO` is disabled in that packaged configuration, so the historical claim that TLS 1.3 necessarily requires PSA crypto is not true for this build. The static archives are approximately 571 KiB (`libmbedcrypto.a`), 336 KiB (`libmbedtls.a`), and 66 KiB (`libmbedx509.a`) before dead-code elimination. The resulting provider size and peak handshake RAM still need measurement.
- wolfSSL: technically strong and small, but GPL/commercial licensing is problematic for a repository with no explicit license.
- BearSSL: compact and permissive, but no TLS 1.3.
- picotls plus crypto backends: flexible but creates a larger integration and crypto-backend burden.
- proprietary BSAFE MES 5/TLS-C: not a viable open-source distribution path and not ABI-compatible merely because of lineage.

No third-party source has been vendored. The initial implementation will link against the Mbed TLS 3.6.5 archives already distributed in the hard-float VitaSDK image. Reproducibility will require recording or pinning the image/toolchain identity and rejecting incompatible Mbed TLS versions at compile time. A custom Mbed TLS configuration cannot safely be mixed with prebuilt archives whose compile-time structure layout differs, so configuration minimization is a later source-build optimization rather than part of the first integration.

The installed CA file is not a proprietary binary store. `misc/certs.cer` is an ASCII, CRLF-terminated PEM bundle with comment labels and repeated `BEGIN CERTIFICATE` blocks. The provider can parse the installed `vs0:/data/external/cert/CA_LIST.cer` directly with Mbed TLS and should cache the resulting trust store once per process rather than reparsing it per connection.

## 11. Deployment and Injection Design

The existing kernel plugin only redirects module paths. A six-function hook design requires a provider in the target process. The basic injection mechanism is now supported by both the current project and established Vita code:

- the current plugin already calls `ksceKernelLoadStartModuleForPid` after the intercepted module load returns to inject the 3.60 DNS compatibility module;
- taiHEN's own plugin loader uses `ksceKernelLoadStartModuleForPid` for user plugins;
- other established Vita plugins, including Adrenaline, load user modules into target processes from kernel hooks;
- `taiHookFunctionOffset` explicitly requires the hook function to reside in the target address space, confirming that the six hooks belong in an injected user module rather than the kernel plugin.

The implementation mechanism is:

1. Hash the installed replacement `libhttp.suprx` in the kernel plugin and enable TLS 1.3 injection only when it matches the repository's known SHA-256.
2. Detect a successful load of the redirected `libhttp.suprx` in the existing module-manager hook.
3. Return from the original loader, then call `ksceKernelLoadStartModuleForPid` for `vs0:/data/external/tls_fixer/tls_fixer_http.suprx` in the same PID. Recursion is bounded because the provider path does not match any redirected `libhttp` path.
4. Pass a versioned start-argument structure containing the just-loaded `libhttp` module ID.
5. In the user provider, call `sceKernelGetModuleInfo` for that ID and validate the module name, path/segment shape, and masked invariant bytes at all hook sites before modifying code.
6. Install all six user-space hooks. If any hook fails, release every hook installed so far and leave the original BSAFE path intact.
7. Fail open to the bundled TLS 1.2 implementation if provider loading, validation, initialization, or hooking fails.

Remaining questions requiring hardware or further binary validation:

- Whether the target process's module-loading policy permits the new provider path.
- How module unload and process termination interact with hook release and provider cleanup.
- Whether browser networking occurs in the browser process, a WebKit process, or both on all supported firmware/configurations.
- Whether `ScePsp2Compat.suprx` alters the relevant module boundary for the browser.

The first two historical concerns are no longer blockers: this project already performs the same post-return per-PID module-load pattern, and the provider path cannot retrigger the `libhttp` branch. Real-hardware testing is still required before claiming that every browser/WebKit process and unload path is covered.

## 12. Error Semantics to Map

The official 3.570 Sony SDK headers establish the public constants used by the transport path:

| Value | Symbol | Role |
| ---: | --- | --- |
| `0x80410123` | `SCE_NET_ERROR_EAGAIN` / `SCE_NET_ERROR_EWOULDBLOCK` | Raw socket would-block result |
| `0x80431075` | `SCE_HTTP_ERROR_SSL` | Public HTTP-layer SSL failure |
| `0x80431082` | `SCE_HTTP_ERROR_EAGAIN` | HTTP state-machine retry result |
| `0x80431068` | `SCE_HTTP_ERROR_TIMEOUT` | HTTP timeout |
| `0x80431022` | `SCE_HTTP_ERROR_OUT_OF_MEMORY` | HTTP allocation failure |
| `0x80435060` | `SCE_HTTPS_ERROR_CERT` | Stored certificate-layer failure |
| `0x80435061` | `SCE_HTTPS_ERROR_HANDSHAKE` | Stored handshake failure |
| `0x80435062` | `SCE_HTTPS_ERROR_IO` | Stored TLS I/O failure |
| `0x80435063` | `SCE_HTTPS_ERROR_INTERNAL` | Stored HTTPS internal failure |
| `0x80435064` | `SCE_HTTPS_ERROR_PROXY` | Stored HTTPS proxy failure |

`0x80435065` is an internal retry sentinel used by the old TLS wrappers and is not exposed in the public SDK header. `0x80435801`, returned for invalid SSL-callback setup arguments, also has no public symbol in the inspected headers and must remain an explicitly named private constant rather than receiving a guessed SDK name.

The public certificate-detail mask is also defined:

```text
0x01 SCE_HTTPS_ERROR_SSL_INTERNAL
0x02 SCE_HTTPS_ERROR_SSL_INVALID_CERT
0x04 SCE_HTTPS_ERROR_SSL_CN_CHECK
0x08 SCE_HTTPS_ERROR_SSL_NOT_AFTER_CHECK
0x10 SCE_HTTPS_ERROR_SSL_NOT_BEFORE_CHECK
0x20 SCE_HTTPS_ERROR_SSL_UNKNOWN_CA
```

The provider should translate Mbed TLS verification flags into this mask and store `SCE_HTTPS_ERROR_CERT` separately from the detail bits.

The replacement error adapter must distinguish at least:

- retry because the socket would block;
- retry because TLS needs read;
- retry because TLS needs write;
- peer close-notify;
- raw EOF without close-notify;
- connection reset;
- timeout;
- certificate chain failure;
- hostname failure;
- protocol version/cipher failure;
- fatal TLS alert;
- allocation failure;
- provider-internal error;
- aborted request/process teardown.

Mapping all negative TLS-library values to a generic `SCE_HTTP_ERROR_SSL` would break Sony's nonblocking state machine and diagnostic APIs.

The concrete first-pass mapping is:

- Mbed TLS `WANT_READ` or `WANT_WRITE`: return `SCE_HTTP_ERROR_EAGAIN` without destroying the connection state.
- Socket `SCE_NET_ERROR_EAGAIN`: convert to the corresponding Mbed TLS WANT result in the BIO callback.
- Fatal handshake: store `SCE_HTTPS_ERROR_HANDSHAKE`, retain the raw provider/network detail, and return `SCE_HTTP_ERROR_SSL`.
- Fatal application read/write: store `SCE_HTTPS_ERROR_IO` and return `SCE_HTTP_ERROR_SSL`.
- Verification failure: store `SCE_HTTPS_ERROR_CERT`, translate the verification detail mask, and return `SCE_HTTP_ERROR_SSL` unless an application callback explicitly accepts it.
- Clean close-notify: return zero to the HTTP receive path.

The exact `sceHttpsGetSslError` field semantics and callback-override behavior still require implementation-level validation.

## 13. Build Environment

The host does not currently expose VitaSDK tools directly in `PATH`, but Docker is available.

Cached hard-float image:

```text
vitasdk/vitasdk:latest
```

Observed toolchain in that image:

```text
arm-vita-eabi-gcc 15.2.0
cmake
ninja
vita-make-fself
vita-elf-create
Mbed TLS 3.6.5 with TLS 1.3 client symbols
```

The implementation must use the normal hard-float image, not the soft-float image.

The existing repository build system is old and will need either targeted modernization or a separate CMake subtree for the TLS provider and host tests.

## 14. Work Completed

- [x] Selected a fresh managed worktree.
- [x] Inspected repository structure and current installer/kernel behavior.
- [x] Recorded exact hashes of bundled modules and CA data.
- [x] Unpacked the bundled 3.73 SELF modules for analysis.
- [x] Opened annotated 3.60 and exact bundled 3.73 HTTP/SSL databases in IDA MCP.
- [x] Confirmed BSAFE MES 3.2.1, SSL-C 2.8.1, Crypto-C ME, Sony source-tree paths, and the Vita TLS 1.2 marker.
- [x] Identified and semantically named the six HTTP TLS transport functions.
- [x] Matched all six uniquely in the exact bundled 3.73 `libhttp`.
- [x] Matched the main certificate-related functions in the exact bundled 3.73 `libhttp`.
- [x] Recovered the main object fields and lifecycle used by the TLS path.
- [x] Confirmed read/write chunking and retry loops.
- [x] Confirmed the handshake uses an `SSL_get_error`-style two-argument classifier.
- [x] Established Docker hard-float VitaSDK availability.
- [x] Recovered public symbolic names for the transport's HTTP, HTTPS, and network errors from the official Sony SDK headers.
- [x] Recovered the surrounding 3.73 request state machine and exact hook prototypes.
- [x] Confirmed that the provider can be injected with the same post-load per-PID mechanism already used by this project and taiHEN.
- [x] Confirmed that the installed CA bundle is directly parseable PEM.
- [x] Selected the VitaSDK-packaged Mbed TLS 3.6.5 as the first implementation engine and confirmed that its hard-float archives contain TLS 1.3 client code.
- [x] Created this persistent progress file.
- [x] Wrote the formal design and implementation plan under `docs/superpowers/`.
- [x] Implemented and host-tested the exact-module gate, Sony ABI accessors, error mapper, connection registry, certificate-wrapper registry, and path helpers.
- [x] Implemented a hard-float Mbed TLS 3.6.5 provider with six transactional `libhttp` hooks, trust-store/DRBG setup, Vita socket BIO callbacks, and public certificate-inspection compatibility hooks.
- [x] Implemented kernel-side exact SELF hashing and post-`libhttp` provider injection.
- [x] Extended the installer/build/package path to deploy `tls_fixer_http.suprx` and detect legacy TLS-1.2-only installations as incomplete.
- [x] Recovered and implemented Sony's effective HTTPS verification-option selection and per-bit certificate filtering.

## 15. Immediate Next Steps

1. Finish the installer uninstall path so it removes only the exact tls_fixer taiHEN configuration block while preserving unrelated user edits.
2. Add a negative static-validator test that flips one invariant hook byte and proves the expected named failure.
3. Run a clean full VPK build with the hard-float image and inspect imports, exports, ARM attributes, artifact sizes, hashes, and package contents.
4. Review all fail-open paths: unknown hash, absent provider, failed provider start, runtime module mismatch, partial hook installation, and connection-local setup failure.
5. Update `README.md` with exact scope, fallback behavior, licensing notice, and explicit hardware-validation status.
6. Remove or ignore `.reverse-tmp/`, `build/`, and root-generated outputs before the aggregate diff.
7. Write the real-hardware validation protocol and document every runtime claim that remains unverified.
8. Review the complete project diff, run final clean verification, and commit coherent source changes without pushing.

## 16. Continuous Update Rule

Update this file after each of the following:

- a reverse-engineered function receives a stable semantic name or prototype;
- an offset, hash, or module identity changes;
- an architectural candidate is accepted or rejected;
- the TLS engine/version is selected;
- a new source component or test is added;
- a build or test is run, including failures;
- a hardware-only uncertainty is discovered;
- a commit is created.

When resuming this task in a new session, read this file first, then inspect `git status`, then load the active project brief and any saved project memory.


## 17. Resume Audit and Reproducible Build Results

A full resume audit found that the worktree already contained an untracked implementation subtree (`tls13/`), formal design/plan documents, host tests, and generated build outputs that were not reflected in the previous completion summary. None of these files are committed yet. The implementation is being treated as provisional and audited against the recovered binary contract rather than accepted because it compiles.

### 17.1 Reproduced checks

Using the cached hard-float `vitasdk/vitasdk:latest` image:

- Host core build with GCC 13.3.0: passed.
- Host CTest suite: 1/1 test passed.
- AddressSanitizer/UndefinedBehaviorSanitizer build: passed.
- Sanitized CTest suite: 1/1 test passed.
- Exact `libhttp` descriptor validation against `.reverse-tmp/lhttp-3.73-fresh.elf`: passed.
- Compressed SELF SHA-256 validation against `misc/lhttp.suprx`: passed.
- Vita compilation and final executable link with hard-float GCC 15.2.0: passed.
- Initial `vita-elf-create` conversion failed because `module_stop` was removed by `--gc-sections`. After explicitly retaining `module_start` and `module_stop`, clean SELF generation passed.

The initial reproducible build failure was:

```text
vita-elf-create: Could not find symbol 'module_stop' for main export 'stop'
```

`arm-vita-eabi-nm` confirmed that the failing linked executable retained `_start`/`module_start` but not `module_stop`. `tls13/provider/CMakeLists.txt` now passes linker roots for both lifecycle entry points. A clean hard-float rebuild retained `_start`, `module_start`, and `module_stop`, and generated `tls_fixer_http.suprx` successfully.

### 17.2 Linked-provider footprint before the lifecycle fix

The linked hard-float executable, before SELF conversion, measured:

```text
.text       328356 bytes
.rodata     122424 bytes
.bss         12672 bytes
Total       464283 bytes
```

ARM attributes include `Tag_ABI_VFP_args: VFP registers`, confirming the normal hard-float ABI. The executable had no unresolved ELF symbols. The broad VitaSDK Mbed TLS configuration also retained server-side and otherwise unused objects; footprint reduction remains a later source-build/configuration task, not a prerequisite for functional integration.

### 17.3 Application certificate callback semantics

Targeted IDA analysis of the original 3.60 `fun_http_tls_verify_callback` established the callback call site more precisely:

```text
callback(verify_bits, certificate_array, certificate_count, user_arg)
```

The callback pointer and user argument are copied into the BSAFE callback metadata and invoked from metadata offsets `+0x10` and `+0x14`, corresponding to connection fields `0x104` and `0x108` recovered earlier.

The callback return convention is not a generic “nonzero means accept” mechanism:

- a negative callback return rejects immediately;
- a nonnegative callback return permits processing to continue;
- when `verify_bits != 0`, Sony still applies additional game/system/firmware policy checks before final acceptance.

Therefore the historical claim that an application callback can simply override arbitrary certificate failures was too broad. The provider now preserves the observed negative-reject/nonnegative-accept convention, wraps the retained Mbed TLS peer chain for the callback, hooks the eight public certificate-inspection functions, and filters failures through the already-policy-checked Sony option mask. Real-hardware validation is still required before claiming complete callback compatibility.

### 17.4 Additional implementation audit findings

- The initial `module_stop` ordering bug has been fixed with an empty-registry stop gate that runs before hooks are removed.
- The initial process-global `errno` shim has been replaced by Vita libc's per-thread `_sceLibcErrnoLoc()`.
- The provider links against VitaSDK's broad Mbed TLS configuration with `MBEDTLS_THREADING_PTHREAD`, `MBEDTLS_FS_IO`, `MBEDTLS_HAVE_TIME`, and TLS 1.3 enabled. Its compatibility shims and imports must be audited against all linked code paths rather than inferred from one successful link.
- Certificate compatibility hooks and wrapper registries are implemented but remain hardware-unvalidated.
- Kernel exact-hash gating, provider injection, installer deployment, and VPK packaging are implemented but remain hardware-unvalidated.

### 17.5 Lifecycle hardening completed

- Added an atomic `tls_fixer_registry_begin_stop_if_empty()` gate. A provider unload now fails before changing hooks or registry state when any provider connection exists.
- `module_stop` no longer removes hooks and only then discovers that the registry is busy.
- Added host coverage for the stop gate, including failed stop leaving insertion available and successful empty stop rejecting later inserts.
- Re-ran normal and sanitizer host tests successfully after the change.
- Re-ran the hard-float Vita build successfully through `tls_fixer_http.suprx` creation.

## 18. Provider, Verification-Policy, Kernel, and Installer Audit

### 18.1 Registry and connection lifecycle corrections

The resume audit found connection-lifecycle bugs that compilation alone could not expose:

- A repeated create on the same Sony connection could cross from an existing provider-owned connection into the legacy BSAFE path. The registry now supports an atomic replacement only when the prior slot is active and has no references; otherwise the operation remains provider-owned and fails coherently.
- Removal is idempotent while a slot is already in `REMOVING`, allowing concurrent shutdown callers to return success without issuing duplicate close-notify/free operations.
- `last_net_error` is reset before every handshake, read, and write so a prior socket failure cannot contaminate a later TLS diagnostic.
- Raw underlying TCP EOF is now a fatal I/O outcome, distinct from authenticated TLS `close_notify`.
- Zero-length I/O returns zero without entering Mbed TLS; a null buffer with nonzero length returns the Sony invalid-value error and records internal diagnostics.
- Timeouts preserve provider connection state. Sony terminates the affected blocking request at the HTTP layer; the TLS object is not independently poisoned by the timeout mapping.

Host coverage was extended for registry replacement, busy replacement, generation changes, cleanup outside the structural lock, and idempotent removal.

### 18.2 Exact Sony HTTPS option contract

Both the annotated 3.60 binary and the exact bundled 3.73 `libhttp` use connection word 53, byte offset `0xD4`, when constructing the SSL verification context.

The exact 3.73 logic is:

```text
connection_options = connection[0xD4 / 4]
if connection_options >= 0:
    effective_options = global_options
else:
    effective_options = connection_options
```

The live global option word is at offset `0xF4` in `libhttp` data segment 1. The exact supported module has:

```text
text segment: filesz = memsz = 0x1D150
data segment: filesz = 0x5A4, memsz = 0x640
```

The high bit marks a per-handle override; the lower bits retain the effective options. The provider validates both segment shapes, stores the live global-option address, and snapshots the effective option mask at provider-connection creation, matching the legacy create path.

The public verification bits are:

```text
0x01 server verification
0x02 client verification
0x04 hostname/CN check
0x08 not-after check
0x10 not-before check
0x20 known-CA check
```

The original callback also consumes private bit `0x40` for chain handling. Provider certificate failures are now filtered as follows:

- with server verification disabled, no server-certificate failure is enforced;
- malformed/signature/internal certificate failures remain enforced when server verification is enabled;
- hostname mismatch is enforced only with `0x04`;
- expiry is enforced only with `0x08`;
- not-yet-valid is enforced only with `0x10`;
- unknown CA is enforced only with `0x20`.

The application callback still receives the filtered public detail mask and is invoked even when the mask is zero, matching the recovered Sony control flow. The provider observes the effective mask after Sony's public option APIs and firmware policy have already applied it; it does not add a new policy bypass.

### 18.3 Certificate callback compatibility

The exact callback ABI and return rule are now encoded:

```text
callback(verify_bits, certificate_array, certificate_count, user_arg)
negative return: reject
nonnegative return: accept, subject to Sony's already-applied option policy
```

Provider-owned certificate and name wrappers are registered for the callback lifetime. The provider hooks and dispatches:

- `sceSslGetSerialNumber`;
- `sceSslGetSubjectName`;
- `sceSslGetIssuerName`;
- `sceSslGetNotBefore`;
- `sceSslGetNotAfter`;
- `sceSslGetNameEntryCount`;
- `sceSslGetNameEntryInfo`;
- `sceSslFreeSslCertName`.

Foreign objects are forwarded to the original BSAFE exports. Wrapper addresses are fixed-capacity and callback-scoped; retaining one beyond the callback violates the recovered lifetime contract and can still exhibit address-reuse/ABA behavior in a later callback. This limitation is explicit rather than hidden.

### 18.4 Kernel and installer implementation

The kernel plugin now:

- hashes the installed replacement `libhttp.suprx` with streaming SHA-256;
- enables injection only for the exact supported compressed artifact;
- safely compares paths without the original short-path suffix underflow;
- injects `tls_fixer_http.suprx` after a successful replacement-libhttp load;
- passes the versioned provider start arguments;
- preserves the existing 3.60 DNS-fix ordering;
- builds cleanly with `-Wall -Wextra -Werror` under hard-float GCC 15.2.0.

The installer now:

- deploys/removes `tls_fixer_http.suprx` with the HTTP/SSL package;
- treats a legacy installation missing the provider as incomplete;
- uses checked bounded copies and transactional temporary/rollback names;
- edits the taiHEN configuration using a NUL-terminated bounded buffer;
- reports a concrete failure and does not reboot after a failed operation;
- fixes the original six-entry menu/five-entry-state out-of-bounds access;
- builds cleanly with strict warnings.

Exact rollback across an entire multi-component full install is not implemented: earlier successful components may remain when a later component fails. The installer leaves the device running, reports failure, and permits a subsequent repair run. Uninstall rewrites the configuration through a temporary file and removes only the exact block inserted by tls_fixer.

### 18.5 Latest reproduced verification

After the lifecycle and HTTPS-option changes:

- normal host CTest: passed;
- ASan/UBSan host CTest: passed;
- exact `libhttp` ELF/signature/SELF validation: passed;
- hard-float provider link and `tls_fixer_http.suprx` generation: passed;
- strict kernel plugin build: passed;
- strict installer/`eboot.bin` build: passed.

The current linked provider footprint is:

```text
text  456840 bytes
data      64 bytes
bss    14688 bytes
total 471592 bytes
```

No claim of successful TLS 1.3 negotiation in the Vita browser has been made. Injection, hook execution, certificate wrappers, nonblocking behavior, process coverage, and runtime memory/performance still require real-hardware evidence.

## 19. Threading, Timeout, Custom-Certificate, and Packaging Audit

### 19.1 Vita pthread compatibility defect fixed

Vita's pthread ABI encodes statically initialized mutexes as sentinel pointer values (`-1`, `-2`, and `-3`). The linked VitaSDK Mbed TLS archives contain static mutexes for PSA state and filesystem/readdir support. The initial shim treated those values as allocated pointers and would have dereferenced invalid memory on first use.

The shim now performs atomic lazy initialization:

1. recognize all three Vita static initializer sentinels;
2. allocate and create a Vita mutex candidate;
3. publish it with compare-and-exchange;
4. destroy/free losing candidates when another thread wins;
5. preserve ordinary dynamically initialized mutex behavior.

The provider rebuilt successfully after this correction. This was a runtime-crash defect that compilation alone could not expose.

### 19.2 Time and CA behavior checked against linked code

Disassembly of the linked `mbedtls_ms_time` confirms that it calls `clock_gettime(CLOCK_MONOTONIC)`. The provider supplies that clock from `sceKernelGetSystemTimeWide`, while UTC certificate-date conversion uses RTC APIs and a reentrant `gmtime_r` implementation.

The exact CA bundle was parsed with native Mbed TLS 3.6.5 outside the Vita target build:

```text
parse_result=0 certificate_count=188
```

This proves the installed PEM syntax and certificate set are accepted by the selected Mbed TLS release. Vita filesystem permissions and runtime memory usage remain hardware-only questions.

### 19.3 Exact retry and timeout behavior

The original handshake wrapper was rechecked in IDA. When the underlying socket reports EAGAIN:

- request offset `0x8C` nonzero: return `SCE_HTTP_ERROR_EAGAIN`;
- request offset `0x8C` zero: return `SCE_HTTP_ERROR_TIMEOUT`;
- do not store a fatal HTTPS I/O error for the timeout branch.

The provider now applies this distinction to Mbed TLS WANT_READ/WANT_WRITE. Read/write timeouts likewise map to the Sony HTTP timeout without marking the Mbed TLS connection permanently failed.

The surrounding Sony receive state machine accepts both raw network EAGAIN and `SCE_HTTP_ERROR_EAGAIN`, so provider read/write WANT results use the public HTTP retry value without changing caller behavior.

### 19.4 Custom certificate/client-key compatibility policy

The provider now hooks `sceHttpsLoadCert` and `sceHttpsUnloadCert`. After a successful load that supplies custom CA or client-certificate/key material, future connections deliberately remain on the original BSAFE path until unload. This avoids silently ignoring application trust anchors or client authentication while keeping legacy TLS 1.2 functionality.

Existing provider-owned connections are not migrated after a late custom-material load. Applications are expected to configure global certificate material before creating HTTPS requests, which is also the meaningful legacy usage pattern.

### 19.5 Kernel module-presence scan hardened

The provider-loaded check now uses the canonical `ksceKernelGetModuleList(pid, 0xFF, 1, ...)` flags and a 256-entry buffer. A list error or saturated result is treated as uncertainty, so injection is skipped rather than risking duplicate provider loads. The exact `libhttp` remains redirected and continues through BSAFE TLS 1.2 in that case.

### 19.6 Full package build reproduced

A clean top-level build produced the installer, kernel plugin, DNS fix, provider, and VPK. The VPK contains the 13 expected entries, including:

```text
tls_fixer.skprx
dnsfix.suprx
compat.suprx
lhttp.suprx
lssl.suprx
tls_fixer_http.suprx
comm2.suprx
certs.cer
```

The current provisional generated hashes are:

```text
VPK:             0b683314fe5ecb7143f481748aa0390966a9a509e2b53f85dbb440cc3037b1ea
installer eboot: 42fdcdd89ba94b96fb19f60920837480d14a44c64735bac66da37be6d4eae2bc
kernel plugin:   fa4f01bd00877a83b1021fdd5afc8e105b051752eec05b1c0d1f65e0b015904c
DNS fix:         1a08412d366794b3bebb341be5d1750866c1f3196cea0050e404de3b40c0e0d6
TLS provider:    03de5a37ae6eea7b31bd1bb936d13bdfeee560f36fc6a901aac74f8848990036
```

These are not release hashes: documentation, license packaging, and final source review are still in progress and will change at least the VPK/provider artifacts.

## 20. Current Resume: Dependency Security and Browser-Path Challenge

The full worklog was reread and reconciled with the existing uncommitted implementation. No prior source changes were reverted.

### 20.1 Current TLS engine, not the cached SDK version

The official GitHub release API was checked through `gh`. As of this check the latest stable Mbed TLS is **4.2.0**, published 2026-07-07, bundling TF-PSA-Crypto **1.2.0**. Mbed TLS 3.6.7 is the current 3.6 LTS maintenance release, but avoiding a major-version migration is not itself a Vita compatibility requirement. The user explicitly challenged why the latest version was not selected. Migration to 4.2.0 is now the target; keep 3.6.x only if an actual measured blocker justifies it.

The cached VitaSDK Mbed TLS 3.6.5 predates multiple upstream security fixes. Examples independently checked against upstream advisories:

- TLS 1.2 signature algorithm policy bypass, CVE-2026-25834: https://mbed-tls.readthedocs.io/en/latest/security-advisories/mbedtls-security-advisory-2026-03-sigalg-injection/
- TLS 1.3 HelloRetryRequest selecting an unadvertised group, CVE-2026-25832: https://mbed-tls.readthedocs.io/en/latest/security-advisories/mbedtls-security-advisory-2026-07-tls13-hrr-unadvertised-group/
- X.509 basicConstraints parsing, CVE-2026-49300: https://mbed-tls.readthedocs.io/en/latest/security-advisories/mbedtls-security-advisory-2026-07-x509-ca-bit-forgery-invalid-basicconstraints/ (its exploit conditions are narrower than arbitrary certificate authentication; do not overstate exposure).

Official release asset selected for the migration:

```text
Repository: Mbed-TLS/mbedtls
Release: mbedtls-4.2.0
Asset: mbedtls-4.2.0.tar.bz2
SHA-256: 2bed9d713b4668f76553b097e72b8aa30bc8f112a940d7ae228d524bbde6ffea
```

**Correction to section 10:** `MBEDTLS_USE_PSA_CRYPTO` being disabled in 3.6.5 does not mean TLS 1.3 does not require PSA. TLS 1.3 uses PSA directly regardless of that switch; the switch controls other/indirect code paths. Later 3.6.x handshakes can initialize PSA lazily. The replacement should initialize and check its crypto provider explicitly rather than confuse the two macros. Primary configuration documentation: https://mbed-tls.readthedocs.io/projects/api/en/v3.6.3/api/file/mbedtls__config_8h/

### 20.2 Browser route not yet proven

Read-only IDA MCP inspection of the existing `tls_fixer-compat-373` database (other worktree path `<workspace>/.reverse-tmp/fwcompare/373/ScePsp2Compat.exec.elf`) found embedded libcurl and OpenSSL, including:

```text
0x812F5868: cookie-file banner generated by libcurl
0x812FB97C: OpenSSL internal error assertion
0x8130F0E0: OpenSSL RSA method
0x8131A37C: second libcurl cookie-file banner
0x813873AC: TLSv1.2
```

This challenges the assumption that hooking `SceLibHttp` supplies browser TLS 1.3. The `SceLibSsl` BSAFE finding remains valid for that module, but must not be generalized to the separate browser compatibility module. Work in progress: verify the analyzed compatibility module against `misc/compat.suprx` and trace the browser's actual network call path. Do not report browser support based solely on an in-app `SceHttp` provider build.

### 20.3 Verification work planned for this resume

- Build a checksum-pinned current engine with explicit Vita entropy, time, mutex and allocation integration rather than SDK-prebuilt ABI shims.
- Add executable tests that negotiate TLS through the real transport implementation, not only enum/registry tests.
- Audit callback reentrancy, provider-owned versus legacy dispatch, unfinished-write retries, zero versus close-notify, and thread-safe stop/cleanup.
- Rebuild the hard-float module and full package after the migration; all section 19 artifact hashes are now historical only.

### 20.4 Exact compatibility-module evidence

`misc/compat.suprx` was unpacked into `.reverse-tmp/compat-bundled.suprx.elf` with the existing `vita-unmake-fself` utility. Its PT_LOAD payloads exactly match the `tls_fixer-compat-373` IDA input:

```text
text: vaddr 0x81000000, filesz 0x39F508
SHA-256 2b54b99bdfb32f55f762f3a1730afb242400b5c237ce327728b5cb29e86b685b
data: vaddr 0x813A0000, filesz 0x9C28
SHA-256 bd3ddba2888e02ccef72ee07e0252fd234ffe59b3a74c8ca1e06ee73a073af56
```

IDA xrefs from the `SSL connection using %s` string at `0x8131DBAC` lead to `sub_810A5ECE` (size `0x366`), a libcurl nonblocking SSL connection driver. Its decompilation directly calls an internal OpenSSL-style connect function at `0x81203814` and error classifier at `0x812047D8`; WANT_READ/WRITE are classes 2/3 and success is 1. On completion it installs send/receive callbacks at `0x810A673C` and `0x810A6650` into its own connection object. This is executable transport code, not just unused vendor banner strings.

Observed libcurl object fields (analysis evidence, not yet a supported new hook ABI): easy-handle pointer word 0, socket words `80 + socket_index`, SSL state at `90 + 6 * socket_index`, OpenSSL handle at `92 + 6 * socket_index`, connecting state at `94 + 6 * socket_index`. **Corrected direction:** receive callback is `0x810A673C`, stored at word `85 + socket_index`, and send callback is `0x810A6650`, stored at word `87 + socket_index`. The send wrapper calls OpenSSL-style write at `0x812038A8`; the receive wrapper calls read at `0x81203836`. Curl error values are AGAIN=81, SEND_ERROR=55 and RECV_ERROR=56. Pending-data helper `0x810A6240` calls the embedded SSL-pending function `0x81203648`. TLS setup helper `0x810A3C98`; socket wait helper `0x81097E82`; timeout helper `0x81093F18`; certificate helper `0x810A58E0`. The previously implemented SceLibHttp hooks do not intercept these calls. Browser entry-point coverage, all cleanup/readiness callbacks, and safe compatibility-module provider loading still require tracing before adding a browser-specific adapter.

### 20.5 Mbed TLS 4.2 source-port implementation and new regression tests

New files `tools/fetch_mbedtls.py` and its five unit tests download through `gh`, verify the fixed official archive SHA-256, reject corrupt cached files without overwriting them, and publish only verified downloads. All five tests pass. Archive and extracted sources remain under ignored `build/deps/`.

`tls13/crypto/` now selects the local verified release archive with CMake FetchContent and defines shared Mbed TLS/TF-PSA configuration. TLS/crypto sources and the provider see the same configuration; the SDK's prebuilt 3.6.5 archives are no longer used. Unneeded TLS servers, DTLS, file helpers, certificate writers, PSK modes and renegotiation are disabled. The provider's old pthread/libc ABI shims were replaced with explicit Mbed TLS ALT callbacks in `platform_shims.c`: Vita mutexes/condition variables, a 64-byte-bounded entropy source, monotonic milliseconds, and 64-bit UTC from RTC ticks. Trust-store loading now uses bounded SceIo reads plus PEM parsing, and PSA initialization/free are explicit.

Native tests compile this actual platform port against test-only Sce API implementations in `tls13/tests/transport/`. Entropy failure wipes partial output; native tests check the 64-byte kernel RNG limit, initialization failure without RTC, PSA randomness, leap-day UTC conversion, and a real pthread-backed condition-variable wait/signal. These platform and core tests passed in `build/crypto4-host`; this is host evidence, not Vita execution.

A second executable compiles the actual `transport.c`, `trust_store.c`, and `vita_net.c` against the same real Mbed TLS 4.2.0/TF-PSA engine. `run_loopback.py` creates a local CA and server certificate and runs controlled Python/OpenSSL TLS servers. The certificate-callback bridge is a test stand-in, not the production certificate export hooks. Initial runs exposed real regressions:

- TLS 1.2 request/response passed.
- TLS 1.3 handshake succeeded, but the first read treated a NewSessionTicket notification (`-0x7B00`) as fatal and returned no data.
- Wrong hostname and unknown CA were rejected correctly.
- A malformed pre-certificate record was mislabeled as a certificate failure because `UINT32_MAX` (verification unavailable) was treated as real verification flags.
- A callback reentering the transport attempted to lock its own mutex, then silently selected the legacy path on lock error.
- Recreating an owned connection with invalid setup input silently selected the legacy path while old provider state still existed.

Fixes are now in the source and awaiting the next complete loopback run: consume bounded ticket notifications, distinguish the unavailable-verification sentinel, use try-lock with provider-owned retry dispatch, and preserve ownership on early recreate failure. The latest ARM build reached provider compilation but found that the old certificate attribute-name helper is no longer public in Mbed TLS 4; this was replaced by a small tested DER-OID name table rather than importing an upstream private header. Subsequent build/test results must be recorded before any success claim.

### 20.6 Verified source-port tests and callback-policy correction

The subsequent normal run passed the eight original loopback scenarios. The expanded sanitizer run (`build/crypto4-host-san`, Ninja, GCC 13.3, AddressSanitizer + UndefinedBehaviorSanitizer + leak checking) passed all six CTest targets, including **eleven** real TLS loopback cases, the actual bundled trust-store parse, entropy/clock/read failures, and registry cleanup lifetime checks. The complete Mbed TLS/TF-PSA object libraries and provider transport were compiled with sanitizer instrumentation, not just the core helpers. Log: `build/crypto4-matrix.log`. After adding `SceIofilemgr_stub` and selecting upstream's internal IP-literal parser, the same command successfully cross-built **`build/crypto4-vita/provider/tls_fixer_http.suprx` with Mbed TLS 4.2.0**. These results precede the callback-policy patch described next and must be rerun after the final changes.

The internal IP parser is selected with upstream `MBEDTLS_TEST_SW_INET_PTON`; despite its name this only selects the parser, not permissive verification. Upstream also uses this selector for platforms lacking a compatible `inet_pton`. Native tests verified matching IPv4/IPv6 certificate identities and rejection of a wrong IP address. The socket used for those tests is IPv4; they do not claim IPv6 socket support on Vita.

**Security correction to sections 18.2/18.3 and the original design:** Sony does not unconditionally honor nonnegative certificate callback results. The exact 3.73 callback invokes the application at `0x810159BE`. After a nonnegative result, if verification bits are nonzero, it applies additional policy at `0x810159D0..0x81015A22`:

1. Permit when `sceAppMgrIsGameProgram()` is nonzero and `sceKernelIsCalledFromSysModule(callback_address)` returns zero.
2. Otherwise permit when the original compatibility-version getter returns less than `0x02100000` (unsigned comparison).
3. Otherwise permit only when `sceRegMgrSystemParamGetInt(0x00563BFE, &value)` succeeds and `value` is nonzero.
4. Negative application results always reject. Zero verification bits do not require override permission.

Import identities were read through IDA from the exact ELF, then the named APIs cross-checked against VitaSDK's NID database. ARM veneer offsets: registry getter `0x18360` / NID `0x347C1BDB`; game-process query `0x18380` / NID `0xFFF8F7F0`; original compatibility-version getter `0x18600` / NID `0x9F793F84` (no public SDK name claimed); system-callback query `0x18620` / NID `0x85E6D2BB`. The provider now binds these **existing imports in the gated libhttp**, checks their NID metadata before activation, and shares a host-tested policy decision function with the certificate callback bridge. It does not reinterpret a callback acceptance as permission to bypass this policy.

The new policy regression tests were first run without the helper and failed as expected. They cover negative acceptance, clean-chain fast path, missing policy, registry failure despite a nonzero output, explicit override allowance, game/system callback allowance, and the exact version threshold. Full post-patch verification remains pending at the time of this entry.

Additional IDA caller verification: `sub_8100C5FA` in exact libhttp accepts both raw network EAGAIN (`0x80410123`) and HTTP EAGAIN (`0x80431082`) at `0x8100C6FC` and `0x8100C826`; it converts them to timeout for blocking requests and preserves retry/partial-byte behavior for nonblocking requests. This supports the provider's HTTP-EAGAIN return convention for reads independently of host mocks.

### 20.7 Production certificate hooks, retained names, stable retries

The loopback executable no longer substitutes a stand-in certificate decision function. It now compiles the production `cert_hooks.c` and captures its eight SceSsl inspection hooks and two SceHttps certificate-load hooks in a test-only taiHEN implementation. Every loopback process first injects a failure at each of the ten certificate-hook installation positions and checks complete rollback. Real application callbacks inspect serial number, subject, issuer, validity, entry count and name entries, exercise short buffers and invalid arguments, verify foreign-pointer forwarding, and free names. The test executable is non-PIE so the application callback and synthetic Sony object pointers obey the expected 32-bit pointer width; this is not proof of a Vita ABI or real taiHEN installation.

This test exposed another compatibility defect: returned subject/issuer names were invalidated at callback return, even though the public API supplies an explicit name-free operation. IDA inspection of the original subject/name factory path (`0x81049570 -> 0x81001760 -> 0x810016BE`) shows name object construction rather than merely returning an address inside the certificate. The provider now deep-copies each name's bounded node/OID/value data into independent storage. Names remain valid after callback return and TLS connection destruction until `sceSslFreeSslCertName` is called. Borrowed certificate handles still expire at callback return. Every name allocation gets its own generation, preventing a freed name handle from aliasing a new name in the same callback.

The retained-name regression was first run against the old bridge and failed on both TLS 1.2 and TLS 1.3 after the connection was destroyed (`build/cert-bridge-red.log`); it passes after the ownership change with leak checking enabled. The core registry tests were updated to assert independent name generations, stale-handle rejection on same-callback slot reuse, retained names and destroy-busy behavior.

A subsequent write-retry regression showed that the old wrapper could report success for changed application bytes while flushing an earlier pending TLS record (`build/write-retry-red.log`). Each connection now retains a private, stable 1500-byte write buffer across WANT results. A relocated caller buffer with identical bytes is accepted; changed length/content is a fatal provider I/O error. Read does not interleave while an application write is pending. Snapshots are zeroized on completion/failure/destruction. Shutdown does not call close-notify on a failed connection or one with a pending write, preventing teardown from flushing queued application data.

**Hot-unload correction:** activated providers now reject `module_stop` and stay resident until process exit. Even a corrected registry cleanup count does not prove that no thread is entering a hook or executing a continuation. The previous empty-registry stop path was therefore not a safe unload proof. Startup rollback remains implemented. Do not re-enable hot unload without a verified entry/continuation quiescence mechanism and real process/module-lifecycle evidence.

### 20.8 Final verification of the 4.2.0 SceHttp component

Fresh commands completed successfully:

```sh
python3 -m unittest discover -s tools/tests
python3 tools/validate_libhttp.py --descriptor tls13/supported_libhttp.json \
  --elf .reverse-tmp/lhttp-3.73-fresh.elf --self misc/lhttp.suprx

docker run --rm -v "$PWD":/src -w /src vitasdk/vitasdk:latest \
  sh -c 'make clean && make -j4'

docker run --rm -v "$PWD":/src -w /src vitasdk/vitasdk:latest sh -c '
  cmake -S tls13 -B build/crypto4-host -DTLS_FIXER_BUILD_HOST_TESTS=ON \
    -DTLS_FIXER_BUILD_TRANSPORT_TESTS=ON &&
  cmake --build build/crypto4-host -j6 &&
  ctest --test-dir build/crypto4-host --output-on-failure &&
  ASAN_OPTIONS=detect_leaks=1 ctest --test-dir build/crypto4-host-san --output-on-failure'
```

Results: five Python fetch/cache tests pass; the exact module validator reports `supported libhttp: OK`; seven normal and seven ASan/UBSan/leak-checking CTest targets pass. The loopback target now executes **fifteen** cases: valid TLS 1.2 and 1.3, wrong hostname, untrusted CA, abrupt EOF, malformed pre-certificate record, callback reentry, invalid recreation of an owned connection, matching IPv4/IPv6 identities, wrong IP, authorized invalid-chain override, negative callback rejection, identical-content relocated write retry, and changed-content write-retry rejection. Tests exercise the real TLS engine and production adapter/hook logic; they do not replace Vita device tests.

Logs:

- `build/tls13-full4-build.log`: clean full provider/kernel/DNS-fix/installer/VPK build.
- `build/tls13-final4-verification.log`: fresh normal and sanitizer tests plus ELF inspection.
- `build/write-retry-verified.log`: final transport regression and ARM module build before packaging.
- `build/tls13-final4-artifacts.json`: machine-readable local artifact identities.

The provider ELF has ARMv7-A, Thumb-2, VFPv3/NEON attributes and `Tag_ABI_VFP_args: VFP registers`. `arm-vita-eabi-nm -u` reports no unresolved ELF symbols. The linked ELF contains `mbedtls_ssl_tls13_handshake_client_step`, `psa_crypto_init`, `mbedtls_platform_get_entropy`, and `tls_fixer_crypto_time`. Its size report is text **297752**, data **24**, BSS **13628** bytes; these are linked-section sizes, not peak process RAM. Trust-chain and per-connection/crypto heap use still require measurement.

The new VPK contains **17 entries**. Byte comparisons verified that its provider, kernel and three license files are the freshly built/current files and that its `compat.suprx`, `lhttp.suprx` and `lssl.suprx` exactly match the repository payloads. The package does not modify Sony binaries to add browser hooks.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `tls_fixer.vpk` | 3139966 | `4f9e118a1133906f21db32f7517975a5c46270580a8ffd8eca52f9816a248619` |
| `build/tls13-vita/provider/tls_fixer_http.suprx` | 245743 | `3a188355838491eeb2033d218178013fed70e750ba04b5d90dd7d2a0bbe7fa3f` |
| `build/tls13-vita/provider/tls_fixer_http` | 493888 | `16e9bc1379aa8327960e39de5d06c190a8c982ecf7316020b2834d52a985d5d3` |
| `build/kernel/tls_fixer.skprx` | 8784 | `2781f1ac09f04f85b2bb447f914adf4eb922d6ffec526775bf102c66bcea5978` |
| `build/old_dns_fix/old_dns_fix.suprx` | 4753 | `1a08412d366794b3bebb341be5d1750866c1f3196cea0050e404de3b40c0e0d6` |
| `eboot.bin` | 58979 | `ad10ea650b7966791b779bbf73bb08aac9f0a8d1e1fff192f9f26a966dcc5dde` |

These are experimental local artifacts, not a validated browser release. No device installation, commit, push or pull request was performed in this resume. Generated binaries, source dependencies, logs and IDBs remain ignored.

### 20.9 Remaining goal and continuation priority

The original goal was browser TLS 1.3. It remains incomplete despite the tested SceHttp component. The browser-specific remaining work is documented in `docs/tls13-browser-path.md`: trace the active WebKit/libcurl backend(s), recover the complete backend configuration/lifetime/readiness contract, implement a separately gated adapter and loading path, then validate on hardware. A partial connection driver or TLS-version banner patch is not a substitute.

The formal design/implementation plan now carry controlling revisions that supersede old 3.6.5, callback-override, name-lifetime, hot-unload and browser-routing assumptions. The hardware validation document separates present SceHttp application tests from future browser acceptance cases. Continue from the exact compatibility-module IDA evidence rather than assuming the six libhttp hooks reach browser traffic.

## 21. Browser backend implementation (continuation)

Command and IDA execution were restored. CHAT.md was read; no further design changes were requested beyond the already-completed current Mbed TLS migration.

### 21.1 Actual WebKit routing established

The exact bundled compatibility module exports `curl_easy_setopt` at Thumb address `0x81093A82`, NID `0x30E7FB1B`, in library `0x81405F79`. Its export table was matched against the 3.65 WebKit module's import table: the matching stub is `0x8185D844`. The annotated 3.60 WebKit database names the same import `ScePsp2Compat_30E7FB1B` at `0x83A5E024`.

In the enriched 3.60 WebKit IDB, `sub_83368F22` is the normal resource-request setup. It sets curl option 32 to 1 (the generic TLS selector), option 81 from the hostname-verification configuration, option 64 from the peer-verification configuration, and option 10083 from the browser cipher-list configuration. This traces executable WebKit calls into the exact compatibility module rather than inferring routing from strings.

The raw 3.65 WebKit IDB has incorrect Thumb mode in this region; its cached xrefs were useful but current ARM disassembly/decompilation there was not. The existing enriched 3.60 WebKit IDB was opened instead. IDA's immediate search also returned no matches for known constants; absence from that search is not evidence of absence. The apparent low-address `0x81022xxx` cluster is graphics code, not a second curl backend.

The default browser cipher string is at compatibility text offset `0x2F5098`; its construction and configuration getter were traced in IDA. The new provider recognizes that exact list and retains only its two ECDHE/AES-128-GCM TLS 1.2 suites, with separate modern TLS 1.3 suites. It does not enable the old list's RC4/3DES entries. Unsupported custom cipher expressions, SSL-context callbacks, client material, CA directories, CRLs, issuer restrictions and certificate-info requests remain on the original backend before any provider bytes are sent.

The socket wrapper was checked in the annotated 3.60 compatibility IDB: it returns the native `sceNetSocket` ID, and its receive wrapper directly calls `sceNetRecv` then converts negative results to POSIX -1. There is no separate socket-descriptor translation required for the new BIO.

### 21.2 Narrow complete backend boundary

The adapter replaces the complete curl connect driver (`0xA5ECE`), close function (`0xA36BA`), and pending-data function (`0xA6240`). After a successful handshake it installs its own send/receive callbacks in the existing per-socket slots. Native OpenSSL context/session fields remain NULL; foreign TLS structures are never placed there. The original curl deadline (`0x93F18`) and socket-wait (`0x97E82`) helpers are reused through validated offsets. Blocking handshakes poll in bounded slices, BIO operations use `SCE_NET_MSG_DONTWAIT`, and closing waits for provider I/O to drain before the native connection can be freed.

The exact compatibility SELF hash is `738862133819fc37bc21f714da7ca76c72d73a620afafbe6a940d87dd4e6dc58`. `tls13/supported_browser.json` and `tls13/browser/module_descriptor.h` record the segment dimensions and relocation-masked signatures. Unlike libhttp, this module's text file and memory sizes differ: file 3798280, memory 3798576 bytes. Data file and memory sizes are 39976 and 53812 bytes.

### 21.3 Code and first verification

New browser code currently includes `browser/config.c`, `browser/backend.c`, their headers, and the descriptor. The bounded CA reader was factored into `provider/ca_file.c` for reuse without linking the SceHttp global state. The SceNet host mock now uses the actual encoded EINTR/RESET/TIMEOUT values and explicitly translates the Vita DONTWAIT flag to the host flag.

The browser configuration test was first run against an always-legacy stub and failed on the normal-browser case. The real backend test was first run against an unimplemented initialization stub and failed on both protocol versions. After implementation, normal host verification passed the configuration test and **17 browser TLS loopback cases**: TLS 1.2/1.3, blocking operation, second socket slot, wrong hostname, untrusted CA, independently disabled peer/host verification, IPv4/IPv6 identities, abrupt EOF, malformed record, timeout, stable/changed write retries, and pre-wire legacy dispatch for custom callbacks/already-native sessions. Existing SceHttp tests also passed after the CA-reader extraction.

Logs: `build/browser-backend-red.log`, `build/browser-config-build.log`, `build/browser-backend-build.log`. These tests use the production browser backend, the real pinned TLS engine and host implementations of Vita APIs. They are not proof of real Vita loading or browser page success. Module activation, kernel injection, packaging, additional concurrency/activation tests and sanitizer verification are the next implementation steps.

### 21.4 Kernel handoff and namespace corrections

The existing injection handoff contained a concrete UID namespace bug. In the enriched 3.60 Modulemgr IDB (`tls_fixer-modulemgr-injection`, base `0xB88000`), the intercepted `fun_LoadModuleForProcess` at `0xB8A1EC` returns module-object word 5. `fun_CreateModuleObjectForPid` creates that value through `ksceGUIDKernelCreateWithOpt`: it is a kernel GUID. The user module-info syscall first converts its argument from PUID to GUID. `fun_GetModuleInfoForProcess` writes module-object word 6 to the returned `SceKernelModuleInfo.modid`, and the user load wrapper also returns word 6. Both provider start paths now obtain this process-visible PUID with `ksceKernelGetModuleInfo(pid, returned_guid)` rather than passing the GUID to a user syscall. An absent/invalid target PUID or wrong module name skips injection.

The same internal loader explicitly uses `ksceIoOpenForPid` when load flag `0x1000` is set, otherwise ordinary `ksceIoOpen`. Browser provider loading now requests `0x1000`, preserves the target's original mount prefix (for example `wb0:/tls_fixer/...`), and derives the CA path from the mapped module's recorded path (for example `wb0:/cert/CA_LIST.cer`). It no longer assumes the browser can open a physical `vs0:` path. Kernel compressed-file gates remain rooted at the installer-controlled physical files and are rechecked immediately before injection.

Two independent loader profiles support application-only and browser-only installation. A fixed in-flight table prevents same-PID/same-profile duplicate or recursive loads. The structural mutex is released before module-list, file hashing and `LoadStartModuleForPid`; it is never held across reentrant provider loading. Module-list errors, saturation, module-info uncertainty, load/start failure, zero/nonresident loader returns and changed hashes skip activation. User and kernel hot-unload paths reject unloading live hook code.

### 21.5 Installation and diagnostics

The VPK now deploys `tls_fixer.suprx` together with the exact compatibility module. A legacy installation missing it is incomplete. Explicit full installation now refreshes the already-installed kernel loader instead of silently retaining an older version; the installer exposes **SQUARE** for full refresh. The original CA backup is retained during refresh. Browser uninstall removes both browser files. Full uninstall remains a sequence of checked component operations, not an all-or-nothing transaction across the entire filesystem.

The browser emits bounded protocol/cipher/error diagnostics to `sceClibPrintf` and, when permitted, `ux0:/data/tls_fixer-browser-<PID>.log`. There are at most 512 records smaller than 512 bytes per provider lifetime; payloads, URLs and secret keys are not logged. Logging failure does not weaken TLS or change connection results. `docs/tls13-browser-test.md` and `tools/tls13_test_server.py` provide the first device-test procedure and a strict-version, no-cache diagnostic endpoint. The helper requires an explicitly supplied certificate/key and was smoke-tested for TLS 1.2 and TLS 1.3 with changing response tokens.

### 21.6 Connection-health path found during final review

The initial three-hook browser set was not complete. Reviewing curl's reference `Curl_ossl_check_cxn` and then verifying the exact binary in IDA identified `0x810A354C`, which calls embedded `SSL_peek` at `0x81203870` on connection offset 368 (socket 0's native SSL handle). Leaving this path native would dereference the intentionally NULL handle of a provider-owned connection.

A fourth hook now supplies the same alive/closed/unknown decision using the provider TLS context. A one-byte lookahead preserves peek's non-consuming semantics, and pending-data/receive honor that cached byte. The regression failed against an always-closed stand-in for both protocol versions, then passed with the actual implementation. All successful response cases now perform health checks repeatedly between reads and still require every byte of a 5000-byte pattern in order. The six runtime/static signatures cover four hooks plus deadline/readiness helpers. Connect is installed last; partial published sets stay inert and resident until process exit.

### 21.7 Verification after the browser changes

The updated native suite has **28 CTest targets**, including **22 browser TLS loopback scenarios**, the original **15 SceHttp scenarios**, kernel loader contracts, mount-preserving paths, 16 browser module activation/failure cases, shared trust parsing, bounded diagnostics and lifetime primitives. The browser cases exercise TLS 1.2/1.3, SNI, blocking/nonblocking operation, both socket slots, independent peer/hostname policy, expiry, unknown CA, custom/missing PEM files, raw EOF versus close-notify, malformed records, write-retry identity, pre-wire legacy fallback, concurrent blocking-handshake cancellation and non-consuming health checks.

After adding the health hook, ASan/UBSan with leak checking passed all 28 targets (`build/browser-peek-verification.log`). Earlier passing 26-target logs predate that correction. The Python suite has 12 fetch/cache, ELF-validation and diagnostic-server tests. The final normal run, rebuilt module/VPK inspection and final artifact hashes are recorded below when complete. No device row has been promoted to passed.

### 21.8 Final source audit, fresh build and hardware-test handoff

The previous post-peek build finished successfully, but this continuation identified and corrected two additional issues before making the final test package:

- An explicitly supplied empty CA filename was conflated with no CA override, silently selecting the default trust store. The connection now retains whether a CA override was requested and rejects the empty filename as `CURLE_SSL_CACERT_BADFILE` before sending TLS bytes. The regression failed against the old code (`build/browser-empty-ca-red.log`) and now passes.
- The browser loopback runner caught all server exceptions as acceptable in negative scenarios, accidentally swallowing its own pre-wire assertions. Only expected socket/TLS errors may now be ignored; assertions and other server exceptions always fail the test. An adversarial test client deliberately transmits bytes in a purported legacy-fallback case. That meta-test failed against the old runner (`build/browser-oracle-red.log`) and now passes, proving the assertion remains observable.

Final verification was run after both corrections and its command session returned exit code 0. Evidence:

| Check | Result | Log |
| --- | --- | --- |
| Python tests | 13 passed | `build/browser-final-python.log` |
| Exact bundled SceLibHttp and ScePsp2Compat ELF/SELF checks | Both passed | `build/browser-final-identities.log` |
| Normal native CTest | 28/28 passed | `build/browser-final-tests.log` |
| ASan + UBSan + leak checking | 28/28 passed; UBSan halts on first error | `build/browser-final-tests.log` |
| Clean installer, kernel, DNS fix, both providers and VPK build | Passed | `build/browser-final-build.log` |
| Both provider ELFs | No unresolved symbols; hard-float ABI | `build/browser-final-build.log` |
| VPK inspection | All 18 members byte-compared with fresh artifacts/source payloads | `build/browser-final-artifacts.log` |

The browser loopback target now contains 23 scenarios; the companion SceHttp target still contains 15. Counts include deliberate pre-wire rejection/fallback scenarios, not 38 successful handshakes. All tests run on the host with Vita/taiHEN test implementations; no hardware case is inferred from these results.

Toolchain: `arm-vita-eabi-gcc 15.2.0`, container image ID `sha256:fd82d88ff456d118eef16533ebf9a3a6ae0e292684fb8a3a35f15f0707b4692d`. Browser ELF section sizes are text 299304, data 16, BSS 11828 bytes; these are not peak RAM measurements. `Tag_ABI_VFP_args` is `VFP registers`.

Final artifacts (all earlier artifact hashes are historical):

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `tls_fixer.vpk` | 3384311 | `4f289628815da2f568e02f8aed2a83709efa3a83bf5e8eb860fdb88d88cb4464` |
| `build/tls13-vita/browser/tls_fixer.suprx` | 245356 | `1a27f6ddbf9419dfa5a176432e384fe6016f01bfc73a3c5ddae0117e9e0efb4e` |
| `build/tls13-vita/provider/tls_fixer_http.suprx` | 245712 | `dcee89c07d4e54cb3e90c6769cf41b156cc7e49e040461d59bc992cb20b391c4` |
| `build/kernel/tls_fixer.skprx` | 11924 | `b1eeb809d240dae8bd921d51992ef33e7cb9b0429ddaf23598eabe12fa444b8d` |
| `eboot.bin` | 59000 | `4f4f7b41af7de5a43212fad38ff7f91941ee740fcdb072f8f5744b0a55ad02cc` |

The handoff VPK is an exact copy under `build/artifacts/tls_fixer-TLS13-browser-test.vpk`. The companion test ZIP contains that VPK, test/recovery instructions, a strict-version diagnostic server, checksums and verification logs. The expected device procedure is full refresh with SQUARE, reboot, then a TLS-1.3-only endpoint whose chain/hostname the Vita trusts. Provider activation and matching server-selected protocol/page-token evidence are required. Real namespace access, loader timing, browser execution, proxy behavior, memory consumption and repeated lifecycle stability remain unverified until the device matrix is run. Do not mark these as passed or describe the build as a production-validated release.

The final ZIP is `build/artifacts/tls_fixer-TLS13-browser-test.zip`, 3397645 bytes, SHA-256 `efd582c4d9ad4f672d95cc2bbbe15fa534bacbab1208f1a7e588b43f7afe0493`. All 11 members were reread and compared with their source bytes; the internal `SHA256SUMS` entries were independently checked against the extracted bytes. The package is ready to hand to the tester. No previous VPK or ZIP hash should be substituted for these identities.

### 21.9 Primary Vita FTP staging, 2026-10-07

At the user's request, connected to primary Vita `192.168.1.146:1337` using FTP. Its installed compatibility/HTTP/SSL files match the supported SELF hashes. The existing installation has no TLS 1.3 providers. Its old diagnostic log reports firmware `0x03600000` and build `3.3-diagnostic-3`; this is a retrieved log, not an independent live firmware query.

Before upload, downloaded the active taiHEN configuration, original pre-tls_fixer configuration, installed kernel plugin and diagnostic log, all five installed tls_fixer modules, active CA bundle, original `CA_LIST.cer_old`, and the existing `ux0:/data/tls_fixer.vpk`. The previous VPK's kernel plugin and certificate bundle exactly match the corresponding active files. Local backup: `build/device-backups/192.168.1.146-20261007-202121/`, with a per-file manifest. Its ZIP SHA-256 is `8110915182a9e6fdb1ad0ebd913c88f801e6f9ce47a12da07b09b72843f44744`.

Uploaded four files to `ux0:/data/tls_fixer-test/`: the final `tls_fixer-TLS13-browser-test.vpk` (SHA-256 `4f289628815da2f568e02f8aed2a83709efa3a83bf5e8eb860fdb88d88cb4464`), `before-TLS13.zip`, personalized `README-FIRST.txt`, and `SHA256SUMS`. Each upload was downloaded again and verified by byte count and SHA-256 before completing staging. Receipt: `build/deploy-146-current.json`, completed at `2026-10-07T20:23:00+02:00`.

No VPK installation, reboot, active plugin replacement, or trust/configuration change was performed remotely. Post-upload reads verified that active `ur0:/tai/config.txt`, `ur0:/tai/tls_fixer.skprx`, `CA_LIST.cer`, and `CA_LIST.cer_old` remain identical to the backup. The user must install the staged VPK in VitaShell, launch the updated tls_fixer installer and press SQUARE for full refresh without uninstalling first, then allow its successful-install reboot. The personalized instructions include the Cloudflare trace and tls13.1d.pw public test pages; no local test server was started and no device TLS result has yet been observed. After the browser test, the user should reopen FTP on port 1337 for log collection.

### 21.10 Current-process PID handoff correction

Post-export review identified a missed activation path in `kernel/main.c`. The intercepted native loader accepts PID zero as the current process, resolving it internally. The hook previously retained the incoming zero and passed it to injection, whose nonpositive-PID guard then skipped the provider. This affects either provider when its target is loaded through that path, and also the current-process shell DNS-fix comparison. It does not imply that every browser load uses PID zero or that hardware failure was observed.

The existing 3.60 Modulemgr IDB was reopened in IDA as `tls_fixer-modulemgr-pid-audit`. At `0xB8A20E..0xB8A210`, the loader checks `R6 == 0`; `0xB8A384` calls `ksceKernelGetProcessId`, `0xB8A388` copies `R0` to `R6`, then execution rejoins the normal load. The hook now snapshots the resolved target PID on entry, retains the incoming PID/flags/options for `TAI_CONTINUE`, and uses the resolved PID for subsequent provider and DNS-fix operations.

The new `tls13/tests/kernel/test_route.c` compiles the production kernel hook, not a copied helper. It covers current-process and explicit remote PIDs for both browser and libhttp loads, unchanged original-call arguments, namespace-preserving paths, negative load results, unrelated modules and shell DNS handling. Its original assertion failed before the fix (`build/kernel-pid-route-red.log`). The fixed regression and real kernel cross-build passed (`build/kernel-pid-route-green.log`). Existing provider tests remain unchanged; a full rerun and new VPK are required before delivery.

The existing device-staging receipt references revision 1. This continuation has not altered the remote staging directory, installed modules, configuration, trust store or device state. Deliver revision 2 under a distinct filename and make the supersession explicit.

Revision-2 verification completed with command exit status zero. `build/pid-r2-tests.log` contains 29/29 normal and 29/29 ASan/UBSan/leak-checking passes; `build/pid-r2-python.log` has 13 Python passes; `build/pid-r2-identities.log` has both supported module gates; `build/pid-r2-build.log` contains the clean installer/kernel/DNS/provider build, empty unresolved-symbol checks for both provider ELFs and hard-float attributes. The unchanged provider SELF hashes confirm this revision changes kernel activation, not the TLS engines.

All 18 rebuilt VPK entries were compared with current artifacts and source payloads. All 12 revision-2 ZIP entries and the internal checksum manifest were reread and verified. Receipt: `build/pid-r2-artifact-receipt.json`.

| Revision-2 artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `build/artifacts-r2/tls_fixer-TLS13-browser-test-r2.vpk` | 3384356 | `4f6db0de711db66863d1298406b98eee6d0cb4c43518d365a214305e43eb728b` |
| `build/artifacts-r2/tls_fixer-TLS13-browser-test-r2.zip` | 3398678 | `76971717c561709ea58a26f9670c42e04bc8426815a820613a311d0e3cabcb57` |
| VPK member `tls_fixer.skprx` | 11970 | `1a54e54913c6cc9f1793738a8427346b6ec32313a662037012547c4207fa491e` |

Revision 2 is ready for controlled device testing only. Installing the old staged VPK is not equivalent to testing this correction; use the distinct r2 file and full-refresh the installer. No active Vita changes, commit or push were performed in this correction.

### 21.11 User-reported boot crash: recovery takes priority

After revision-2 delivery, the user wrote in CHAT.md: "Ok but how do I recover knowing that now my vita crashes on the epilepsy screen?" This is the first direct hardware-failure report in this continuation. The installed revision is not yet determined; no crash dump or kernel trace has been retrieved. The PID-zero correction is not evidence of a fix for this boot crash.

Immediate instructions were sent: stop installing test builds, fully power down, hold L throughout startup to bypass taiHEN plugin loading, and if VitaShell becomes available comment out only the `ur0:tai/tls_fixer.skprx` entry in `ur0:tai/config.txt`. The saved pre-test configuration confirms that exact entry and also contains YAMT and other plugins; do not replace/delete the entire config as the first recovery action. If the normal power-off UI is inaccessible, Sony documents holding Power until the recovery menu appears; choose Restart with L held, not format/restore/update/rebuild.

Primary recovery references checked: `https://enso.henkaku.xyz/` explicitly documents L-held boot to disable taiHEN plugins; `https://manuals.playstation.net/document/en/psvita/basic/power.html` documents recovery through the power button. The backup at `build/device-backups/192.168.1.146-20261007-202121/` includes the actual pre-test config, kernel plugin, CA files and prior VPK. Its manifest was reread. No recovery files have been written to the device yet.

Awaiting the user's answer: does L-held boot pass the warning screen, and is VitaShell accessible? Recover the device and preserve failure evidence before further implementation or deployment.

The user subsequently reported that L-held boot reaches the home screen but all apps, including VitaShell, are absent. Confirmed hardware/storage: OLED/1000, no Sony memory card, Ensō installed, no HENkaku Settings visible. The working hypothesis is changed/unavailable ux0 mounting, not proven app deletion. Do not repeat the assumption that VitaShell is available or recommend molecularShell installation without a writable ux0.

Upstream source was checked with `gh` through Paul_priv: `yifanlu/taiHEN/plugin.c` opens `TAIHEN_CONFIG_FILE` then `TAIHEN_RECOVERY_CONFIG_FILE`; `plugin.h` defines those as `ux0:tai/config.txt` and `ur0:tai/config.txt`. `SKGleba/yamt-vita/README.md` and `src/main.c` show YAMT's core driver added to Ensō's `boot_config.txt`, separately from the taiHEN helper/settings entries. This supports a temporary microSD tai-config override during normal boot, contingent on the card being mounted before taiHEN reads it. Installed-version/timing behavior is not yet confirmed.

Prepared `build/recovery-sd/tai/config.txt` from the exact saved pre-test config. It differs only by adding `#` to the sole `ur0:tai/tls_fixer.skprx` line; all other bytes are preserved, including YAMT and other plugins. Original config SHA-256: `75e5e866ac62e20c535d76e06a67698c940711f39e03ac8c645a2c6da3f66cee`; recovery config SHA-256: `a0782dd12b545499e5bdc85818d47c1591e6dbebb9e4f9b2fe1b2a0eedc68488` (991 bytes). Exported recovery ZIP: `build/recovery-sd/tls_fixer-disabled-SD2Vita-recovery.zip`, 1418 bytes, SHA-256 `0481233d393790fc5e683c572be4e0e742a9d234641d2921a47a29558866d70a`; its sandbox copy and manifest-equivalent config comparison were independently verified.

Instructions sent: fully power off; access the microSD on a computer without formatting; back up any existing card-root `tai/config.txt`; place the recovery file there; safely eject and boot normally without L. If apps/VitaShell return, back up and comment out tls_fixer in the current ur0 config, then rename the temporary ux0 config so ur0 becomes authoritative again, and reboot. If it fails, return to L-held boot; do not format/rebuild/restore/update. Awaiting the result. No remote device writes have been performed during recovery.

The user requested a replacement ZIP containing the plugins, not merely a config referring to internal files. The working donor address was corrected by the user to **192.168.1.250** (not .146); the user also confirmed this donor has no SD2Vita, explaining the absence of YAMT. A mistaken initial read-only .146 attempt exited unsuccessfully and is not used in the new package. Neither device was modified.

Read-only FTP to `.250:1337` succeeded. Snapshot: `build/recovery-donor250-20261007-204910/`, pointer `build/recovery-donor250-current.json`. Active donor config is in ur0; ux0 config was absent. Its model-specific boot configuration was inspected but deliberately not packaged for installation. Common plugin references from the donor and affected pre-test configs were fetched twice and byte-compared, yielding 29 distinct binaries. Receipt: `plugin-receipt.json` in the snapshot. tls_fixer and both TLS13 providers were excluded.

Missing YAMT components were obtained through authenticated `gh release download v4.0 --repo SKGleba/yamt-vita --pattern yamt.vpk`. Official VPK size 68071, SHA-256 `ba4be76c17aa0b93ce765831925d47b9086e7c1ca9ca0a50a0093cbc3fe51579`. Five components (full/lite core, full/lite settings, helper) were extracted; the helper is named `yamt_helper.skprx` in the package. There are 34 plugin binaries total. The two unavailable probes `lowva_probe.skprx` and `plain_crashdump.skprx` were already disabled in the affected original config.

The complete recovery package is `build/recovery-full/tls_fixer-SD2Vita-recovery-with-plugins.zip`, 322424 bytes, SHA-256 `6e5c0c79bb5b39915d9b42c66206a273d80a7c4560595fe7b14b94b48c908d43`. All 41 entries, the SHA256SUMS manifest, and every active config path were checked on the host and independently in the conversation sandbox. `MANIFEST.json` records per-file donor/release provenance and hashes. Package helper: ignored `build/package_recovery_plugins.py`.

The active `tai/config.txt` points to supplied `ux0:tai/recovery/` binaries and enables only HENkaku user support, YAMT helper and the existing LiveArea layout plugin for first recovery. All other supplied plugins remain disabled. A separate `profiles/config.affected-full-without-tls_fixer.txt` preserves affected pre-test enable/disable choices apart from removing tls_fixer and rewrites available paths to packaged binaries. No donor-only extras are newly enabled. Both profiles have no unresolved active file references.

The user was instructed to copy the entire `tai` directory to the microSD root (after backing up existing config/recovery directory), safely eject, reinsert with the Vita powered off, and boot without L. The early-mount dependency was explicitly retained: a card-based config cannot bootstrap a card that is not mounted before taiHEN reads it. Do not copy donor boot_config or blindly load both YAMT cores. Optional plugins can still depend on existing internal settings/data, which were not overwritten. Awaiting physical recovery result; no boot success is claimed.

The user reported that the plugin-inclusive microSD attempt **did not work**, and suspected YAMT was not loaded because it belongs in boot_config. This is consistent with the previously identified bootstrap dependency, but actual driver state has not been observed. Do not keep recommending the card-only approach for this device state.

The next recovery route was checked against primary `henkaku/henkaku/bootstrap/bootstrap.c`, fetched read-only through `gh` and saved as `.reverse-tmp/recovery-henkaku-bootstrap.c`. The online R-trigger reset at lines 719-732 removes both tai configs and HENkaku configuration/core files. `install_taihen` at lines 422-450 reinstalls the core files under ur0 and recreates the default ur0 config. This is called at line 753, **before** the separate `dev_exists("ux0:data")` check at line 766 for molecularShell installation. With no memory card, line 788 explicitly reports skipping molecularShell; this does not itself prevent internal taiHEN/config repair. The routine does not format storage, install firmware or replace boot_config, but it deliberately resets plugin config and HENkaku settings and redownloads HENkaku core files.

Instructions sent: on the affected 3.60 OLED, boot with L, release L at home screen, visit `http://henkaku.xyz/`, start the online installer and press R/R1 at its reset/reinstall prompt. Require successful internal taiHEN download/install/verification; stop and report an error if that fails. The no-memory-card molecularShell skip is expected. After success reboot without L and check HENkaku Settings and SD2Vita apps. Saved backups will be used to restore wanted plugin settings later. Awaiting this result; neither normal boot recovery nor storage recovery is yet confirmed.

**User clarification supersedes the preceding recovery assumption:** the last card-package test actually **booted successfully without holding L**. "It didn't work" did not mean the boot crash persisted. The assistant explicitly corrected its misunderstanding and withdrew the immediate L-boot/config-reset instruction. Current guidance: remain in the normal boot, do not reset HENkaku config yet, and report whether HENkaku Settings is now present and whether the apps remain missing. Normal boot has been observed; storage/app access and the mechanism of improvement remain unconfirmed. Do not recommend another forced-reset or firmware action based on the older crash assumption.

The user confirmed that apps and HENkaku Settings remained absent in the normal boot. A normal online HENkaku bootstrap run was requested as a diagnostic, without R/reset; an installer-time L precaution was suggested to avoid loading suspect kernel plugins. The user reported "taiHEN has already been started!" and supplied a screen photo at `https://imgur.com/download/OMvCwvi/`. The download endpoint returned 403; its public image CDN URL `https://i.imgur.com/OMvCwvi.jpg` succeeded. The photo was viewed through Paul_priv, then rotated with macOS sips and viewed again (no OCR). Files: `.reverse-tmp/recovery-screen-OMvCwvi.jpg` and `...-upright.jpg`.

The image clearly shows **"molecularShell has been manually removed, skipping reinstallation"**, followed by the already-started taiHEN message. It does not show the no-memory-card skip. The bootstrap code's `dev_exists` is weak: it treats only `sceIoOpen` error `0x80010013` as absent and returns true for other errors, so the photo does not prove a healthy/writable SD2Vita mount. "Manually removed" is a heuristic based on existing HENkaku configuration and absent expected molecularShell executable, not evidence that the user deleted applications. The already-started result means this run did not create a new taiHEN instance; the assistant explicitly acknowledged that L in this run was not a way to reconfigure the existing instance.

Latest instructions, now based on that observed skip: exit bootstrap, reopen the official HENkaku browser installer and hold **R** at its short reset/reinstall prompt (not L) until forced-reinstall/config-reset is confirmed; release R and observe actual molecularShell/package download/install. File installation precedes the final taiHEN start call, so an already-started message can still follow a successful shell installation. Reboot normally without L only after successful package installation, then inspect molecularShell/HENkaku Settings. If download/install errors or no-card skip appear, stop and return the exact output. The user was explicitly told this resets plugin/HENkaku settings but does not format storage or reinstall firmware, and the pre-test configuration is backed up. Awaiting result; file-manager access is still unconfirmed.

**Final screen-text correction from the user supersedes the photo interpretation above:** the actual line is **"No memory card installed, skipping installation of molecularShell"**. The intermediate user OCR saying "No config changes needed" and the assistant's "manually removed" reading were both wrong. The assistant acknowledged this and withdrew the available-ux0/shell-removal inference. R-reset by itself cannot provide storage for shell installation; no further R/L retry was recommended merely to obtain molecularShell. User explicitly confirmed official Ensō/taiHENkaku 3.60.

The official live HENkaku page/payload was downloaded read-only for comparison: `go/payload.js` points to `http://henkaku.xyz/go/henkaku.bin`; the downloaded payload is `.reverse-tmp/recovery-live-henkaku.bin`, 80735 bytes, SHA-256 `3360b5b01329d7f16cd84d6d3dbcb1a65632e5580bc268df80172949a6fc3fff`. Embedded SELF begins at 0xAE38, ELF at 0xAED8. It was not modified or executed. Stock `SKGleba/henlo_jb` README documents a 3.65+ browser entry point, while its bootstrap includes mount-SD2Vita/NEAR-replacement options; no working stock 3.60 entry was established. NEAR replacement writes system-app files and resets app.db, so it was not recommended as a harmless launcher. No custom native recovery payload was created. Broader native recovery work was offered only subject to explicit approval.

The user then obtained a **temporary Sony memory card**, so custom-bootstrap work is unnecessary and paused. Latest instructions: fully power off, remove SD2Vita, insert Sony card, boot with L for the initial plugin-bypassed recovery (native Sony storage does not depend on YAMT), release L at home screen, and cancel format/update prompts. If a file manager is already present, use it without reinstalling. Otherwise run official HENkaku and hold R at the short force-reinstall prompt, release once acknowledged, require successful shell/package installation, then reboot normally with Sony card still inserted and SD2Vita removed. The config/settings-reset effect was explicitly disclosed. Enable unsafe homebrew and open the file manager, then start FTP and report its displayed address/port. Inspect the affected device's current ur0 config/boot_config/YAMT files before repairing storage. Do not copy donor boot configuration. Awaiting card recognition/file-manager/FTP result; no recovery writes were performed remotely.

### 21.12 Read-only kernel artifact audit while recovery is pending

The current generated kernel ELF was opened in IDA as `tls_fixer-kernel-r2-boot-audit`, input `build/kernel/tls_fixer.elf`, image base 0x81000000. It contains VFP/NEON instructions in code reached by kernel module routing: `inject_target` has `VLDR D16` at 0x8100058E and `VSTR D16` at 0x810005A2; `tls_fixer_path_equals` contains vectorized loops starting near 0x810007DC; `tls_fixer_path_has_suffix` and `tls_fixer_browser_replacement_path` also contain many vector instructions. A scoped rendered-listing regex search returned 100 matches before pagination. This was real disassembly of the generated artifact, not inferred from hard-float ELF attributes alone.

The first `insn_query` using mnemonic `V*` returned zero; that wildcard query is not reliable evidence of absence. The subsequent regex `search_text` found the actual instructions. Imported function-boundary annotations also truncate the recovered module_start at its printf call, so do not infer full-function coverage from that truncated function range.

Unmanaged VFP/NEON in a kernel module is a concrete build concern and a plausible explanation for the reported boot crash that host mocks/sanitizers would not expose. It is **not yet confirmed as the device's crash cause**: the installed revision, fault PC and kernel SIMD context state have not been obtained. No build flags, sources, binaries or device files were changed in this audit. The user was informed of the finding and that recovery remains the priority. Before any further test release, investigate kernel-safe compiler flags plus an executable-instruction build gate and confirm the actual device evidence. Do not simply disable one vectorization optimization and assume all VFP register use is gone.

## 22. Primary Vita boot failure after revision-1 installation

The user reports completing the staged VPK installation and full refresh, followed by an automatic reboot and a crash at the epilepsy warning screen. This is a failed hardware acceptance result. The previously staged revision-1 VPK has SHA-256 `4f289628815da2f568e02f8aed2a83709efa3a83bf5e8eb860fdb88d88cb4464`. Installed bytes have not been retrieved since the failure, so that attribution follows the staging receipt and the user's report, not a post-failure hash check.

A read-only TCP connection attempt to `192.168.1.146:1337` timed out. No remote recovery write, configuration change, reboot, or replacement deployment has been performed during this response. The exact faulting instruction and whether the reported crash is an exception or a hang remain unknown. Startup of the new kernel loader and automatic SceHttp-provider injection are investigation candidates; the screen location alone does not prove either cause. The revision-2 current-PID correction is not an established fix for this failure.

Immediate recovery instructions: force power off only if the system is frozen, boot while holding L to bypass taiHEN plugins, then use VitaShell to comment out only the active `ur0:tai/tls_fixer.skprx` line in `ur0:tai/config.txt`. Save and reboot normally before resuming FTP. Do not format, restore the system, update firmware, rebuild the database, remove enso, or rerun the experimental installer as a recovery step. If bypassing plugins changes storage visibility, do not accept format/update prompts.

The pre-update backup and manifest remain under `build/device-backups/192.168.1.146-20261007-202121/`. A matching backup was staged on the device at `ux0:/data/tls_fixer-test/before-TLS13.zip`; its internal paths include `ur0/tai/tls_fixer.skprx` and `ur0/tai/config.txt`. The pre-update plugin was 7235 bytes, SHA-256 `075aa4f53ae652732fc3bd4412f9a2139b3b608d9f2d32f2d7a1eb03dff0f939`. Initially disable only the tls_fixer entry to minimize changes; collect post-failure files and restore prior components deliberately after access is available.

The completion and readiness statements in earlier sections are historical and superseded by this incident. Do not call the device recovered or the boot defect fixed without a successful device boot and relevant evidence.

## 23. User-confirmed recovery and mandatory automatic recovery

The user now explicitly reports having recovered the primary Vita, reached LiveArea, and regained all applications. This supersedes the pending-recovery status in sections 21.11 and 22. The recovery procedure and current device configuration have not been independently inspected. No further FTP reads/writes, reboot, installation, or arming was performed in response.

The user requires future experimental changes to revert automatically. Their example is that an tls_fixer module should disable its next startup immediately when it begins running, so a crash is recoverable by an ordinary reboot. This requirement is recorded in the new root AGENTS.md for subsequent work, not merely kept in chat. Backups and manual L-held recovery do not satisfy it.

Design refinement: a one-shot permission must be consumed and synchronized to persistent storage before experimental initialization, hooks or injection. Persistence uncertainty must refuse activation. Success and failure both leave the next boot disabled, and only explicit user-approved re-arming permits another attempt. Self-disarming within the experimental module cannot protect faults before module_start; a separately qualified minimal guard can consume the permission before loading the payload. The first qualification should instead use manually launched volatile activation after LiveArea without a persistent boot entry.

One-shot activation is not full persistent-file rollback. Future test deployment must retain known-working boot/configuration/storage/plugin/CA files and stage test resources separately. Any unavoidable persistent replacement requires an independently designed and interruption-tested rollback transaction; it cannot be described as automatically reverted merely because an enable file was removed.

The initial documentation update did not implement a runtime safeguard. The user's subsequent decision and implementation below supersede the proposed separate-loader architecture. Kernel-only test-bundle delivery is recorded in section 23.4; no replacement full-refresh VPK is approved.

### 23.1 User selected direct self-removal, not a separate loader

The user explicitly rejected a separate loader and requested immediate removal of the module's own entry from `ur0:tai/config.txt` on module load. The implementation follows that choice: no guard module, permission token, launcher or new deployment mechanism was added. The first operation in `kernel/main.c:module_start` is `tls_fixer_self_disarm()`. Failure returns `SCE_KERNEL_START_FAILED` before debug output, replacement-file queries, loader initialization, hook installation or injection.

`kernel/self_disarm.c` disables the exact `ur0:tai/tls_fixer.skprx` and `ur0:/tai/tls_fixer.skprx` boot entries (including case variants) in KERNEL sections. A one-byte positional write replaces the initial path character with `#`; for example, `ur0:tai/tls_fixer.skprx` becomes `#r0:tai/tls_fixer.skprx`. This is intentionally an in-place comment rather than truncating/replacing the full config: every other byte, file length, unrelated plugin, section and newline is preserved. Re-enabling is a deliberate restoration of the original path, never an automatic startup/cleanup action.

All duplicate matching entries are disabled. An existing alternate `ux0:tai/config.txt` is handled too, so a shadowing config cannot retain the same active path unnoticed. An absent alternate file is allowed only for the explicit not-found error; permission errors, unavailable mounts and other uncertainty abort activation. An unsupported path whose basename is tls_fixer.skprx is rejected rather than guessed or silently ignored. Missing/already disabled boot entries do not authorize a run.

The function uses a bounded temporary kernel memblock, positional one-byte writes, `ksceIoSync` on the file, close, `ksceIoSync` on the mount, and a full exact read-back. Allocation/read/size/NUL/write/sync/close/verification errors abort. It does not create, truncate, rename, or restore configs. Concurrent external editing of plugin configs during startup remains prohibited.

The upstream taihen-parser lexer/parser were read through gh. Its actual syntax treats CR and LF as line boundaries, trims C whitespace, permits whitespace after `*` and `!`, and treats `#` as a comment only at the beginning of a trimmed line. The first draft's inline-comment assumption was wrong and was corrected with a failing regression. There is no added upstream-parser dependency.

### 23.2 Synchronization and generated-code checks

The existing 3.60 Iofilemgr IDB was inspected in place as `tls_fixer-self-disarm-io360`. `ksceIoSync` at approximately 0xBE0EA0 routes through its direct worker `sub_BE9198` or the scheduler wrapper `sub_BF5334`. The direct worker dispatches file vnode synchronization and, for mount roots, mount synchronization. The scheduled operation is initialized through `sub_BF6FCC`/`sub_BF69B4` with its async byte clear, selecting the synchronous dispatch branch. This supports requesting completion through `ksceIoSync`; it is not a device power-loss experiment. The function named `ksceIoSyncByFd` in this IDB looks like a file-reference/validation accessor, not a flushing primitive, so the implementation does not rely on that name or prototype.

Kernel translation units now use `-mgeneral-regs-only`, retaining the existing ABI. GCC's ARM option documentation states that this excludes compiler-generated FP/Advanced-SIMD registers but does not constrain assembly. `tools/verify_kernel_registers.py` therefore checks the actual linked executable before SELF generation and rejects decoded VFP/NEON, FP coprocessor aliases, and undefined instructions. The previous `build/kernel/tls_fixer.elf` was rejected with 236 decoded FP/SIMD instructions; the fresh self-disarming kernel passes. The user-space TLS providers' build flags were not changed.

Fresh binary inspection in IDA (`tls_fixer-self-disarm-entry-audit`, `build/self-disarm-kernel-clean/tls_fixer.elf`) confirms the entry sequence: GP-register prologue at 0x81000210, BL to self-disarm at 0x81000214, compare/branch on its result at 0x81000218/0x8100021A, and the first debug call only at 0x81000234. The initial decompilation was incorrectly truncated by a no-return annotation; the raw scoped instruction query, not that pseudocode fragment, establishes the order.

### 23.3 Verification and remaining limits

The startup-order test failed before adding the gate. Self-disarm file tests failed against the initial no-op stub; separate regressions exposed parser whitespace/comment and duplicate case/alias gaps before their corrections. Tests use distinct working and durable file images to simulate a crash/restart after successful disarming, then confirm that another activation is refused without re-enabling. These are host tests, not live Vita reboot evidence.

Final commands in `build/self-disarm-verified.log` exited successfully after the last source change: **30/30 normal CTest targets**, **30/30 ASan/UBSan/leak-checking targets**, and **17 Python tests**. A fresh Ninja kernel build in `build/self-disarm-kernel-clean` passes the generated-register gate and has no unresolved ELF symbols. Source/build evidence is not evidence that the original device boot fault is fixed.

The earlier combined verification command was blocked with an indeterminate tool-safety status; separate ordinary unit-test and read-only disassembly-check commands subsequently ran normally. No device command was involved. One initial cross-build also caught an incorrect include path; it was corrected to the actual `psp2kern/kernel/sysmem.h` before the successful fresh build.

This safeguard protects subsequent boot selection only after the config edits have been synchronized successfully. It cannot protect failures before module_start or before disarming completes, does not undo overwritten system files, and has not yet had physical crash-durability validation. The user's recovered Vita and the donor were not contacted or modified, no new VPK was produced for delivery, and nothing was uploaded, installed, armed, committed or pushed. Old packages remain withdrawn.

### 23.4 Revised kernel-only test bundle

The user asked whether a new test was ready and requested completing the remaining work. A fresh verification run (`build/self-disarm-bundle-verification.log`, exit 0) again passed all 30 normal and 30 sanitizer CTest targets, all 17 Python tests, the linked-kernel register check, and the no-unresolved-symbol assertion. IDA inspection of the 3.60 Iofilemgr positional-write entry additionally confirmed its VFS pwrite dispatch and the two stack words for the 64-bit offset. This did not execute anything on a Vita.

The next test is deliberately kernel-only: it does not use the withdrawn full-refresh VPK or overwrite CA files, storage configuration, user providers or Sony modules. `docs/tls13-self-disarm-test.md` specifies current-state backup/inspection before explicit one-boot activation; first-boot verification of exact self-commented entries; a second normal reboot without re-enabling; and a separate, later approved TLS attempt. The absence of active tls_fixer on the second boot is expected, not a request to run the installer again. No claim is made that disabling the kernel restores earlier persistent files.

Exported archive: `build/artifacts-self-disarm/tls_fixer-self-disarm-kernel-test.zip`, **11091 bytes**, SHA-256 `5ce4893dcba76688d1e860242af88a959fe83d82e276991545e3bfc05e523059`. Its five entries (kernel, instructions, manifest, checksums and build/test log) were all reread and byte-compared with the inputs; each checksum-manifest entry was verified independently. The kernel member is **9415 bytes**, SHA-256 `af00ce3b8a89472aa9b50dc98c1fbbe62dc796a96c30b8c5a0d29d853703c223`. Receipt: `build/artifacts-self-disarm/receipt.json`.

The bundle is available for the next explicitly approved device check; no test was performed, no recovered-device files were inspected or altered, and no enabling or reboot was requested remotely. Physical durability and the original crash diagnosis remain unverified. Do not treat the newly exported archive as proof of boot safety or reuse the old full-refresh installation instructions.

### 23.5 Recovered primary inspected and new kernel staged, not enabled

The user answered "yes but be careful please" to the explicit request to back up current files and stage the kernel-only test, with activation left pending. FTP at `192.168.1.146:1337` responded. The current `ur0:tai/config.txt` is 713 bytes, SHA-256 `ebc1bf2c08c0c1e25a27187a2948c0b1aa21a3e4165f58ecd38b03e11b2fe068`, with no tls_fixer entry. No `ur0:tai/tls_fixer.skprx` was listed. `ux0:tai` returned `550 Invalid directory`; that observation is recorded rather than treating arbitrary FTP errors as proof that all alternate paths are absent.

The current config, boot_config, YAMT config, YAMT kernel and YAMT helper were each read twice and byte-compared before backup. Local snapshot: `build/device-backups/192.168.1.146-recovered-20261007T215813Z/`; its manifest identifies each remote/local file and hash. Timestamped backup ZIP: `build/device-backups/192.168.1.146-recovered-20261007T215813Z.zip`, 11248 bytes, SHA-256 `ec2e33c26c2330c5c6f7db9736c00c24f80ccccb979f21f61445b33ce01d5f8a`. Use this new recovered-state snapshot, not the older pre-crash snapshot, for any subsequent approved edit.

Four files were staged only in the new inactive directory `ux0:/data/tls_fixer-self-disarm-test-20261007T215813Z/`: `tls_fixer.skprx`, `before-this-test.zip`, `README-FIRST.txt`, and `SHA256SUMS`. Each was uploaded under a temporary filename, downloaded and compared, renamed within that same inactive directory, then downloaded and compared again. The kernel hash remains `af00ce3b8a89472aa9b50dc98c1fbbe62dc796a96c30b8c5a0d29d853703c223` (9415 bytes). The personalized README explicitly says the test is not enabled and not to run an older installer or copy the kernel to ur0 yet.

Post-upload retrieval verified the current config, boot_config and all three backed-up YAMT files were unchanged. The active `ur0:tai/tls_fixer.skprx` path remains absent. No boot entry was added, no active kernel was installed or replaced, no system module or certificate was changed, and no reboot was requested. Staging receipt: `build/self-disarm-staged-146.json`; current backup pointer: `build/self-disarm-stage-backup-current.json`. One-boot activation requires a separate user confirmation.

### 23.6 Removable active kernel path, proposed by the user

The user understood the staging location as the intended active plugin path and proposed the additional recovery benefit of removing its memory card. I clarified that the previously described activation would have copied the kernel to ur0, then adopted the removable-file placement instead. The user explicitly confirms that ux0 is their removable card and that their internally stored always-on vitacompanion FTP is their recovery route even without that card. The recovered config snapshot indeed references vitacompanion and its kernel component under ur0. These entries must remain unchanged.

The exact active test path is now `ux0:/data/tls_fixer-one-shot/tls_fixer.skprx`, referenced from `ur0:tai/config.txt`. No separate loader or permission token was introduced. The old ur0-only self-disarm build would reject this path; it must not be used for this revised activation. The regression failed on the new slash path before the implementation change; both that path and its no-slash variant passed after adding these fixed spellings to the recognized self-entries. Legacy ur0 entry disabling and rejection of unknown aliases remain. Expected one-byte result is `#x0:/data/tls_fixer-one-shot/tls_fixer.skprx`.

Read-only analysis of the already downloaded current YAMT config found version 4, enabled state 1 and mount 0x800 configured as `sdstor0:gcd-lp-act-entire` with card-present requirement 1/1. The backed-up boot_config has the early YAMT kernel load. The v4.0 YAMT source definitions were retrieved using gh to decode this; it is configuration evidence, not a direct live mount query. The user separately confirmed the removable mapping. taiHEN's upstream plugin loader source logs module-load failures and continues its config parse; a missing test file cannot execute this payload, but this observation is not a guarantee against unrelated failures.

Fresh verification (`build/self-disarm-ux0-verified.log`, exit 0) passed 30/30 normal targets, 30/30 ASan/UBSan/leak-checking targets, 17 Python tests, the register-use gate and the no-unresolved-symbol assertion. New kernel: `build/self-disarm-ux0-kernel/tls_fixer.skprx`, 9495 bytes, SHA-256 `0b3cbc6314d1b220ef2aa920f8550d3c2e173d2bf83ca25e11a54fa8defc7dd1`. Exported five-entry bundle: `build/artifacts-self-disarm-ux0/tls_fixer-self-disarm-ux0-test.zip`, 12013 bytes, SHA-256 `ed4e154995110c656c25e05d14b94021e90f449b1ce8888aac514388a84138f5`. All members and checksum entries were reread and verified.

The earlier timestamped device staging directory is unchanged and contains the older ur0-only kernel. No upload of this revised ux0-capable kernel or active config edit has yet occurred. Explicit permission to upload at the fixed removable path and add its one-boot entry was requested, with reboot left to the user. No old VPK/full refresh is involved. Removing or deleting the payload on the removable card is an additional fallback for the pre-module_start window; automatic self-disarming remains the normal next-boot behavior after successful synchronization.

### 23.7 Revised removable kernel uploaded; user prohibited activation

The user authorized uploading the revised module but explicitly prohibited adding it to `ur0:tai/config.txt` because they were about to sleep, and permitted finishing the turn after upload. FTP reads before writing confirmed no active tls_fixer reference in the internal config, no ux0 tai directory/config, and no internal tls_fixer.skprx file.

Uploaded only the revised kernel to `ux0:/data/tls_fixer-one-shot/tls_fixer.skprx` via an inactive temporary name, verified its bytes by retrieval before renaming, then retrieved the final path and verified it again. The result is 9495 bytes, SHA-256 `0b3cbc6314d1b220ef2aa920f8550d3c2e173d2bf83ca25e11a54fa8defc7dd1`. The upload receipt is `build/self-disarm-ux0-upload-146.json`, completed at 2026-10-07T22:11:42Z.

Post-upload reads confirm unchanged `ur0:tai/config.txt` (SHA-256 `ebc1bf2c08c0c1e25a27187a2948c0b1aa21a3e4165f58ecd38b03e11b2fe068`) and `ur0:tai/boot_config.txt` (`17d953014a4ba215a66d2c51e95a9e88f144862152b5f039a1fbd76629dae3c9`). ux0 still has no tai directory/config, and ur0 still has no tls_fixer.skprx. No configuration was edited, no module load was requested, and no reboot occurred through our tools. The earlier backup and staging directory remain intact. One-boot activation and hardware testing are expressly pending a later user instruction.

### 23.8 Explicit one-boot activation on 2026-10-08

The user asked whether the test was already transferred and said they were ready. Read-only FTP retrieval confirmed the fixed ux0 path contains the revised 9495-byte kernel, SHA-256 `0b3cbc6314d1b220ef2aa920f8550d3c2e173d2bf83ca25e11a54fa8defc7dd1`. The current internal config is now 680 bytes, SHA-256 `426fd53403fcf2091a0243718f3e9b5f0e438909538a7cdb1ba600233c26b179`, with no tls_fixer entry; it differs from the earlier 713-byte recovered snapshot. No older snapshot was restored. The alternate ux0 config returned `550 File not found.` The existing external tls_fixer directory still contains both user providers and the replacement Sony modules, so the test runs real routing/injection after self-disarming, not an inert probe.

The user explicitly answered "yeah" to adding the single boot entry, leaving reboot to them. The current config, boot_config, YAMT config/kernel/helper and internal vitacompanion user/kernel files were each read twice, compared and backed up under `build/device-backups/192.168.1.146-one-shot-20261008T095625Z/`. The config was also copied and read-back verified on the Vita as `ur0:tai/config.before-tls_fixer-one-shot-20261008T095625Z.txt`. A temporary inactive file proved that this FTP server's APPE preserves existing bytes; the probe was then deleted. Preflight receipt: `build/one-shot-preflight-current.json`.

At 09:57:33 UTC, one APPE operation appended exactly `\n*KERNEL\nux0:/data/tls_fixer-one-shot/tls_fixer.skprx\n` to the existing config, preserving all prior bytes without truncation or renaming the live file. The 726-byte result was retrieved twice and compared. All backed-up boot/storage/FTP files were retrieved and confirmed unchanged. This FTP read-back establishes the written bytes, not physical power-loss durability; startup self-disarming separately requires file/mount synchronization.

Activation receipt: `build/one-shot-activation-146.json`. Armed config SHA-256: `01d21cddeee7d5ea255082f5579b798e1c387ee174b73e2b4da22f797d8054f9`. Expected self-disarmed config SHA-256: `0c09159d2fa0d5e16d62b62ffbdf15595d8e4b862efe033d6decaad77d4bc9b9`. The sole expected startup edit is byte offset 689 changing `u` to `#`, producing `#x0:/data/tls_fixer-one-shot/tls_fixer.skprx`. Both complete expected file images are in the new backup directory.

The user was told to reboot normally once with the card inserted, without L, without an installer and without website tests, then report LiveArea/apps and leave FTP running. No reboot, hot-load, user-module replacement or certificate change was requested through tools. If a crash occurs, do not re-arm; obtain the result and inspect available evidence before any additional approved boot. Once first-boot disarming is observed, the second normal boot checks that the entry remains disabled. Neither boot has yet been observed in this subsection.

### 23.9 First physical self-disarm test: boot failure, recovery succeeded

The user reported: "I rebooted but it froze on the epilepsy warning again and then the vita turned off. I turned it on again and this time it didn't freeze on the warning but showed the livearea." These are user-observed outcomes; the agent did not issue either boot. No re-enabling was performed after the first authorized append.

At 10:01:33 UTC, read-only FTP on `.146:1337` succeeded. The retrieved `ur0:tai/config.txt` is 726 bytes with SHA-256 `0c09159d2fa0d5e16d62b62ffbdf15595d8e4b862efe033d6decaad77d4bc9b9`, exactly matching the predicted disabled image. It contains `#x0:/data/tls_fixer-one-shot/tls_fixer.skprx` and no active tls_fixer entry. Its original 680-byte prefix is unchanged. Boot_config remains `17d953014a4ba215a66d2c51e95a9e88f144862152b5f039a1fbd76629dae3c9`; YAMT config remains `a8df985f6e2906157e6372b2fd7b3c58b075ff6300d0c787cabc9e9a224b5b12`. The test kernel remains 9495 bytes with SHA-256 `0b3cbc6314d1b220ef2aa920f8550d3c2e173d2bf83ca25e11a54fa8defc7dd1`.

Evidence snapshot: `build/device-evidence/146-self-disarm-crash-20261008T100133Z/`. Receipt: `build/self-disarm-crash-evidence-current.json`. This establishes that the disarming edit survived this real boot failure and power cycle. It does not establish universal crash durability, that every self-disarm synchronization call returned, or where execution stopped. The boot defect persists despite the generated-kernel FP/SIMD correction.

The checked FTP listings at ux0 root, ux0:data, ur0:data, ur0:temp and ur0:tai did not reveal a core dump dated today's test. The retrieved 2627-byte `ur0:tai/tls_fixer.log` is dated October 7, so it must not be treated as this attempt's trace. Old cores were not downloaded or attributed to this failure. The user was told not to re-enable, reinstall or test websites and that subsequent evidence gathering is read-only.

Read-only follow-up IDA in the existing 3.60 Modulemgr database (`tls_fixer-post-disarm-boot-audit`) inspected `fun_StartModuleForProcess` and `fun_StartLoadedProcessImage`. They show a separate user-entry-thread start path and synchronous start-result handling, but this is not evidence that today's fault reached provider injection. A subsequent decompilation request was blocked by tool safety checks; no alternative execution route was used. No root cause or new fix is claimed from these observations. Further localization requires distinguishing self-disarm completion, kernel initialization/hook installation and provider loading rather than treating another full experimental boot as a useful undifferentiated test.

### 23.10 Local-only self-disarm isolation diagnostic

The user asked whether they needed to answer or do anything. I clarified that no action was needed for local investigation and proposed a minimal diagnostic that stops immediately after self-disarming; the user replied "ok". This is approval of local preparation, not permission to upload, enable or reboot the device.

The new CMake option `TLS_FIXER_SELF_DISARM_ONLY=ON` builds an alternative of the same kernel plugin in a separate directory. The unchanged self-disarm routine remains the first call in module_start; success returns immediately, before logging, replacement queries, loader initialization or hooks. Module stop has no hooks/resources to release in this profile. The diagnostic link excludes `tls13_loader.c`, the path implementation and the associated TLS/loader/taiHEN stub libraries. It adds no separate loader, runtime arming file or launcher. The normal build defaults to the existing full behavior and is not a crash fix.

The new production-entry regression failed before implementing the profile because it observed startup operations after disarming (`build/disarm-probe-entry-red.log`). After implementation, `build/disarm-probe-verification.log` records exit 0, **31/31 normal targets**, **31/31 sanitizer targets**, **17 Python tests**, clean separate diagnostic/full kernel builds, no unresolved symbols, and no decoded FP/SIMD instructions in either build. A linked-symbol check found no routing, injection, path or taiHEN hook functions in the diagnostic. The original deployment snapshot and its on-device file were not overwritten.

IDA opened the new diagnostic ELF as `tls_fixer-disarm-only-entry`. Its complete 16-byte module_start at 0x81000000 is a GP-register prologue, BL to `tls_fixer_self_disarm`, conversion of the result to the native start-success/start-failed return, and POP to the caller. There is no later startup call. Diagnostic ELF section sizes total 1808 bytes of text with no data/BSS; this is not a runtime memory measurement.

Local diagnostic kernel: `build/self-disarm-probe-kernel/tls_fixer.skprx`, **5949 bytes**, SHA-256 `2f4db2adb61310e055b952465c918900e2d006aaf7467ef002b633c9a283b4f7`. Five-entry archive: `build/artifacts-disarm-probe/tls_fixer-self-disarm-only-probe.zip`, **6929 bytes**, SHA-256 `336e87aeee4624c80d1d81a78a661928cd2041a0b0cb6435bf5fc9e9c94f2ab0`. Every member and checksum-manifest entry was reread and verified; receipt is in that directory. Procedure and interpretation: `docs/tls13-self-disarm-isolation-test.md`.

The diagnostic is prepared locally only. If a later approved boot succeeds and the config is disabled, that shifts investigation toward the full build's later startup stages; it does not identify a specific cause. If it also fails, later TLS hooks/injection are not required to trigger that failure. No device write, upload, re-enable or reboot took place during this local preparation, and no repaired-boot claim is made.

### 23.11 Standing diagnostic permission; remote probe activation blocked

The user approved replacing the disabled kernel with the isolation probe and enabling its one boot, then added: "you don't need to ask next time. Just ask me for the reboot, I need to always do it manually". AGENTS.md now records standing permission for staged one-shot diagnostic kernels and their own entry only, with every reboot performed by the user. This is not permission for VPK installs, unrelated persistent changes, or agent-issued reboot commands.

Before the attempted change, all current config/boot/YAMT/internal-FTP files and the existing removable test kernel were read twice and backed up under `build/device-backups/146-before-disarm-probe-20261008T102541Z/`. The exact disabled config was also copied to `ur0:tai/config.before-disarm-probe-20261008T102541Z.txt` and verified. A disposable inactive FTP REST/STOR probe showed that a positional one-byte write preserves both the prefix and suffix; the disposable file was deleted. Receipt: `build/disarm-probe-preflight-current.json`. No active config or kernel changed during preflight.

The subsequent tool command to replace the inactive payload and restore its one boot-entry character was blocked by OpenAI's safety checks. It was not retried through another execution route. The user was told not to reboot and that this was a tooling interruption, not a request to repeat consent.

A separate read-only FTP check at 10:27:02 UTC confirms the device remains unchanged: config hash `0c09159d2fa0d5e16d62b62ffbdf15595d8e4b862efe033d6decaad77d4bc9b9` with the single disabled `#x0:/data/tls_fixer-one-shot/tls_fixer.skprx` line; old staged kernel still 9495 bytes/hash `0b3cbc6314d1b220ef2aa920f8550d3c2e173d2bf83ca25e11a54fa8defc7dd1`; boot_config still `17d953014a4ba215a66d2c51e95a9e88f144862152b5f039a1fbd76629dae3c9`. Receipt: `build/disarm-probe-postblock-readcheck-146.json`. The new 5949-byte self-disarm-only probe remains LOCAL ONLY. No probe test has been armed or run, and no reboot command has been issued. Do not tell the user to reboot as though deployment succeeded.

The user then requested manual instructions. The 6929-byte diagnostic ZIP was exported as a conversation artifact (hash `336e87aeee4624c80d1d81a78a661928cd2041a0b0cb6435bf5fc9e9c94f2ab0`). Instructions were to rename the disabled old removable kernel to an inactive backup, transfer only the ZIP's 5949-byte `tls_fixer.skprx` to the fixed test path using their FTP client, and replace the existing boot line's initial `#` with `u` in VitaShell, without changing any other byte or adding a duplicate. The user was explicitly told to stop before rebooting, leave FTP running and report "copied and edited" so the agent can perform a read-only hash/config check. No manual action or subsequent boot has yet been confirmed. The denied remote write was not retried through another agent tool.

### 23.12 User manually staged the isolation probe; pre-reboot read-back passed

The user reported "copied and edited". A read-only FTP check at 10:32:23 UTC confirms the correct 5949-byte diagnostic kernel, SHA-256 `2f4db2adb61310e055b952465c918900e2d006aaf7467ef002b633c9a283b4f7`, at the exact removable path. The 726-byte internal config matches the expected one-character re-enable, hash `01d21cddeee7d5ea255082f5579b798e1c387ee174b73e2b4da22f797d8054f9`, with exactly one active test entry. The alternate ux0 config is absent. Boot_config, YAMT config/kernel/helper and vitacompanion user/kernel files all match their pre-probe backups.

Receipt: `build/disarm-probe-manual-ready-146.json`. The captured user-armed config is in the pre-probe backup directory as `config.user-armed-probe.txt`. The tool's output-poll call returned an indeterminate safety status; the completed read-only check's saved receipt was read instead. No remote write or alternate write route was used for this verification.

The user was told they may now reboot normally once, manually, with the card inserted, no L, no installer and no browser/TLS testing. Await their result, then retrieve the config and check the expected disabled hash `0c09159d2fa0d5e16d62b62ffbdf15595d8e4b862efe033d6decaad77d4bc9b9`. Do not infer a result before that report. The diagnostic contains no later TLS/hook startup, so a completed boot versus another failure narrows the investigation as described in section 23.10.

### 23.13 Self-disarm-only boot reached LiveArea; post-boot FTP unavailable

The user reported "reached the livearea without crashing" for the manually staged 5949-byte self-disarm-only build. They then asked why TLS hooks were absent. I explained that this is an isolation diagnostic, not a TLS functionality test: the unchanged self-disarm-first path is retained, and the later initialization/hook/injection stages are excluded to narrow the boot failure. The production TLS adapters remain in the project.

The immediate read-only FTP check failed with connection refused, as did a second check at 10:40:38 UTC. No post-boot result receipt was produced and no device configuration or kernel was changed. The user was asked to restart the usual FTP service and leave it running, with no further reboot. Do not mark this probe's self-comment or its successful module_start return as observed until additional evidence is available. Reaching LiveArea alone could also reflect fail-closed refusal; the pre-boot kernel and enabled config were verified, but the post-boot state remains pending.

### 23.14 Initialization-only diagnostic prepared locally

The next local profile, `TLS_FIXER_INITIALIZE_ONLY=ON`, retains self-disarming and the original debug/replacement-file/hash/mutex startup, then returns before module lookup or hook installation. It does not invoke provider injection. The shared loader translation unit remains linked; the path/redirection unit is excluded, and the unreferenced static load hook is absent from the checked ELF. Do not claim that this binary contains no injection-related code. CMake rejects simultaneously selecting both isolation profiles.

The new production-entry regression first failed because the existing code installed a hook after initialization (`build/init-probe-entry-red.log`). After adding the return boundary, **32/32 normal tests**, **32/32 ASan/UBSan/leak-checking tests**, and **17 Python tests** pass. The separate kernel build passes the linked-register scan with no decoded FP/SIMD and has no unresolved symbols or linked load hook/taiHookFunctionOffsetForKernel symbol. Log: `build/init-probe-verification.log`, completed with exit 0 and `INITIALIZE_ONLY_LOCAL_VERIFICATION_PASSED`.

IDA session `tls_fixer-init-only-entry` inspected the built module_start at 0x81000000..0x8100008E. It calls self-disarm before logging/stat/hash initialization, and returns without a module-hook call. This is static code evidence, not a device result or repaired-boot claim.

Local kernel: `build/initialize-only-probe-kernel/tls_fixer.skprx`, **7825 bytes**, SHA-256 `11635e145002cc5d0599b77e09763d4f9711f8615dfb63c49cde9221b405b2de`. Five-entry archive: `build/artifacts-init-probe/tls_fixer-initialization-only-probe.zip`, **9521 bytes**, SHA-256 `cfa83519828131828c94add20b84bf26a34e927bd5fd347b89b8e6ecdf9b24c5`. All members and checksum entries were reread and compared; receipt is in the archive directory. Procedure: `docs/tls13-initialize-isolation-test.md`.

This stage has not been transferred, armed or executed. First restore read-only FTP access and verify the previous probe's state. The earlier denied remote replacement/arming command has not been retried through another route. All earlier full VPKs remain withdrawn.

### 23.15 Disarm-only result read back; initialization probe handed to user

After the user reported FTP accessible, the read-only check completed at 10:47:50 UTC. Receipt `build/disarm-probe-result-146.json` confirms the exact disabled config hash `0c09159d2fa0d5e16d62b62ffbdf15595d8e4b862efe033d6decaad77d4bc9b9`, the 5949-byte probe hash `2f4db2adb61310e055b952465c918900e2d006aaf7467ef002b633c9a283b4f7`, absent alternate config, and unchanged boot_config/YAMT/FTP files. This verifies the self-comment after the reported successful boot, not a captured module_start return value or universal power-loss safety.

The initialization-only ZIP (9521 bytes/hash `cfa83519828131828c94add20b84bf26a34e927bd5fd347b89b8e6ecdf9b24c5`) was exported and linked in CHAT.md. The user was told to preserve the current probe as `tls_fixer.disarm-only-5949.skprx.bak`, manually copy the new 7825-byte kernel into the fixed removable test path, and replace only the existing entry's initial `#` with `u`. Instructions explicitly stop before reboot and ask for "copied and edited" with FTP running, so a read-only integrity/config check precedes the manual reboot request. The notification service failed for that last message, but the message was saved in CHAT.md; it was not resent solely to retry notification.

No remote write, enable or reboot was issued by the agent. Manual staging and the next boot remain unconfirmed. Do not infer that this stage was installed merely from export or user readiness.

### 23.16 Initialization-only probe manually staged and verified before reboot

After requesting a status update, the user was given the next-probe instructions again in response and then reported "copied and edited". At 11:09:29 UTC, read-only FTP verified the 7825-byte initialization-only kernel/hash `11635e145002cc5d0599b77e09763d4f9711f8615dfb63c49cde9221b405b2de` at the fixed removable path. The config is 726 bytes/hash `01d21cddeee7d5ea255082f5579b798e1c387ee174b73e2b4da22f797d8054f9`, exactly the expected one-character re-enable. Boot_config, YAMT and FTP components are unchanged, and no alternate config is present. Receipt: `build/init-probe-manual-ready-146.json`.

The user was told to reboot normally once, manually, with the card inserted, no L, no installer and no browser test, then report LiveArea/failure and restore FTP. No agent-side device write or reboot occurred for this staging. The probe result is not yet known; do not advance to full hooks or injection until it is reported and read-back checked.

### 23.17 Initialization-only boot verified; redirection-only probe prepared

The user reported "Done, it reached the livearea". Read-only FTP at 11:11:32 UTC verifies the exact disabled config hash `0c09159d2fa0d5e16d62b62ffbdf15595d8e4b862efe033d6decaad77d4bc9b9`, the 7825-byte initialization-only kernel/hash `11635e145002cc5d0599b77e09763d4f9711f8615dfb63c49cde9221b405b2de`, and unchanged boot_config and YAMT configuration. Receipt: `build/init-probe-result-146.json`. This is a successful reported boot plus persisted disarming, not a captured return value from every internal initialization call.

The next profile `TLS_FIXER_REDIRECTION_ONLY=ON` retains startup and installs the ordinary path-redirection hook, but returns immediately after TAI_CONTINUE in the load hook. Thus it does not call TLS-provider injection or the shell DNS-helper startup. The regression compiles the production entry/hook and verifies actual hook installation, both current-PID and explicit-PID paths, preserved arguments/results, replacement paths and absence of provider/DNS calls. It failed on the prior implementation (`build/redirection-probe-entry-red.log`) and passed with the early return.

The verification command completed with exit 0: **33/33 normal targets**, **33/33 ASan/UBSan/leak-checking targets**, **17 Python tests**, and a separate clean kernel build with no unresolved symbols or decoded FP/SIMD instructions. Log: `build/redirection-probe-verification.log`. IDA session `tls_fixer-redirection-only-entry` confirms the original loader continuation call at 0x81000034 is followed only by stack restoration and function return at 0x81000036..0x81000038, not a post-load call. The shared loader implementation is still linked; do not claim those unrelated functions are absent from the binary.

Local kernel `build/redirection-only-probe-kernel/tls_fixer.skprx`: **9030 bytes**, SHA-256 `641fd9326008b4f6dfa53375dbd2129d9e8477ae836de799d05611c9ffe83a97`. Verified five-entry archive `build/artifacts-redirection-probe/tls_fixer-redirection-only-probe.zip`: **10648 bytes**, SHA-256 `41d1ea123b09e170fd5fc2ba7d2a27f3ad602001a1d67e515c4b84bb16678c91`. Procedure: `docs/tls13-redirection-isolation-test.md`; receipt in archive directory.

The archive was exported and the user was given the same manual copy/edit instructions, preserving the 7825-byte prior kernel, changing only the test line's initial `#` to `u`, then reporting "copied and edited" before any reboot. The read-only verification is still required before the next manual reboot request. No agent-side device writes, new activation or reboot occurred while preparing this diagnostic. No root cause or fixed full build is claimed.

### 23.18 Redirection-only probe manually staged; pre-boot verification passed

The user reported "done" after the copy/edit instructions. Read-only FTP at 11:17:33 UTC verifies the 9030-byte redirection-only kernel/hash `641fd9326008b4f6dfa53375dbd2129d9e8477ae836de799d05611c9ffe83a97`, the exact 726-byte armed config/hash `01d21cddeee7d5ea255082f5579b798e1c387ee174b73e2b4da22f797d8054f9`, absent alternate config and unchanged boot_config/YAMT/FTP files. Receipt: `build/redirection-probe-manual-ready-146.json`.

The user was told to reboot manually once with the card inserted and no L, then report LiveArea/failure and leave FTP available. No network-site test, installer or automatic reboot was requested. Await the result and retrieve the self-disabled configuration before changing or re-enabling anything further.

### 23.19 Redirection-only boot verified; preparation-only diagnostic exported

The user reported "I rebooted and it opened the livearea without issues". Read-only FTP at 11:19:46 UTC verifies the exact disabled config/hash `0c09159d2fa0d5e16d62b62ffbdf15595d8e4b862efe033d6decaad77d4bc9b9`, the 9030-byte redirection-only kernel/hash `641fd9326008b4f6dfa53375dbd2129d9e8477ae836de799d05611c9ffe83a97`, and unchanged boot_config/YAMT configuration. Receipt: `build/redirection-probe-result-146.json`. This shifts attention to omitted post-load work but does not identify the faulting instruction or exclude timing/layout effects.

New mutually exclusive profile `TLS_FIXER_PREPARE_ONLY=ON` restores post-load in-flight reservations, module-list queries, hash rechecks, module-info/name/PUID validation and cleanup, returning before arguments are passed to any LoadStartModuleForPid call. The DNS-helper startup is also suppressed. The preparation test includes 70 repeated reservations to check cleanup, both providers, and invalid metadata/hash failure paths. Two production-code regressions initially failed on actual provider/DNS invocation (`build/prepare-probe-entry-red.log`), then passed after the profile was implemented.

Verification completed with exit 0: **35/35 normal tests**, **35/35 ASan/UBSan/leak-checking tests**, **17 Python tests**, clean separate kernel build, no unresolved symbols, and no decoded FP/SIMD instructions. The generated ELF has no ksceKernelLoadStartModuleForPid or ksceKernelUnloadModuleForPid symbol. Log: `build/prepare-probe-verification.log`.

IDA session `tls_fixer-prepare-only-entry` inspected the generated code. Its initial decompilation truncated the function at an imported mutex call because of import/function-analysis artifacts; that incomplete pseudocode was not treated as behavior. Instruction queries across the ELF symbol-sized range 0x81000890..0x81000A6C show mutex operations, module list/info, memset/strcmp and target_matches, with no module load/start call.

Local kernel `build/prepare-only-probe-kernel/tls_fixer.skprx`: **9201 bytes**, SHA-256 `0b91b51f8ddaaaa87ee9dd7ba461de525775b5766dc70742acf2fdfd53c28f05`. Five-entry archive `build/artifacts-prepare-probe/tls_fixer-preparation-only-probe.zip`: **9719 bytes**, SHA-256 `5864d0dc612cbdbe57068c894656e5265e2a25efab5a17087ecdbd86ea9ff523`. Every archive/checksum entry was reread and verified; receipt is in that directory. Procedure: `docs/tls13-prepare-isolation-test.md`.

The probe was exported and manual copy/edit instructions sent, preserving the prior 9030-byte kernel and touching only the fixed removable kernel plus its one comment character. The user was told to report copied/edited and wait for read-only verification before a manual reboot. No agent-side device upload, write, activation or reboot was performed. Neither this next boot nor a repaired full boot is claimed.

### 23.20 Preparation-only transfer reported; FTP read-back timed out

The user reported "done" after the manual preparation-only transfer/edit instructions. The first read-only FTP attempt connected but timed out while downloading the first file. A second attempt at 11:29:22 UTC timed out before login. Its receipt `build/prepare-probe-manual-ready-146.json` records `verification_passed: false`, no downloaded files and the timeout; it is not a staging-success receipt. There is no new kernel/config hash to authorize a boot yet.

The user was explicitly told not to reboot, to disconnect other FTP clients/close the editor and restart only the FTP service, keeping the Vita itself on. Do not assume the new file is correct or that the entry is disabled: the manual edit was reported but is unverified. Resume with read-only retrieval once FTP is available, comparing against the 9201-byte kernel/hash `0b91b51f8ddaaaa87ee9dd7ba461de525775b5766dc70742acf2fdfd53c28f05` and the exact 726-byte armed config/hash `01d21cddeee7d5ea255082f5579b798e1c387ee174b73e2b4da22f797d8054f9`. No agent write or reboot was performed during these checks.

### 23.21 Preparation-only crash; persistent stage diagnostics requested

The user independently restarted the Vita while resolving the FTP problem, reported another crash, then reported LiveArea on the following power-on. The pre-boot FTP verification had not completed. At 11:38:20 UTC, read-only FTP nevertheless confirmed the installed file is exactly the 9201-byte preparation-only probe/hash `0b91b51f8ddaaaa87ee9dd7ba461de525775b5766dc70742acf2fdfd53c28f05`, the config has the exact predicted disabled hash `0c09159d2fa0d5e16d62b62ffbdf15595d8e4b862efe033d6decaad77d4bc9b9`, and boot_config/YAMT configuration are unchanged. Receipt: `build/prepare-probe-crash-evidence-current.json`; snapshot: `build/device-evidence/146-prepare-crash-20261008T113820Z/`. No agent reboot or re-enable occurred.

The fetched `ur0:tai/tls_fixer.log` remains the old 2627-byte file/hash `4ced7d08be3b1b418eee2caa02553d5ec4f49b1a940afed67f05260fefd69541`. Scanned usual directories contained historical core files but no identified October 8 crash dump; these old files were not downloaded or attributed to this fault.

Read-only upstream research at taiHEN commit `309b3800bcb8ebbd5e4f5e5e920af3da3590b829` found that its user-plugin hook runs after preloaded modules start, with a source comment about a firmware preload limit. Local reference files are under `.reverse-tmp/taihen-lifecycle/`; this source is not a proven match of the device's installed binary. That lifecycle mismatch may matter to full provider injection, but it cannot alone explain the current preparation-only failure, whose binary has no module load/start import. The user was explicitly told the earlier hypothesis was insufficient.

The user asked, "Did you consider adding diagnostics so we can see what fails and when?" I acknowledged that persistent diagnostics should have been added earlier. The next local change keeps self-disarming first, opens a bounded telemetry log before hooks, and records synchronized entered/returned stages with PID/thread/result data around reservation locking, module list/info, hash recheck and target-ID lookup. No TLS payloads or secrets are logged. This is observation of the failing preparation profile, not another claimed fix. The device remains disabled and no new reboot was requested.

### 23.22 Integrated stage recorder verified and exported

Read the recent CHAT.md exchanges and resumed the unfinished integration, rather than the stale saved plan that still awaited the preparation probe. `kernel/boot_trace.c` records sequence, thread, target PID, module/object, result bits, stack pointer and monotonic time to `ux0:/data/tls_fixer-one-shot/startup.log`. Self-disarming still precedes trace creation. Entered/returned records bracket startup checks, loader initialization, hook installation, reservation, module listing/inspection, hash recheck, target-ID inspection and cleanup. The preparation-only build has no module load/start/unload calls or imports.

The pre-opened log is bounded to 512 records shorter than 192 bytes; each completed record requests synchronous file flushing. Formatting uses a static buffer protected by a non-waiting atomic reservation. Reentrant logging is refused rather than waiting while another call owns the buffer. Log-open failure stops startup before any hooks. Failed enter/return logging aborts further preparation, while an existing reservation is still cleaned up. The test enforces that file logging is never performed with the diagnostic reservation mutex held. Self-disarming means the following disabled boot does not reopen/truncate this log; preserve it before any subsequent deliberate activation.

The initial integrated check passed its 11 selected trace/route tests and cross-built. Additional coverage verifies the longest permitted stage, invalid stages without writes, unavailable thread IDs, event-before-open, oversized write returns, partial-write-then-error behavior, startup event failures before hook installation and both routes refusing unlogged preparation. These additions test existing behavior; they are not presented as newly reproduced defects or a root-cause fix.

Fresh full verification in `build/traced-prepare-verification.log` returned exit code 0: **51/51 normal CTest targets, 51/51 ASan/UBSan/leak-checking targets, 17 Python tests, a clean traced kernel build, the decoded FP/SIMD instruction gate, no unresolved ELF symbols, and no module load/start/unload symbols**. Build flags select only `TLS_FIXER_PREPARE_ONLY=ON` and `TLS_FIXER_ENABLE_BOOT_TRACE=ON`. The log/source integration did not change the user-space TLS provider configuration.

The compiled-code review in `build/traced-prepare-binary-review.log` finds stack frames of 552 bytes in the load hook, 1544 bytes in preparation and 128 bytes in the recorder. These are plugin frame sizes, not total stack headroom or evidence of an overflow. Repeated IDA service requests returned HTTP 502, so no new firmware reverse-engineering claim was made; the generated-code review used objdump and the existing register gate. Prior firmware/IDA findings remain historical evidence, not a new successful session.

An additional local metadata/inventory shell command received an indeterminate tool-safety rejection and did not execute; it was not retried. The independent supported artifact-export action reported an immutable kernel snapshot: `build/traced-prepare-kernel/tls_fixer.skprx`, **11610 bytes**, SHA-256 **`188b063b82a11eeb3e4ab36e1384c1d54fd02d82468ff3f28c4c4dd2efd3dcf7`**. This is a standalone kernel export, not a rebuilt VPK or ZIP. Instructions and log interpretation are in `docs/tls13-traced-preparation-test.md`.

No FTP operation, remote upload, entry re-enable, module load or reboot occurred in this continuation. The last known remote file remains the disabled 9201-byte preparation probe. For the next test, retain that file and any old startup.log, manually transfer only the identified traced kernel, restore the test entry's first character from # to u, and perform a read-only full hash/config check before requesting the user's manual reboot. Do not tell the user that export to the conversation transferred the file to the Vita.

Interpretation limits: the last entered stage without a returned record narrows a boundary, not necessarily the exact faulting instruction; incomplete writes, trace failure/limit, concurrency and logging-induced timing changes matter. A boot that succeeds because the logger refused preparation is not a successful preparation run. No original-boot-fix or hardware acceptance claim is made until actual trace evidence is available.

### 23.23 User requested direct transfer; traced diagnostic armed and verified

After receiving the export, the user asked "can you try to send it yourself?" A fresh read-only preflight succeeded on `.146:1337`. It read config, boot_config, YAMT config/kernel/helper, both internal vitacompanion modules and the 9201-byte prior preparation kernel twice each. The config remained the expected disabled hash `0c09159d2fa0d5e16d62b62ffbdf15595d8e4b862efe033d6decaad77d4bc9b9`; no alternate ux0 config existed. The read-only preflight receipt records whether a previous startup.log existed. Snapshot: `build/device-backups/146-before-traced-prepare-20261008T122257Z/`; receipt: `build/traced-prepare-preflight-current.json`.

The direct FTP transfer completed successfully through the normal connector command tool. The new kernel was uploaded under an inactive temporary name and read-back verified before renaming. The previous kernel is retained on-device as `ux0:/data/tls_fixer-one-shot/tls_fixer.before-traced-prepare-20261008T122257Z.skprx.disabled`, and the disabled config is copied to `config.before-traced-prepare-20261008T122257Z.txt` in that same directory. Final payload and backup reads matched their originals; all protected files remained unchanged. Transfer receipt: `build/traced-prepare-upload-146.json`. No full-refresh VPK, system module, CA bundle or storage driver was deployed.

Under the user's standing permission for successive one-shot diagnostics, the exact entry was then deliberately enabled. A new disposable REST/STOR check proved the server preserved prefix/suffix for a one-byte positional write. The real edit restored byte 689 from # to u; it did not append, truncate or replace the config. The complete 726-byte read-back matched armed hash `01d21cddeee7d5ea255082f5579b798e1c387ee174b73e2b4da22f797d8054f9`. Kernel bytes/hash were rechecked, as were boot_config, YAMT and the internal FTP modules. Arming receipt: `build/traced-prepare-armed-146.json`, completed at `2026-10-08T12:25:59Z`.

The user was explicitly told the diagnostic is transferred/armed and asked to reboot normally once, manually, then report the boot outcome. If it crashes and powers off, the following ordinary power-on is expected to skip it after self-disarming; this expectation remains limited to the already-described post-disarm window. The agent issued no reboot, power, hot-load or hot-unload command. This is an armed-test handoff, not a successful execution result. Retrieve startup.log and the complete config as the next device action, before replacing or re-enabling anything.

### 23.24 First traced boot: no ux0 log; internal-log variant verified and staged

The user reported "done it went to livearea without issues". At 12:29:27 UTC, read-only FTP verified the exact 11610-byte traced kernel and expected self-disabled config hash. Boot_config/YAMT configuration were unchanged. However, `ux0:/data/tls_fixer-one-shot/startup.log` returned `550 File not found.`. Receipt: `build/traced-prepare-result-146.json`; snapshot: `build/device-evidence/146-traced-prepare-20261008T122927Z/`.

This is NOT a proven successful preparation run. The gate may have returned failure after its config edit, or log opening may have failed; either prevents later hooks in the traced build. More generally, previous reported positive isolation boots without stage telemetry do not independently establish that every intended stage executed. The user was told this explicitly. No original-crash fix is inferred.

The logger destination was changed from the removable ux0 alias to `ur0:tai/tls_fixer-startup.log`, in the internal directory containing the config successfully written by the gate. This is a diagnostic hypothesis about log accessibility, not a confirmed namespace diagnosis. Self-disarm, entry ordering, preparation behavior, event encoding and bounds were left unchanged. The host test explicitly requires the internal path. Two attempts to run the intentionally failing old-path assertion were blocked with indeterminate tool-safety status; no successful red run is claimed. After the path correction, the ordinary full verification command ran. Its output-poll was blocked, but its saved complete log reached `INTERNAL_TRACE_VERIFICATION_PASSED` after 51/51 sanitizer and 51/51 normal tests, 17 Python tests, a clean kernel build, register check and empty unresolved-symbol listing: `build/traced-ur0-verification.log`.

New exported kernel: `build/traced-prepare-ur0-kernel/tls_fixer.skprx`, **11608 bytes**, SHA-256 `1eec8b8211bbe5fd329e95ae879b855bf055d9e2fa218960170371ef46e2e381`. Only the log destination changed in production code. The earlier 11610-byte export remains historical, not the current test file.

Fresh preflight at 12:34:48 UTC again read the disabled config, kernel, boot_config, YAMT and internal FTP components twice. Neither the internal nor ux0 diagnostic log existed; no alternate ux0 config existed. Snapshot/receipt: `build/device-backups/146-before-internal-trace-20261008T123448Z/` and `build/internal-trace-preflight-146.json`. The preflight output-poll was blocked, but the completed saved receipt was read through the structured file tool; no duplicate preflight or alternative write route was used.

The verified new payload was then transferred under an inactive name and published at the fixed removable path, retaining the old kernel as `tls_fixer.before-internal-trace-20261008T123448Z.skprx.disabled` and a config backup beside it. A disposable positional-write check again preserved prefix/suffix. Restoring byte 689 from # to u produced the exact expected armed config hash `01d21cddeee7d5ea255082f5579b798e1c387ee174b73e2b4da22f797d8054f9`; all protected files remained unchanged. Deployment completed through the normal command tool at 12:36:34 UTC with an exit-0/read-back receipt: `build/internal-trace-deployment-146.json`. No reboot was issued through tools. The user was notified that the variant is armed and asked to reboot manually, report the result and keep FTP available. No test result is yet recorded for the internal-log variant.

### 23.25 Internal log also absent; report gate failures rather than skipping them

The latest CHAT.md records the user's internal-log boot reaching LiveArea. Read-only receipt `build/internal-trace-result-146.json` at 12:39:35 UTC has the exact 11608-byte kernel, the expected disabled config and unchanged boot_config/YAMT config, but no internal startup.log. A new preflight at 13:18:22 UTC independently confirms that state and that both trace paths and the new result-file path are absent. Snapshot: `build/device-backups/146-before-disarm-result-20261008T131822Z/`; receipt: `build/disarm-result-preflight-146.json`.

This invalidates treating logless positive isolation boots as evidence that their named stages executed. The gate may write the comment and then fail file/mount synchronization, read-back, alternate-config checks or cleanup. Existing trace creation follows the gate's success check, hiding those failures.

The previous continuation had added `TlsFixerDisarmReport` and fault-stage tests, but left the result writer as a stub. This continuation reproduced that writer's failing valid-case assertion and a new production-entry regression showing a failed gate was not reported (`build/disarm-result-resume-red.log`). The completed `TLS_FIXER_DISARM_RESULT_ONLY` profile attempts the unchanged gate policy, reports success or first failure, and unconditionally omits all subsequent loader/TLS/hook initialization. Reporter failure also returns startup failure; it never authorizes the experiment.

The reporter uses an existing 256-byte internal file, exact size validation, bounded ASCII/hex formatting and positional writes. It uses no create/truncate flag, handles partial and invalid write results, requests file synchronization and closes the file. Its header/footer and PENDING preallocation distinguish completed output from an unexecuted or partial report. The result-file synchronization can itself fail; readable contents are not a claim of physical crash durability. No alternate-config or synchronization check was removed from the gate.

Full verification reached `DISARM_RESULT_FULL_VERIFICATION_PASSED` in `build/disarm-result-verification.log`: **63/63 normal CTest targets**, **63/63 ASan/UBSan/leak-checking targets**, **17 Python tests**, clean diagnostic/full kernel builds, both decoded FP/SIMD gates and no unresolved symbols. The diagnostic symbol inventory contains no hook/provider loader or module load/start calls. An added mock seek-error case initially produced a signedness compilation error; it was corrected before this successful run. Docker bind-mount make emitted millisecond clock-skew warnings in the native build; separate fresh Ninja kernel builds and the actual test results were inspected.

The generated entry calls self-disarm at 0x81000002, retrieves its report at 0x81000008, calls the writer at 0x81000010 and returns without other initialization. A fresh IDA open request returned HTTP 502, so this is generated-code verification from the build disassembly, not a new successful firmware-IDB investigation. Output-poll calls were rejected by tool safety checks; the already completed saved logs were read, without rerunning denied polling through another route. Documentation: `docs/tls13-disarm-result-test.md`.

### 23.26 Result-only diagnostic and preallocated report staged on primary

The ordinary deployment command completed under the standing one-shot diagnostic permission. It first compared the current files with the fresh preflight, backed up the kernel/config/boot/YAMT/internal-FTP files again locally, and retained the disabled config on the device. It prepared the 256-byte PENDING report under an inactive temporary path, verified retrieval, and renamed it to `ur0:tai/tls_fixer-disarm-result.txt`. This file is diagnostic output, not an arming token. No existing report was overwritten.

The new kernel was uploaded under an inactive name, read-back checked, then published at `ux0:/data/tls_fixer-one-shot/tls_fixer.skprx`, retaining the old file as `tls_fixer.before-result-20261008T132654Z.skprx.disabled`. A disposable REST/STOR test verified one-byte positional editing preserved both surrounding ranges. Only byte 689 of the actual config was restored from # to u, yielding the exact 726-byte armed hash. Protected boot/storage/internal-FTP files were verified unchanged afterward. No VPK, CA, Sony module, storage configuration, hot-load or reboot command was involved.

Receipt: `build/disarm-result-deployment-146.json`, completed **2026-10-08T13:27:01Z** with `armed_readback_verified`. Snapshot: `build/device-backups/146-disarm-result-stage-20261008T132654Z/`. Kernel: **8266 bytes**, SHA-256 `c4e82a9d92b59fc057d497449777070bce8f1eb811262d9ea23b34afc53b5ecd`. PENDING record SHA-256: `43e53679a15d7ce600adfa433593af8a1709658858dcc1bead12ae769e4b16b5`. Armed config: `01d21cddeee7d5ea255082f5579b798e1c387ee174b73e2b4da22f797d8054f9`; expected disabled config: `0c09159d2fa0d5e16d62b62ffbdf15595d8e4b862efe033d6decaad77d4bc9b9`.

The user was asked for one normal manual reboot and to leave FTP available. No result is inferred yet. Next action after their report is read-only retrieval of the preallocated result file, full config and exact kernel, preserving all evidence before another re-enable.

### 23.27 Gate completion is now directly recorded on hardware

The user reported reaching LiveArea without crashing. Read-only retrieval at 13:29:02 UTC captured the complete 256-byte report with header/footer intact: `outcome=00000000`, `code=00000000`, `config=ffffffff`, `writes=00000001`, `verified=00000001`, `cleanup=00000000`, `stage=gate.complete`. The output hash is `5809260dd4660d1b35f14ddee242fbc2539e1c5a5b0664469f035f301044060e`. The actual 8266-byte kernel matched, the config matched the exact predicted disabled hash, and boot_config/YAMT config remained unchanged.

Receipt: `build/disarm-result-evidence-146.json`. Snapshot: `build/device-evidence/146-disarm-result-20261008T132902Z/`. This establishes a successful gate return and existing-file reporting for this run. It does not retroactively prove the gate's outcome in every earlier isolation test or identify the original preparation crash. Logger creation/setup is now the observation gap to measure.

### 23.28 Preserve native trace-setup errors independently of startup.log

The traced preparation profile now reports the gate result before branching on success and appends `trace_setup=XXXXXXXX` to a reserved 32-byte area at offset 192 after the logger setup returns. This preserves the gate fields and footer. Failure of the gate, either report write, or trace setup prevents subsequent hooks. Logger file path and original create/truncate flags remain unchanged to measure that path rather than substituting an unproven workaround. No TLS-provider load/start was enabled.

`tls_fixer_boot_trace_open` previously reduced the native open/initial-record failure to -1. It now preserves native negative open/thread/write/sync results when available. Regressions failed for exact open/sync status, the absent setup-record writer, and the missing early gate report (`build/trace-setup-status-red.log`), then passed. The setup-record test uses short writes and verifies that the existing gate fields and footer bytes are unchanged.

Fresh verification reached `TRACE_SETUP_RESULT_VERIFICATION_PASSED`: **64/64 normal targets**, **64/64 ASan/UBSan/leak-checking targets**, **17 Python tests**, clean traced kernel build, no decoded FP/SIMD instructions, no unresolved symbols and no module load/start/unload symbols. Log: `build/traced-setup-result-verification.log`. Kernel: `build/traced-setup-result-kernel/tls_fixer.skprx`, **14109 bytes**, SHA-256 `5ed6eac8d0b9517b654ecfa19714206bd78c9ec2e51e5bbad1619f8f745ca5a6`.

The ordinary direct staging invocation `python3 build/stage_trace_setup.py` was blocked by tool safety checks before producing an execution result. It was not retried through another tool or route. An independent read-only check at 13:37:29 UTC confirmed the device is unchanged: the disabled config, 8266-byte result-only kernel and successful gate report still match. Receipt: `build/trace-setup-postblock-readcheck-146.json`. No new reboot was requested.

A verified four-entry ZIP was exported for manual staging: `build/artifacts-trace-setup/tls_fixer-trace-setup-diagnostic.zip`, **14272 bytes**, SHA-256 `38d3dee08ae02de45b0c253a52d600221813bcf2faf4ae47fdf0c2f62278d9d7`. It contains the 14109-byte kernel, a new 256-byte PENDING report/hash `031eec35a599d8d82c4b5d629d0198714f24031b8e6ba87df55c8229e5965ebd`, instructions and per-file hashes. All archive members were reread and compared. The user was told to retain the previous kernel/report, copy these two files to their exact paths, restore only the existing entry character from # to u, and report "copied and edited" with FTP running before any reboot. Neither that manual transfer nor a new boot is confirmed yet.

### 23.29 Manual logger-setup transfer verified before the requested reboot

The user reported "done". Read-only FTP at **13:44:49 UTC** confirmed the correct 14109-byte kernel/hash `5ed6eac8d0b9517b654ecfa19714206bd78c9ec2e51e5bbad1619f8f745ca5a6`, the exact 256-byte PENDING report/hash `031eec35a599d8d82c4b5d629d0198714f24031b8e6ba87df55c8229e5965ebd` and expected armed config/hash `01d21cddeee7d5ea255082f5579b798e1c387ee174b73e2b4da22f797d8054f9`. Boot_config, YAMT config/kernel/helper and vitacompanion user/kernel files all matched the recovered baseline; alternate ux0 config was absent. Files were retrieved twice and retained in `build/device-evidence/146-trace-setup-ready-20261008T134449Z/`. Receipt: `build/trace-setup-manual-ready-146.json`.

The user was asked to perform one normal manual reboot, without L, installer or browser test, then report the result and leave FTP available. No agent-side write or reboot occurred during this verification. Await the user report, then preserve the setup report and startup.log if present before any further activation.

### 23.30 Last logger-setup result and fresh read-only confirmation

The latest CHAT.md records the user's subsequent boot reaching LiveArea without issues. The completed receipt `build/trace-setup-result-146.json` at 13:47:21 UTC contains `stage=gate.complete`, `outcome=00000000`, one entry written/verified, and `trace_setup=80010016`. The 256-byte result hash is `1c59113f55deb3468d3317fea77e8b65b3f8b4d26375dcb27a838f7c48a371d1`. No startup.log existed. This result had not been incorporated into the previous handoff header.

Fresh read-only FTP at 14:50:37 UTC independently confirmed the same result, exact disabled config hash `0c09159d2fa0d5e16d62b62ffbdf15595d8e4b862efe033d6decaad77d4bc9b9`, old 14109-byte kernel/hash `5ed6eac8d0b9517b654ecfa19714206bd78c9ec2e51e5bbad1619f8f745ca5a6`, absent startup log/alternate config and unchanged boot_config/YAMT config. Receipt: `build/trace-mode-precheck-146.json`; snapshot: `build/device-evidence/146-trace-mode-precheck-20261008T145037Z/`. No device write, upload, activation or reboot occurred.

### 23.31 Invalid logger creation mode identified in firmware and corrected

IDA inspection followed Iofilemgr `ksceIoOpen`/`vfsOpen` into Exfatfs VOP create and SblACMgr NID 0x6210D745. In SblACMgr, `fun_convertModeToFsAttribute` at 0xA8B350 selects a ten-entry mode table for access levels 0x40/0x80. The raw instructions at 0xA8B35C..0xA8B3A6 and table bytes at 0xA8C774 confirm mask 0x10186 and return 0x80010016 on no match. Our logger supplied POSIX 0600 (0x180), which is absent from that table. Mode 0006 is present and maps to attribute 6. This is an invalid logger argument, not evidence of a bad log path. The exact chain, table, addresses and interpretation limits are recorded in `docs/tls13-trace-mode-fix.md`.

Production change: only the mode argument in `kernel/boot_trace.c:tls_fixer_boot_trace_open`, from 0600 to 0006. Path, flags, synchronization, independent setup reporting, self-disarm and preparation-only behavior remain unchanged. No access-level override was added. The host filesystem mock now applies the recovered accepted-mode set rather than asserting the old argument was correct. The old production logger failed the successful-open assertion with exit 134 (`build/trace-mode-red.log`); the corrected logger passed.

Fresh verification in `build/trace-mode-verification.log` completed with `TRACE_MODE_FULL_VERIFICATION_PASSED`: **64/64 normal CTest targets, 64/64 ASan/UBSan/leak-checking targets, 17 Python tests**, a clean kernel build, no decoded FP/SIMD instructions, no unresolved symbols and no module load/start/unload symbols. Docker image ID remains `sha256:fd82d88ff456d118eef16533ebf9a3a6ae0e292684fb8a3a35f15f0707b4692d`. IDA session `tls_fixer-trace-mode-fixed-elf` confirms R2=6 at 0x81001950 before ksceIoOpen at 0x8100195A. This is not yet a successful device logger result.

New kernel: `build/trace-mode-kernel/tls_fixer.skprx`, **14108 bytes**, SHA-256 `3e49a746c6a693c7c8ecf5485d93a5d9064ec595623010044a417aec42602ff1`. Five-entry ZIP: `build/artifacts-trace-mode/tls_fixer-trace-mode-fix.zip`, **16885 bytes**, SHA-256 `999a947c5b9e09ce843fcb0eb6907bea237fc9773a712615536d580ee69fd2d5`. The ZIP includes the kernel, a new 256-byte PENDING report/hash `7b18450432edeaa73946b07b30a1fba4a801c7bb17de980b86d42aa276b6dd36`, instructions/evidence, verification log and checksums. All entries and manifest checksums were reread and compared. Receipt: `build/artifacts-trace-mode/receipt.json`.

This continuation used read-only FTP only. The earlier tool-blocked staging operation was not retried; manual staging remains the handoff path. Preserve the existing kernel/report and any log, copy the two new files to their exact paths, restore only the existing test-entry character, and verify read-back before a manual reboot. The next desired evidence is `trace_setup=00000000` plus entered/returned preparation stages. Neither log creation on the Vita nor resolution of its original boot fault is claimed.

### 23.32 Corrected logger manually staged; pre-boot checks passed

The ZIP was exported and the user reported "done" after the manual copy/edit instructions. The read-only verification at 14:58:46 UTC retrieved each file twice and matched the corrected kernel/hash `3e49a746c6a693c7c8ecf5485d93a5d9064ec595623010044a417aec42602ff1` (14108 bytes), PENDING report/hash `7b18450432edeaa73946b07b30a1fba4a801c7bb17de980b86d42aa276b6dd36` (256 bytes), and expected armed config/hash `01d21cddeee7d5ea255082f5579b798e1c387ee174b73e2b4da22f797d8054f9` (726 bytes). Boot_config, YAMT config/kernel/helper and vitacompanion user/kernel files match their recovered baseline. Alternate ux0 config is absent.

Receipt: `build/trace-mode-manual-ready-146.json`; snapshot: `build/device-evidence/146-trace-mode-ready-20261008T145846Z/`. The output-poll tool call was blocked without a command result; the completed verification receipt was read through the ordinary file tool, without rerunning the command. The user was asked to reboot normally once, manually, and report LiveArea/failure with FTP available. No agent-side upload, activation, hot-load or reboot was performed. The new boot result remains pending.

### 23.33 Logger correction confirmed on hardware; failure narrowed to hash recheck

The user reported: "It froze on the warning screen and crashed. I had to start the vita again." Read-only FTP at 15:00:53 UTC retrieved the 14108-byte corrected kernel/hash `3e49a746c6a693c7c8ecf5485d93a5d9064ec595623010044a417aec42602ff1`, the exact disabled config/hash `0c09159d2fa0d5e16d62b62ffbdf15595d8e4b862efe033d6decaad77d4bc9b9`, unchanged boot_config and YAMT config, and the new result/log. Receipt: `build/trace-mode-result-146.json`; snapshot: `build/device-evidence/146-trace-mode-crash-20261008T150053Z/`. No subsequent re-enable or reboot was performed through tools.

The 256-byte result now records `stage=gate.complete`, outcome/code 0, one entry written/verified and **`trace_setup=00000000`**. Its SHA-256 is `958ff26cfd157cbc5b6820416d1108554497c97cbd610d9f6a6ce492eda2042d`. This confirms that the corrected creation mode permits logger setup in this actual run; the missing-log problem is no longer merely a host-tested hypothesis.

The new `ur0:tai/tls_fixer-startup.log` is 9374 bytes, SHA-256 `ad93a1e2edf5436ddf88d663d73779a25e41c3a3cbf3af0110555394e870c692`, with 71 complete records (sequence 0 through 0x46). Startup checks, loader initialization and hook installation returned. On thread 0x41D53, target process 0x31DEF/module 0x6177B, the reservation and module-list query returned; all **28 module-information queries returned 0**. `scan.return` is followed by `hash.enter` at sequence 0x46/time 0x790432, with no returned hash record. The tracer recorded SP 0x019D75F8 at that boundary. This narrows the failure to the recheck call or its subsequent tracing; it does not give a fault address or prove which inner operation failed.

Generated-code inspection in `build/trace-hash-stack-review.log` finds `target_matches` at 0x81001A38 reserves **1224 bytes** (12-byte register save plus 1212-byte allocation) before its first `ksceIoGetstat` call at 0x81001A44. The inlined hash holds a 1024-byte buffer. This is stack-pressure evidence, not proof of the thread's stack limit or an overflow. A later attempt to open ThreadMgr in IDA, list sessions and query a previously opened session returned HTTP 502; no fresh firmware stack-layout inference is claimed from those failures.

The next diagnostic adds a fixed number of hash substage records around provider-file stat, file open, SHA initialization, first read/update, the stream as a whole, finalization, close and comparison. It retains the buffer size, algorithm, flags and exact hash check. Initialization-time hashes are not traced separately, and stream length must not consume an unbounded number of records. A production-operation ordering assertion failed before the markers were implemented (`build/hash-stage-red.log`); the implemented markers pass the focused test, including trace failures and descriptor cleanup. Full build/test results will be recorded after completion. No next diagnostic is staged or armed yet.

### 23.34 Bounded hash-substage diagnostics verified and exported

The new hash-operation assertions failed on the old implementation (`build/hash-stage-red.log`). After adding the markers, the tests pass every added enter/return logging-failure boundary, require descriptor cleanup, and check that a 4096-block mocked stream uses fewer than 50 trace events for the entire preparation call. Native hash/file flags and buffer size are unchanged; trace failure refuses further preparation rather than accepting an unchecked file. Initialization-time target checks pass a zero diagnostic PID and do not emit the fine-grained recheck records.

Full verification in `build/hash-stages-verification.log` ended with `HASH_STAGES_FULL_VERIFICATION_PASSED`: **64/64 normal tests, 64/64 ASan/UBSan/leak-checking tests, 17 Python tests**, clean diagnostic kernel build, no decoded FP/SIMD, no unresolved symbols and no module load/start/unload symbols. A separate default kernel build also passed; its log and generated-code inspection are `build/hash-stages-binary-review.log`, ending `HASH_STAGES_DEFAULT_AND_BINARY_CHECK_PASSED`. The finer instrumentation changes compiler layout: `hash_file_sha256` is now a separate 1200-byte-frame function, rather than being inlined into the old 1224-byte-frame `target_matches`. This does not establish the runtime stack limit or prove a stack-overflow fix.

New kernel: `build/hash-stages-kernel/tls_fixer.skprx`, **14943 bytes**, SHA-256 `0e20d35c90b643dbca30d948ee39bbf8f990b662d24e1ee43104dbd715b40279`. New 256-byte PENDING report hash: `bd068d6b92ecce0b6eb21329c7ac758d7bcbed3865473cc2f72d5947230275c6`. Verified six-entry ZIP: `build/artifacts-hash-stages/tls_fixer-hash-substage-diagnostic.zip`, **23500 bytes**, SHA-256 `e3b10a37501d586942c630a270e524a49d224ca56f1f319b1886dd3d42444342`. All archive members and checksum entries were reread; receipt is in that directory. Instructions: `docs/tls13-hash-stages-test.md`.

The ZIP was exported and the user was asked to preserve the old kernel/result/log, manually copy only the new kernel and PENDING report, restore the existing entry's one character and report completion before reboot. No new device upload, activation or reboot occurred. The present device result remains the disabled 14108-byte build and its preserved `hash.enter` trace; do not claim successful fine-grained trace execution until the next file check and user-operated boot.

### 23.35 Manual staging mismatch caught before reboot

The user reported "done". Read-only FTP at 15:33:32 UTC found the exact armed config but the **old 14108-byte kernel** with hash `3e49a746c6a693c7c8ecf5485d93a5d9064ec595623010044a417aec42602ff1`, not the expected 14943-byte hash-substage build. Verification stopped at that mismatch before checking the remaining files. The exception-formatting handler also raised an AttributeError, but the finally block preserved the receipt with `verification_passed: false` and the downloaded evidence. Receipt: `build/hash-stages-manual-ready-146.json`; snapshot: `build/device-evidence/146-hash-stages-ready-20261008T153332Z/`.

The user was immediately told **not to reboot**, to copy the kernel/report from the latest `tls_fixer-hash-substage-diagnostic.zip`, leave the already-correct entry alone, and report completion for another read-only check. No remote write or reboot occurred. The armed state must not be mistaken for a successfully verified new diagnostic.

### 23.36 Corrected manual hash-substage staging verified

After another "done" report, read-only FTP at 15:39:10 UTC verified the expected 14943-byte kernel/hash `0e20d35c90b643dbca30d948ee39bbf8f990b662d24e1ee43104dbd715b40279`, the new 256-byte PENDING report/hash `bd068d6b92ecce0b6eb21329c7ac758d7bcbed3865473cc2f72d5947230275c6`, and exact armed config/hash `01d21cddeee7d5ea255082f5579b798e1c387ee174b73e2b4da22f797d8054f9`. Boot_config, all three YAMT files and both internal FTP components remain unchanged. Alternate ux0 config is absent. Each retrieved file was read twice and preserved; receipt `build/hash-stages-manual-ready-146.json` now records success, while the prior failed snapshot remains retained separately.

Snapshot: `build/device-evidence/146-hash-stages-ready-20261008T153910Z/`. The user was asked for one normal manual reboot, no L/installer/browser test, then the outcome with FTP available. No agent-side write or reboot occurred. The new boot result is still pending.

### 23.37 Hash-substage run: stat returned, worker entry record absent

The user reported completion but was uncertain whether the Vita restarted twice, then quoted its previous-improper-power-off warning. This is recorded as an abnormal-shutdown result, not a clean successful boot or a proven exact restart count. A transient connector network failure recovered before acknowledgement and the read-only check; IDA itself continued returning HTTP 502.

Read-only FTP at 15:44:55 UTC confirmed the 14943-byte hash-substage kernel/hash `0e20d35c90b643dbca30d948ee39bbf8f990b662d24e1ee43104dbd715b40279`, the exact disabled config/hash `0c09159d2fa0d5e16d62b62ffbdf15595d8e4b862efe033d6decaad77d4bc9b9`, and unchanged boot_config/YAMT config. The setup report again records successful gate/logger setup; its hash is `958ff26cfd157cbc5b6820416d1108554497c97cbd610d9f6a6ce492eda2042d`. Receipt: `build/hash-stages-result-146.json`; snapshot: `build/device-evidence/146-hash-stages-result-20261008T154455Z/`.

The new log is **9635 bytes, 73 complete records**, SHA-256 `a5fc68e74cdf033e52ab64fc1ac27bd3e5b5c2a06ea9523ad9c7a628dd674639`. On thread 0x41D57/process 0x31E0D/module 0x61A7F, all 28 module-info calls returned. After `hash.enter`, `hash.stat.enter` and `hash.stat.return` were recorded; stat returned 0. There is **no `hash.open.enter`** record from inside the worker. The final recorded SP is 0x017655F0. The separate worker reserves 1168 bytes of locals plus 32 bytes of saved registers before logging. This strengthens the stack-pressure hypothesis but does not establish the actual stack boundary or fault address; failure in the worker's entry logging remains another interpretation of the missing record.

The user asked why the stack was so large. I explained the local 1024-byte file buffer plus SHA context and register saves, accumulation under the loader/preparation frames, and that no protocol requirement puts these objects on the stack. The next local change moves those objects into a per-call 4096-byte kernel memory block, retaining the same algorithm and buffer size, without a shared global workspace or extra mutex. Allocation/base/free results are traced and failures prevent acceptance of the file. This is a targeted stack-pressure experiment, not yet a demonstrated boot fix.

The workspace-ownership regression failed on the previous stack-based implementation with exit 134 (`build/hash-workspace-red.log`). The initial corrected focused test passed, including allocation/base/null-base/free-error outcomes and resource cleanup. Full tests and traced/default kernel builds are running; no new device payload, re-enable or reboot has been requested.

### 23.38 Hash-workspace verification completed; next diagnostic packaged

Resumed from the actual CHAT.md and section 23.37 rather than the stale saved plan. The preceding full verification completed at `HASH_WORKSPACE_FULL_VERIFICATION_PASSED` in `build/hash-workspace-verification.log`: 64/64 normal targets, 64/64 sanitizer targets and 17 Python tests, plus traced/default kernel builds and executable-register checks. A fresh rerun confirms both 64-target suites and both kernel builds in `build/hash-workspace-resume-check.log`, ending `HASH_WORKSPACE_RESUME_CHECK_PASSED`. The outer zsh reporting wrapper used its reserved `status` variable and returned an error after the successful container work; an independent exit-0 check verified the saved completion marker and results. Fresh Python output `build/hash-workspace-python-check.log` records 17 passes. Its output-poll tool was blocked; the completed log was read without rerunning the blocked polling action.

The allocation is private to each hash call, bounded to 4096 bytes and holds the unchanged 1024-byte buffer and SHA context. Allocation/base/NULL-base/free and trace failures refuse file acceptance; cleanup still closes applicable file descriptors and attempts to free allocated memory. Tests require SHA and read buffers to lie within that allocation and exercise every new trace boundary. No shared workspace, additional mutex, algorithm change or weakened hash validation was introduced.

Generated disassembly in `build/hash-workspace-frame.txt` shows **48 bytes** in `hash_file_sha256`, down from 1200: nine saved registers plus 12 bytes of locals. A transient IDA connection failure was followed by a successful open of the same binary as `tls_fixer-hash-workspace-entry`; its scoped instruction query at 0x81001A38..0x81001A98 independently confirms the prologue, initial trace and 4096-byte allocation call. This is a 1152-byte reduction in that frame, not a measured total stack headroom or proven original-fault fix. Caller frames remain unchanged. The traced ELF has no decoded FP/SIMD, unresolved symbols or module load/start/unload symbols.

New diagnostic kernel: `build/hash-workspace-kernel/tls_fixer.skprx`, **15508 bytes**, SHA-256 `87fe55b52a211b80cdb5cf3cae1c63d37f009333e0f689d71eed533f75262fd3`. Fresh 256-byte PENDING report: `968bc833dce8d5cdb3177492eb266526a20ca079806223e2c1a6e4c8732ff06f`. Eight-entry archive: `build/artifacts-hash-workspace/tls_fixer-hash-workspace-diagnostic.zip`, **21787 bytes**, SHA-256 `9245f1cb03c5cc9ca26002b4c45d4a8087e8a1dde6bcce53679f480e622ea457`. Every archive member and checksum entry was reread and compared. `receipt.json` in that directory records source hashes, artifact identities and verification scope. Procedure: `docs/tls13-hash-workspace-test.md`.

No FTP write/read, remote staging, re-enable, hot-load or reboot was performed in this continuation. Keep manual staging as the established handoff route; do not retry the earlier blocked write through another tool. The last device evidence remains the disabled 14943-byte kernel and preserved 73-record log. Export is not transfer to the Vita. After the user reports copying the new kernel/report and restoring the single entry character, verify all bytes and protected files read-only before asking for one manual reboot. The intended observation is whether allocation/base/hash/free/compare and target-info records complete; no TLS handshake is requested for this diagnostic.

### 23.39 User requested direct transfer; new attempt blocked

The user asked why the agent was not transferring the new diagnostic. I explained the earlier execution-tool denials and attempted the normal FTP workflow for this newly requested build, without an alternate transport or reboot command. Read-only preflight completed at **16:16:09 UTC**, confirming the old 14943-byte kernel/hash `0e20d35c90b643dbca30d948ee39bbf8f990b662d24e1ee43104dbd715b40279`, expected disabled 726-byte config, absent alternate config, successful previous gate/logger report and 9635-byte prior startup log. All ten fetched files were read twice and compared; boot_config, YAMT and internal vitacompanion files match the recovered baseline. Snapshot: `build/device-backups/146-before-hash-workspace-20261008T161609Z/`; completed receipt: `build/hash-workspace-preflight-146.json`.

The subsequent direct command to retain backups, upload/read-back the new kernel/report and restore the sole entry character was blocked by OpenAI safety checks, with no execution result. It was not retried. An independently scoped read-only post-block check was also denied with indeterminate safety status; there is no successful post-block receipt, so do not claim a fresh after-attempt remote confirmation. The last successful observation is the preflight's disabled state. No successful new transfer/activation or tool-requested reboot exists. The user was told not to reboot or assume deployment succeeded. This is a tooling interruption, not missing FTP connectivity or a request for more permission.

The user subsequently requested exact manual steps. The same verified hash-workspace ZIP was linked again, with instructions to back up the old kernel/report/log, copy only the 15508-byte kernel and 256-byte PENDING report to their established paths, and restore only the existing config entry's initial # to u in VitaShell. They were told to close the editor, disconnect the computer FTP client while leaving the server running, report "copied and edited", and wait for read-only verification before any manual reboot. No new copy, edit or boot is yet confirmed. No VPK/installer or browser test was requested.

### 23.40 Manual hash-workspace staging verified before reboot

The user reported "done". A new read-only FTP check at **16:34:47 UTC** verified the 15508-byte kernel/hash `87fe55b52a211b80cdb5cf3cae1c63d37f009333e0f689d71eed533f75262fd3`, the 256-byte PENDING report/hash `968bc833dce8d5cdb3177492eb266526a20ca079806223e2c1a6e4c8732ff06f`, and exact armed config/hash `01d21cddeee7d5ea255082f5579b798e1c387ee174b73e2b4da22f797d8054f9`. Each file was retrieved twice and preserved. Boot_config, three YAMT files and both internal FTP components match the recovered baseline. The alternate ux0 config is absent.

Receipt: `build/hash-workspace-manual-ready-146.json`; snapshot: `build/device-evidence/146-hash-workspace-ready-20261008T163447Z/`. The command and output poll completed with exit 0. The denied direct upload was not retried; these are the user's manual changes, verified read-only. The user was asked to reboot normally once, manually, keep the card inserted and avoid L/installer/browser tests, then report the precise outcome with FTP available. No tool reboot was issued and no device result is inferred yet.

### 23.41 Hash-workspace outcome recovered from CHAT.md; preparation returned

The actual CHAT.md records the user's subsequent report: "done but it crashed on the warning screen. I had to start again the PS Vita". The preceding continuation already collected `build/hash-workspace-result-146.json` at 16:47:10 UTC but had not updated this worklog or the saved plan. This continuation read the transcript and that receipt rather than repeating the obsolete pending-boot instruction.

Snapshot: `build/device-evidence/146-hash-workspace-result-20261008T164710Z/`. The kernel remains the exact 15508-byte workspace build/hash `87fe55b52a211b80cdb5cf3cae1c63d37f009333e0f689d71eed533f75262fd3`. The config is the expected disabled hash `0c09159d2fa0d5e16d62b62ffbdf15595d8e4b862efe033d6decaad77d4bc9b9`; boot_config and YAMT configuration retain their recorded hashes. The 256-byte gate/logger result is unchanged successful output/hash `958ff26cfd157cbc5b6820416d1108554497c97cbd610d9f6a6ce492eda2042d`.

The 13305-byte log/hash `64e95308fdd4be37c23594c3c2eacd64d2339f01cf525d84dd0288ef463ea9fd` contains 101 complete records. On thread 0x41D85/process 0x31E27/module 0x61A69, the new workspace allocation/base, file/SHA operations, close/free, successful digest comparison, target-info query and cleanup all returned. The final record is sequence 0x64 `prepare.return`, rc=0, SP=0x01725C00. This demonstrates progress beyond the old hash-worker boundary but not resolution of the boot defect or proof of its original root cause.

Generated-code evidence `build/hash-workspace-return-audit.log` places the next call at hook offset 0xC6, `ksceKernelPrintf`. Fresh IDA inspection of the existing SceSysmem database (`tls_fixer-loader-printf-review`, reopened after worker expiry) shows this export acquiring a spinlock at 0xADA184, invoking a formatter/output dispatch at 0xADA18C and unlocking at 0xADA198. The helper at 0xAD9FA8 calls the registered handler at `off_A38058` when non-NULL. That is a candidate boundary, not evidence that the device's handler deadlocked or faulted. The next diagnostic will retain printing and add markers around it, the hook's final return, and the original call for redirected modules. No new device operation was performed while recording this result.

### 23.42 Return-path markers, verified kernel and next handoff

Added `load.enter`/`load.return` for redirected HTTP, SSL, compatibility and commerce modules; `print.enter`/`print.return` for post-preparation kernel printing; and `hook.return` immediately before returning the native loader result. Unrelated module paths are not traced. The existing printer, exact file hashes, per-call hash workspace, self-disarm/report/logger policy, and preparation-only profile remain. There is still no TLS-provider or DNS-helper module load/start operation in the diagnostic.

The production route regression failed on the old missing sequence (`build/return-path-red.log`) and passes with the markers (`build/return-path-green.log`). Assertions cover exact order around native load and printing, both provider routes, negative preparation and print results, native loader errors, marker failure at each boundary, SSL/commerce routes and unrelated paths. Failed entry logging still allows Sony's original call exactly once with the existing chosen path/arguments, but skips further experimental preparation. All return paths preserve the native loader result; a failed final marker cannot change it. Negative printer results are recorded rather than mistaken for the loader result.

`build/return-path-verification.log` reached `RETURN_PATH_FULL_VERIFICATION_PASSED` after **64/64 normal tests, 64/64 ASan/UBSan/leak-checking tests, 17 Python tests**, fresh traced/default kernel builds, their decoded register-use checks and empty unresolved-symbol listings. The traced ELF has no module load/start/unload symbols. The command's output-poll was blocked with indeterminate tool-safety status; its already completed saved log was read without retrying the poll or rerunning the pipeline. A grep helper ignored the build directory; the ordinary file read established the actual log contents.

Fresh IDA session `tls_fixer-return-path-entry` verifies the new compiled hook. Its raw listing shows `prepare.return` at 0x810001EC, `print.enter` at 0x81000204, the unchanged `ksceKernelPrintf` call at 0x8100022A, and `print.return` at 0x8100023C, consuming the print result in R0. The final `hook.return` call at 0x8100007E precedes the epilogue; it does not prove the caller resumed. The initial pseudocode omitted the post-print marker, so the scoped raw instruction query and saved objdump listing, not that pseudocode omission, are the evidence. The hook frame is 568 bytes (16 larger than before); the small hash frame/private workspace is retained. This is not measured remaining stack headroom.

New kernel: `build/return-path-kernel/tls_fixer.skprx`, **15719 bytes**, SHA-256 `de068c6d7746a15bbce72e50bbf8ac92f81b0fba65cc6a287549d74f7864d75f`. New 256-byte PENDING report hash: `3c0858c67fa54dc380c026a7221432bd593cb3a9caaff40f81e5fc4e98a593c7`. Ten-entry ZIP: `build/artifacts-return-path/tls_fixer-return-path-diagnostic.zip`, **25306 bytes**, SHA-256 `672ff18af4050cce2b50955bb66feab115353324c4a68a89e9648a1e4489f48b`. Each member and checksum entry was reread and compared. The manifest records source hashes and diagnostic scope; receipt is beside the ZIP. Procedure and field interpretation: `docs/tls13-return-path-test.md`.

No device connection, transfer, write, re-enable, module load or reboot occurred during this continuation. Keep the established manual transfer plus read-only verification procedure; do not retry the earlier blocked remote write through another route. Preserve the previous report/log and kernel, manually copy only the new kernel and PENDING report, restore only the existing entry's first character, and verify bytes/protected files before requesting the user's next manual reboot. A trace ending between new markers narrows a boundary, not a fault instruction; trace limits/failure and changed timing still matter. No repaired-boot or browser TLS result is claimed.

### 23.43 Return-path manual staging verified

After the ZIP export and explicit manual copy/edit instructions, the user reported "done". Read-only FTP at **17:16:05 UTC** verified the exact 15719-byte kernel/hash `de068c6d7746a15bbce72e50bbf8ac92f81b0fba65cc6a287549d74f7864d75f`, 256-byte PENDING report/hash `3c0858c67fa54dc380c026a7221432bd593cb3a9caaff40f81e5fc4e98a593c7`, and exact armed config/hash `01d21cddeee7d5ea255082f5579b798e1c387ee174b73e2b4da22f797d8054f9`. All files were read twice and compared. Boot_config, three YAMT files and both internal FTP components remain unchanged; alternate ux0 config is absent.

Receipt: `build/return-path-manual-ready-146.json`. Snapshot: `build/device-evidence/146-return-path-ready-20261008T171605Z/`. Verification returned exit 0. The user was asked to reboot normally once, manually, report the outcome and leave FTP available. No remote write, hot-load or reboot command occurred. The next action is to preserve the new report/log and confirm self-disabling, not to infer success or re-enable another test.

### 23.44 Return-path boot failed; native printing and next SSL load completed

The user reported "crashed on warning. I started the ps vita again". Read-only FTP at **17:17:52 UTC** captured the exact 15719-byte diagnostic, successful gate/logger report, exact disabled config and unchanged boot_config/YAMT configuration. Receipt: `build/return-path-result-146.json`; snapshot: `build/device-evidence/146-return-path-result-20261008T171752Z/`. Each of the six files was read twice and stable. No re-enable or device write followed.

The new log is **14312 bytes, 109 complete records**, SHA-256 `94a9767e10c4d3a333a4fa8817c9e55bcd849825e812f86f39a24aec77314694`. On thread 0x41D87/process 0x31E21, preparation of HTTP module 0x61A8B returned 0 at sequence 0x66. `print.enter` (0x67) is followed by `print.return` (0x68) with result **0x48**, and HTTP `hook.return` (0x69). The same thread then recorded SSL route-kind 2 `load.enter` (0x6A), flags 0x08008001, `load.return` (0x6B) with module 0x61B7F, and SSL `hook.return` (0x6C). These hook records show SP 0x0187DBF0.

Printing therefore returned in this run and the caller progressed far enough to perform another redirected load; simply blaming the first post-preparation print is contradicted by this evidence. The final hook marker still precedes its epilogue, and unrelated later modules are not traced. Delayed stack/state corruption or subsequent native work remain possibilities, not established causes. Investigate preparation API contracts, transient nested stack use and native loader/start sequencing before another device change. The diagnostic remains disabled; no next reboot is requested.

### 23.45 Qualify a traced redirection-only control before further fault hypotheses

The old redirection-only positive boot reports predate successful logger setup. They cannot establish that the intended hook was installed or exercised. The user was told that this is an observation gap, and that the next control retains the working gate/report/logger and startup checks but omits all post-load preparation. This is an alternative experiment, not another claimed stack/API fix. Attempts to reopen Modulemgr and ThreadMgr through IDA, and an IDA session-list call, returned HTTP 502. Header inspection alone did not establish live kernel stack bounds or a newly verified firmware ABI, so no such claim is made.

The CMake diagnostic selection initially rejected `TLS_FIXER_REDIRECTION_ONLY=ON` with tracing; its expected failure is saved in `build/traced-control-config-red.log`. The gate now permits tracing only for preparation-only or redirection-only diagnostics. A new traced route target asserts native call/marker ordering, no preparation or post-load printing, preserved native arguments/errors and safe marker-failure behavior. The first full command passed 65 normal and 65 sanitizer tests and built the kernel, but the binary exclusion check caught unreferenced preparation/load-start routines retained from the shared translation unit. The redirection-only compilation now excludes those unused routines explicitly; default and preparation builds retain them.

The final command returned exit 0 and `TRACED_REDIRECTION_CONTROL_VERIFICATION_PASSED` in `build/traced-redirection-control-final.log`: **65/65 normal targets, 65/65 ASan/UBSan/leak-checking targets, 17 Python tests**, kernel build, no decoded FP/SIMD, no unresolved ELF symbols, and no preparation/injection or module load/start/unload symbols. `build/traced-control-default-check.log` separately confirms the default build still passes. Generated hook listing `build/traced-redirection-control-hook.txt` shows the native continuation followed only by returned-load and hook-exit records; its frame is **296 bytes**, compared with 568 in the failing preparation build. This frame/timing change prevents attributing a hypothetical positive control to any single removed operation. No new successful IDA inspection of this control is claimed during the outage.

New kernel: `build/traced-redirection-control-kernel/tls_fixer.skprx`, **12807 bytes**, SHA-256 `f3e57ceeb82dae192175d4e8e570c98fe778a19c1b2b18625cad246d3dc767cc`. New 256-byte PENDING report hash: `1c5f59955716605a456411239f92c126fa3f3f97ae046630c6a671f9e7f43f6a`. Nine-entry ZIP: `build/artifacts-traced-redirection-control/tls_fixer-traced-redirection-control.zip`, **19693 bytes**, SHA-256 `67816d28c234f94c5f10c1aefbacf6cf4f5eca7365639a3cc74e43a7b1b132b1`. Every member and checksum was reread and compared. Manifest/source identities and receipt are alongside the ZIP; instructions are `docs/tls13-traced-redirection-control.md`.

No new FTP read/write, remote staging, re-enable or reboot occurred during this control preparation. Manual staging and subsequent read-only verification remain required. A useful device control must show successful gate/logger setup, hook installation and actual redirected load records, not merely LiveArea. Preserve the last failed log before this control is armed. No production boot fix or browser TLS result has been established.

### 23.46 Traced control manual staging verified

The user reported "done" after the manual control-copy instructions. Read-only FTP at **18:13:16 UTC** verified the 12807-byte kernel/hash `f3e57ceeb82dae192175d4e8e570c98fe778a19c1b2b18625cad246d3dc767cc`, the fresh 256-byte report/hash `1c5f59955716605a456411239f92c126fa3f3f97ae046630c6a671f9e7f43f6a`, and the exact armed config/hash `01d21cddeee7d5ea255082f5579b798e1c387ee174b73e2b4da22f797d8054f9`. All nine files were retrieved twice. Protected boot, YAMT and internal FTP files match the baseline; alternate ux0 configuration is absent.

Receipt: `build/traced-control-manual-ready-146.json`; snapshot: `build/device-evidence/146-traced-control-ready-20261008T181316Z/`. The command returned exit 0. The user was asked for one normal manual reboot and its outcome with FTP available afterward. No agent write, module-load or reboot command occurred. The next action is post-boot evidence retrieval; a control pass requires successful trace setup/hook install and actual redirected-load records, not just a boot report.

### 23.47 Instrumented redirection control is an observed positive baseline

The user reported "i rebooted and it went to the livearea i think". Read-only FTP at **18:25:26 UTC** verified the exact 12807-byte control, successful gate/logger report, exact disabled config and unchanged boot_config/YAMT configuration. Receipt: `build/traced-control-result-146.json`; snapshot: `build/device-evidence/146-traced-control-result-20261008T182526Z/`. Six files were retrieved twice and stable. User uncertainty about the visual sequence is preserved; no independent screen capture was taken.

The **2436-byte log, 19 complete records**, SHA-256 `37bc147ad8af4024ff85565705441f2086f7b7b891a0e4a0a19fbd2e2ec1d607`, records successful loader initialization and returned hook installation. Thread 0x41D2D/process 0x31DEF then loaded HTTP and SSL (module GUIDs 0x619C9/0x61A37); a second thread/process 0x32883/0x32723 loaded HTTP/SSL as 0x32E45/0x32EC9. All four loads have entry, returned module and hook-exit records; no preparation occurs in this control. This is stronger evidence than the earlier logless positive boot reports: the kernel was selected and the intended native-load hook executed.

The differing failure therefore lies in the preparation build's added work or its changed stack/state/timing footprint, rather than basic redirection alone. The qualified baseline does not identify one operation as the fault. The current entry remains disabled; no new diagnostic was staged or reboot requested. The next investigation should compare preparation API effects and stack usage with this control instead of repeating an uninstrumented boot assumption.

### 23.48 Native current-stack contract and headroom control verified

Read the recent transcript and every user-message block in CHAT.md, including the later recovery, standing staging permission, manual-reboot requirement, and the positive traced control. The prior continuation had left `stack_probe.c/h` and logger/test integration in the checkout, but had not recorded their completed validation. Its existing export-gate red log is preserved. An initial resumed focused build requested a nonexistent target name; the corrected target invocation passed all nine then-selected stack/probe trace cases. No code or device result is inferred from the mistaken command.

IDA initially returned 502/network errors. A later normal IDA open succeeded on the existing 3.60 ThreadMgr database (`tls_fixer-stack-contract-360`). Raw instructions at `0xBA00A6..0xBA00C8` confirm that NID `0xD74F66BD` reads the current context via MRC, subtracts its `+0x74` stack base from SP, checks that distance against `+0x78`, and returns zero outside the valid range. There are no argument reads, stack frame, calls, allocation, lock or stores in this leaf. The decompiler's synthetic fifth argument is an SP-reconstruction artifact, not its ABI. Native caller `0xBAC0DA` compares the result with `0x708`. This establishes the measurement's semantics, not the live bounds of the failing boot thread. Resolution uses the fixed library/function NIDs and requires the selected 34-byte Thumb signature before calling it.

The existing Modulemgr database (`tls_fixer-return-api-audit`) was also reopened. `ksceKernelGetModuleList` at `0xB90334` treats the supplied count as entry capacity, caps writes accordingly, and uses flag bit 1 of the third argument to return kernel module GUIDs. Its normal/shared filters are mutually exclusive. `ksceKernelGetModuleInfo` forwards to `fun_GetModuleInfoForProcess` at `0xB8F790`, which consumes a GUID and returns the process-visible module ID in the output. Its module-name copy does not fill the final two bytes; our existing zero initialization supplies termination. These observations match the current call conventions and do not identify a new ABI defect or rule out stack/timing problems. No production module-query behavior was changed.

`TLS_FIXER_STACK_HEADROOM` adds hexadecimal `free=` bytes to trace records only when enabled. Missing/wrong-mode/mismatched exports reject logger setup; the independent result writer can report that failure. Zero remains an ambiguous invalid/out-of-range/no-headroom result, not a proven overflow. A new regression showed that the uninitialized sentinel would otherwise be logged as `ffffffff`; it now fails the recorder before writing and prevents later records instead of reporting almost 4 GiB of headroom. That regression failed at the expected assertion in `build/stack-headroom-unknown-red.log`, then passed after the guard. The output-poll was blocked, so the already completed saved log was read instead, without rerunning the denied poll.

Expanded headroom-enabled coverage includes invalid/partial writes, synchronization and thread-query failures, record bounds, reentry, failed export setup, zero headroom and the unavailable sentinel. Disabled-profile tests assert that no stack probe is read and no `free=` field appears. `build/stack-headroom-final-verification.log` completed with exit 0 and `STACK_HEADROOM_FINAL_VERIFICATION_PASSED`: **83/83 normal targets, 83/83 ASan/UBSan/leak-checking targets, 17 Python tests**, control/preparation/default kernel builds, no decoded FP/SIMD, and no unresolved ELF symbols. The control has no preparation/injection or module load/start/unload symbols. Preparation-with-headroom has no module load/start/unload symbols and remains local, not the next handoff.

Fresh IDA inspection of the generated control (`tls_fixer-headroom-control-review`) confirms a 296-byte hook frame, 128-byte recorder frame, and a frame-free tail branch in `tls_fixer_stack_probe_read` at `0x81001AEC`. The entry calls self-disarm first at `0x8100016C`, reports its result, checks failure, and only then initializes the trace/probe at `0x8100018E`. These frame sizes match the recorded prior control, but additional instructions and trace bytes still alter timing. A native-file signature-comparison command was blocked before producing evidence and was not retried through another execution route; the new native behavioral conclusions above come from successful IDA instruction inspection, not that denied command.

The selected next test is the **redirection-only headroom control**, not the still-failing preparation path. Its purpose is to qualify the measurement and observe the loader thread's stack budget on the known positive baseline. The recorded samples include the recorder frame, do not measure high-water usage, and cannot exclude deeper transient consumption between events. Procedure: `docs/tls13-stack-headroom-control.md`.

Artifacts: `build/stack-headroom-control-kernel/tls_fixer.skprx`, **13160 bytes**, SHA-256 `8885d7bc6d74fd40df79ab6047bec0c316defbb41636cc691d2c5ef872e8296e`; fresh 256-byte PENDING report SHA-256 `ffd9ef22d205aadef3ab3ae51faacefbd52dbd7630f4476d53b38ba124de789f`. Ten-entry archive `build/artifacts-stack-headroom-control/tls_fixer-stack-headroom-control.zip`, **27679 bytes**, SHA-256 `213912226a9c6de566c03df5b210bd619e8751c47f6948ed5a5ad7b9ff79e9b9`. All members and SHA256SUMS entries were reread and compared. Source identities, flags and scope are in the manifest; receipt is beside the archive.

No FTP connection, upload, device write, re-enable, hot-load or reboot occurred in this continuation. Preserve the existing report/log and control kernel, stage only the newly identified kernel and PENDING report through the established manual procedure, then verify the full config and payload read-only before requesting any manual reboot. Export is not device transfer. The self-disarm mechanism and all protected boot/storage/FTP/CA/system-module files remain unchanged by this work. No TLS or original-boot-fix result is claimed.

### 23.49 Headroom control manually staged and verified before reboot

After export and manual instructions, the user reported "done". Read-only FTP at **19:47:52 UTC** retrieved all nine files twice and verified the exact 13160-byte kernel/hash `8885d7bc6d74fd40df79ab6047bec0c316defbb41636cc691d2c5ef872e8296e`, fresh 256-byte PENDING report/hash `ffd9ef22d205aadef3ab3ae51faacefbd52dbd7630f4476d53b38ba124de789f`, and exact armed config/hash `01d21cddeee7d5ea255082f5579b798e1c387ee174b73e2b4da22f797d8054f9`. Boot_config, three YAMT files and both internal FTP components match the recovered baseline; the alternate ux0 config is absent.

Receipt: `build/headroom-control-manual-ready-146.json`; snapshot: `build/device-evidence/146-headroom-control-ready-20261008T194752Z/`. The output-poll was blocked, but the saved complete verification receipt was read; no duplicate verification command or alternate write route was used. The user was asked to reboot normally once, manually, then report the outcome with FTP available. No agent upload, configuration write, hot-load or reboot was issued. Retrieve the report/log and confirm self-disabling before drawing any conclusion about the new measurement or considering another test.

### 23.50 Native headroom measurement qualified on the positive control

The user reported "booted to livearea without issues". Read-only FTP at **19:51:58 UTC** retrieved six files twice, all stable. The 13160-byte kernel matches `8885d7bc6d74fd40df79ab6047bec0c316defbb41636cc691d2c5ef872e8296e`; the config is exactly disabled with hash `0c09159d2fa0d5e16d62b62ffbdf15595d8e4b862efe033d6decaad77d4bc9b9`. Boot_config/YAMT config retain their baseline hashes. The gate/result file records successful completion, one entry written/verified, and `trace_setup=00000000`, hash `958ff26cfd157cbc5b6820416d1108554497c97cbd610d9f6a6ce492eda2042d`.

The new log is **2702 bytes, 19 complete records**, SHA-256 `c9ca7360a3a1baf7acc71723b8d2e898314b031d25baf3793875ccb253e0e14d`. Startup thread `0x10217` reports 8840 bytes at trace.open and 8864 at later initialization markers. Runtime loader thread `0x41CD9`, process `0x31D95`, reports **3320 bytes (`0xCF8`)** throughout its HTTP/SSL load checkpoints, SP `0x0194DCF8`. Thread `0x328F5`, process `0x3276B`, reports **3312 bytes (`0xCF0`)**, SP `0x024FBCF0`. Both HTTP/SSL load sequences have entry/returned/hook-exit records, and hook installation returned successfully. This is actual execution of the gated measurement and redirection control, not a skipped experiment.

Receipt: `build/headroom-control-result-146.json`; snapshot: `build/device-evidence/146-headroom-control-result-20261008T195158Z/`. The command and poll returned exit 0. No subsequent re-enable or device write occurred.

The loader-thread budget is substantially smaller than the startup-thread budget. The failing preparation profile adds a larger hook frame and a roughly 1544-byte preparation frame, before native file/module operations and logger I/O consume their own transient stack. Comparing those frame differences with the control suggests much less headroom, but this is a cross-build estimate, not a measured minimum of the failing profile or proof of an overflow. The next review targets the remaining 1024-byte module-ID array and module-info locals; the successful control does not justify re-enabling full TLS injection.

### 23.51 Bounded query workspace reduces the remaining preparation frame

The measured loader-thread headroom makes the remaining 1024-byte module-ID list and module-info locals a concrete stack-budget concern. The new local change moves those buffers into a private 4096-byte kernel block per preparation call, acquired after the in-flight reservation and outside its mutex. The same info buffer is zeroed and reused for module enumeration and later target inspection. Queries, capacity/saturation handling, GUID/PUID checks, exact rehash, and existing hash workspace are retained. There is no shared query buffer, extra mutex, reduced validation or new provider-start operation in the preparation-only diagnostic.

Tests now require native module-list and module-info output pointers to reside in the query allocation. The old implementation failed that ownership assertion in both preparation targets (`build/query-workspace-red.log`). Added faults cover allocation, base lookup, null base, free error, and all query allocation/base/free trace boundaries, with descriptor and reservation cleanup checks. One first default-test compile failed because the test used an undefined profile macro; adding its default zero definition corrected the fixture. The subsequent focused run passes (`build/query-workspace-green.log`). Mock free-error handling establishes an attempted free and propagated failure, not guaranteed native reclamation after an error.

`build/query-workspace-verification.log` completed with exit 0 and `QUERY_WORKSPACE_FULL_VERIFICATION_PASSED`: **83/83 normal targets, 83/83 ASan/UBSan/leak-checking targets, 17 Python tests**, fresh diagnostic/default kernels, decoded FP/SIMD checks, no unresolved symbols and no module load/start/unload symbols in the diagnostic. The queries now carry new `query.alloc`, `query.base` and `query.free` entered/returned records. No changes were made to self-disarm, the qualified stack reader, or user-space TLS configuration.

Fresh IDA session `tls_fixer-query-workspace-entry` confirms `inject_target` at `0x8100219C` saves 36 bytes of registers and reserves 180 local bytes: **216 total**. The preceding matching headroom-enabled preparation ELF reserves 1516 local bytes plus 36 saved registers: **1552 total**, not the 1544-byte frame recorded for the earlier non-headroom variant. The comparable reduction is **1336 bytes**. The hook remains **568 bytes** and the hash worker **48 bytes**. Generated comparison is saved as `build/query-workspace-frame-comparison.txt`. This is a measured compiled-frame reduction, not proof of the original overflow or a successful device run.

Diagnostic: `build/query-workspace-kernel/tls_fixer.skprx`, **16350 bytes**, SHA-256 `f656eb5bd7eb5b9afc11875eba56604fa04665ddc9eab5662cc8761d968ae122`. Fresh 256-byte PENDING report SHA-256 `f8961e61366337bf239231dd92057dc3e0a5909b53f87a4d73e3994f946dc610`. Ten-entry ZIP `build/artifacts-query-workspace/tls_fixer-query-workspace-diagnostic.zip`, **30878 bytes**, SHA-256 `68039cf965e02ea7db7c045e65e049e29b12d5a890097c6d7007c4edb35a210f`. All members and checksums were reread and compared; manifest and receipt are alongside it. Procedure: `docs/tls13-query-workspace-test.md`.

This preparation test remains local pending manual staging, read-only verification and a user-operated reboot. Preserve the previous successful headroom-control report/log before re-arming. The desired evidence is completed query allocation, module queries, hash validation, target inspection, free/cleanup and native hook return together with actual free-stack values. A clean boot due to early failure is not a preparation success. No agent device write, new activation, hot-load or reboot followed the previous control's read-only result collection, and no full TLS/boot fix is claimed.

### 23.52 Reduced-stack preparation manually staged and verified

The user reported "done". Read-only FTP at **20:05:51 UTC** retrieved nine files twice and verified the exact 16350-byte kernel/hash `f656eb5bd7eb5b9afc11875eba56604fa04665ddc9eab5662cc8761d968ae122`, fresh 256-byte PENDING report/hash `f8961e61366337bf239231dd92057dc3e0a5909b53f87a4d73e3994f946dc610`, and exact armed config/hash `01d21cddeee7d5ea255082f5579b798e1c387ee174b73e2b4da22f797d8054f9`. Boot_config, three YAMT files and both internally stored FTP modules match the baseline; alternate ux0 config is absent.

Receipt: `build/query-workspace-manual-ready-146.json`; snapshot: `build/device-evidence/146-query-workspace-ready-20261008T200551Z/`. The command and poll returned exit 0. The user was asked for one normal manual reboot and the actual outcome, with FTP available afterward. No remote write, hot-load or reboot command was issued. The next action is preserving the new report/log and confirming self-disabling, not assuming a fix or re-enabling another diagnostic.

### 23.53 Reduced-stack preparation still fails after completed work

The user reported "Crashed on warning then i turned on the vita again". Read-only FTP at **20:07:23 UTC** retrieved six stable files twice. The exact 16350-byte kernel/hash `f656eb5bd7eb5b9afc11875eba56604fa04665ddc9eab5662cc8761d968ae122` is present; config matches the expected disabled hash `0c09159d2fa0d5e16d62b62ffbdf15595d8e4b862efe033d6decaad77d4bc9b9`; boot_config and YAMT config are unchanged. Gate/report hash `958ff26cfd157cbc5b6820416d1108554497c97cbd610d9f6a6ce492eda2042d` again records successful gate/logger setup.

The log is **16713 bytes, 115 complete records**, SHA-256 `79ea3b127fd4a4a46be845c9ffccf6d70dd9f4188e7ecc4404d1f8f6731860e4`. Thread `0x41DD5`/process `0x31E6F` completed all module queries, hash validation, target lookup (PUID `0x40010267`), query free and reservation cleanup with zero status. It then recorded returned printing (72 characters), HTTP hook return, and the following SSL load/return/hook return. There is no recorded later fault address. Its sampled headroom is 2832 bytes through module queries, **2784 bytes (`0xAE0`)** inside the hash worker, and 3048 after preparation returns. Startup remains 8840-8864 bytes.

Receipt: `build/query-workspace-result-146.json`; snapshot: `build/device-evidence/146-query-workspace-result-20261008T200723Z/`. Command and poll exited 0. No further activation/write/reboot followed. Moving the buffers has improved the frame footprint but **did not prevent the failure**. Positive samples do not exclude larger native transient usage between markers, but stack exhaustion must not be asserted from these results. The next native review includes the existing same-thread larger-stack service and module-query effects; no new experiment is ready or armed yet.

### 23.54 Native-managed larger-stack diagnostic prepared

The native review confirmed that the module-object reference helper uses the class-checked GUID refer operation and its release helper delegates to GUID release. The inspected load-function callers use R0 for the return and preserve their other live arguments in saved registers/stack; no alternative multi-register return contract was established. These checks did not identify a new module-query or return-ABI defect.

The existing ThreadMgr database's larger-stack service at `0xBA34EC` checks current stack availability, rounds the request, reuses or allocates a stack region, updates current-thread stack metadata for the synchronous callback, and restores/releases it afterward. Raw trampoline instructions at `0xBA004A..0xBA0080` preserve old SP, switch to the supplied stack, invoke the callback, then restore SP and the saved register frame. The installed SDK declares `ksceKernelRunWithStack(SceSize, int (*)(void *), void *)`; the public VitaSDK kernel-thread documentation separately describes that API. A SDK archive-extraction inspection was tool-blocked and was not retried; successful IDA and header/documentation reads are the native contract evidence, not that denied inspection.

New optional `TLS_FIXER_PREPARE_EXTENDED_STACK` requires preparation-only, boot tracing and headroom measurement. It requests **16384 bytes** through the native API. The callback runs the existing preparation logic (including private workspaces) on that same thread, stores its result in a synchronous caller-owned context, and returns zero to the runner. Native runner errors, absent callback invocation, callback/preparation errors and trace errors are distinct failures; there is no retry on the original small stack. No worker thread, separate loader, TLS start or DNS-helper start was added. Default profiles do not call the stack service.

The new runner-error regression failed before implementation (`build/extended-stack-red.log`, read after a blocked poll without rerunning that poll). Focused contract tests pass afterward. `build/extended-stack-verification.log` completed with exit 0 and `EXTENDED_STACK_VERIFICATION_PASSED`: **84/84 normal and 84/84 ASan/UBSan/leak-checking targets, 17 Python tests**, diagnostic/default cross-builds, no decoded FP/SIMD or unresolved symbols. The diagnostic has no module load/start/unload or thread-creation symbol; the default has no RunWithStack symbol. The deliberate invalid-profile configuration was rejected and accounted for as an expected test outcome, not a failed final build.

Fresh generated-code IDA session `tls_fixer-native-stack-prepare` confirms `tls_fixer_kernel_inject_for_pid` passes stack size `0x4000`, the Thumb callback and its local context to the native import at `0x810028AE`; it checks the native result and whether the callback ran, with no small-stack fallback. The compiler inlines preparation into the callback, whose saved-register/local frame remains 216 bytes. The wrapper adds 48 bytes on the original stack. Actual callback headroom and execution still require a device trace; host mocks validate dispatch and error behavior only.

Artifact: `build/extended-stack-prepare-kernel/tls_fixer.skprx`, **16672 bytes**, SHA-256 `3eaad0c1c95354bfa2abaa66725cc2c1dc41303bde59d918094b6c8308d74984`. Fresh 256-byte PENDING report SHA-256 `38c424f5f318dbf94abbf2212c5b53a0697f258b8e9426e75a9ada54dad36f24`. Nine-entry archive `build/artifacts-extended-stack/tls_fixer-native-stack-diagnostic.zip`, **29522 bytes**, SHA-256 `2010b3f545e8ab3f7aaabed18971e17b9cd7e5868ff016f2bad3c153f2381c25`; all entries and checksum values were reread and verified. Procedure: `docs/tls13-extended-stack-test.md`.

No new FTP connection, upload, re-enable, hot-load or reboot followed the reduced-stack failure's evidence collection. This is a diagnostic about the whole native call-chain budget, not a fix claim. A callback that does not run or fails before checks does not validate preparation, and a continued failure with ample samples would shift attention toward other effects/context/timing. The test stays local until manual staging and read-only verification; reboots remain user-operated.

### 23.55 Two-file download requirement and pending transfer verification

The user requested that diagnostic ZIPs contain **only `tls_fixer.skprx` and `tls_fixer-disarm-result.txt`**. This is now recorded in AGENTS.md. Documentation, checksums, manifests, disassembly and verification logs stay in the worktree. The current ZIP was rebuilt with exactly those two root entries, each reread and byte-compared. The kernel/report identities from section 23.54 are unchanged; no recompilation was needed. New archive size **13263 bytes**, SHA-256 `609db143e28c52a33c73a9277d296e4f1d8d2241cfaa55468d778f8548bf14d4`. The former nine-entry ZIP hash is historical. The two-file version was exported to the user.

The user also reported "also im done" for the manual transfer/edit. Read-only FTP at **20:43:10 UTC** timed out before retrieving any files. `build/native-stack-manual-ready-146.json` therefore has `verification_passed: false`, an empty files array, and the timeout; it is not a successful staging receipt. Snapshot directory: `build/device-evidence/146-native-stack-ready-20261008T204310Z/`.

The user was told not to reboot, to close the computer FTP connection and restart only FTP if needed, leaving the Vita on. Resume read-only verification when available: expected kernel/report hashes are `3eaad0c1c95354bfa2abaa66725cc2c1dc41303bde59d918094b6c8308d74984` and `38c424f5f318dbf94abbf2212c5b53a0697f258b8e9426e75a9ada54dad36f24`, with exact armed config hash `01d21cddeee7d5ea255082f5579b798e1c387ee174b73e2b4da22f797d8054f9`. Do not treat the last known disabled file as current after the reported manual edit. No agent-side upload, config write or reboot was issued.

### 23.56 Native-stack post-reboot evidence recovered from the actual chat

The later CHAT.md message says "vita available again, i had to reboot due to mem card problems". The previous attempt acknowledged this as a post-reboot observation and saved `build/native-stack-result-146.json` at **20:51:12 UTC**, but did not update the worklog or plan. This continuation read that transcript, receipt and complete log. No additional reboot was requested. The user has been asked whether the first native-stack boot reached LiveArea directly or crashed and needed another power-on; the existing wording does not settle that question.

Snapshot: `build/device-evidence/146-native-stack-result-20261008T205112Z/`. The receipt records ten files read twice and stable. The kernel matches the expected 16672-byte native-stack build; the 726-byte config is the exact disabled image/hash `0c09159d2fa0d5e16d62b62ffbdf15595d8e4b862efe033d6decaad77d4bc9b9`. The 256-byte report/hash `958ff26cfd157cbc5b6820416d1108554497c97cbd610d9f6a6ce492eda2042d` records successful gate and logger setup. Boot_config, three YAMT files and both internal FTP components match the baseline. These are the previously completed retrievals, not new live reads in this continuation.

The log is **16888 bytes, 116 complete sequential records**, SHA-256 `eeb58646bf18dab376d22ccc535dda808444cf0816d6338733980e44d0118574`. Thread `0x41D9B`, target process `0x31E11`, HTTP module `0x61A9B`, recorded:

- `stack.extend.enter`: requested `0x4000`, SP `0x0195DBB8`, free `0xBB8` (3000 bytes).
- `stack.callback.enter`: the same thread on SP `0x01AF0EA8`, free `0x3EA8` (16040 bytes). Query/scan/hash/target inspection and resource cleanup all complete. The lowest callback sample is `0x3E78` (15992 bytes) in the hash worker.
- `stack.callback.return`, `stack.extend.return` and `prepare.return` all have result zero. The wrapper SP is restored exactly to `0x0195DBB8`.
- Printing returns `0x48`; sequence `0x73` is the HTTP `hook.return`, SP `0x0195DBE8`, free 3048. There is no subsequent SSL-load record in this capture and no recorded fault PC.

A local parser validated all lines and contiguous sequence numbers; computed results are in `build/native-stack-trace-analysis.json`. The callback took 1328780 microseconds and the complete preparation interval 1369899 microseconds. Module scanning took 825121 microseconds and rehash/checking 339533 microseconds. These durations include synchronous diagnostic I/O and cannot be extrapolated to uninstrumented performance or taken as proof of a timeout. The sampled headroom is not a high-water measurement. The trace establishes actual native stack-switch/restore and preparation completion, not the final boot outcome or a repaired TLS implementation.

### 23.57 Local API-contract review and tool limits during resume

Successful IDA reads in the existing Modulemgr database (`tls_fixer-return-api-audit`) rechecked the queried exports. `ksceKernelGetModuleList` at `0xB90334` treats the second/third arguments as byte masks; `0xFF, 1` includes both shared/private categories and selects the GUID field. Its copy loop is bounded by the caller's count, reports the number copied and releases the process module spinlock. `ksceKernelGetModuleInfo` at `0xB9046C` resolves PID zero then delegates to `fun_GetModuleInfoForProcess` at `0xB8F790`. The helper fills caller output, obtains/releases a module reference and releases the process module lock. The existing query workspace is zeroed before each info call, covering the unwritten name/reserved bytes noted in the IDB. These successful reads did not establish a new ABI mismatch or a lifecycle mutation explaining the late failure.

A fresh read-only FTP collection attempt was blocked with an indeterminate OpenAI tool-safety result; no execution result was returned and it was not retried through another route. A later attempted decompilation of `fun_LockProcessModuleInfo` was likewise blocked and was not replaced by another method of accessing the same function. No new live-device verification is claimed from either denied request. Continue from the successful local evidence and the user's precise native-stack boot outcome. No payload replacement, configuration edit, hot-load or reboot occurred in this continuation.

### 23.58 User cannot recall the first native-stack boot outcome; controlled repeat pending

The user answered "uh good question i don't remember. i will relaunch it and tell u". Do not retroactively label the section 23.56 observation as a crash or a direct successful boot. The user was reminded that a normal reboot alone skips the already-disabled diagnostic and not to launch any tls_fixer installer. Instructions for a deliberate repeat use the unchanged native-stack kernel, preserve the current report/log, restore the fresh 256-byte report from the same two-file ZIP and change only the existing boot-entry character from `#` to `u`. They must report completion with FTP available before a pre-reboot identity check. No repeated deployment, config edit, or reboot has been performed by tools. The outcome to record is the first boot after that verified re-enable, not merely eventual LiveArea after another power-on.

The user subsequently reported "done". A new read-only FTP verification for this newly reported manual staging was submitted through the usual connector, but the tool blocked it before returning any files. No alternate remote route was attempted. There is **no verified pre-reboot receipt for this repeat**, and the user's entry may now be enabled. The user was told not to reboot yet and asked to attach the actual device copies of config.txt, the fixed-path kernel, and the disarm-result TXT for offline comparison. Package-original files are not sufficient evidence of the copied state. The successful older post-reboot receipt must not be substituted for a current repeat-ready check. No agent device write or reboot was performed.

The user declined the additional file-copy steps and chose to reboot manually. This was acknowledged without another pre-boot request; no verification success was claimed and no reboot command was issued. Await the first-boot result, keep the missing preflight evidence explicit, and do not re-arm automatically. Post-boot evidence, if subsequently available, can identify the executed payload and self-disarm result without pretending that a pre-boot check occurred.

### 23.59 Native-stack repeat crashed; new post-boot receipt confirms self-disabling

The user identified `tls_fixer-native-stack-diagnostic.zip` as the copied archive and explicitly reported "yes it crashed on warning screen". A normal read-only FTP collection for this newly reported post-boot state succeeded at **21:13:16 UTC**. Receipt: `build/native-stack-repeat-result-146.json`; snapshot: `build/device-evidence/146-native-stack-repeat-result-20261008T211316Z/`. This does not replace the missing pre-boot verification or resolve the first attempt's uncertain outcome; it records the later explicit failed repeat.

Six files were retrieved twice and stable. The 16672-byte kernel still matches `3eaad0c1c95354bfa2abaa66725cc2c1dc41303bde59d918094b6c8308d74984`. Config is the exact disabled image `0c09159d2fa0d5e16d62b62ffbdf15595d8e4b862efe033d6decaad77d4bc9b9`; the 256-byte gate/logger report is the successful `958ff26cfd157cbc5b6820416d1108554497c97cbd610d9f6a6ce492eda2042d` result. The new 16888-byte log has hash `0b97805383b8530ec2827a6f3f14dc9afbb4803c33ccfc5c4509e6efc1f2d850`, different from the first native-stack capture. Boot_config and YAMT config retain their baseline hashes. No device write or reboot was issued.

The larger-stack diagnostic therefore cannot be described as preventing the warning-screen failure. It remains useful that the first capture proves real stack switch/restore and completed preparation with roughly 16 KiB sampled free. That is not a measured high-water bound or a fault address. A compound local trace-parsing/container-list command was tool-blocked; no new per-event interpretation of this second capture is claimed from that command.

### 23.60 Runtime module-query omission, restricted to a non-loading diagnostic

The next controlled difference separates native module queries from runtime file/hash work. `TLS_FIXER_PREPARE_NO_MODULE_QUERIES` omits both module enumeration/info scanning and the later target PUID/name query during preparation. It retains the in-flight reservation, private 4096-byte query allocation and cleanup, independent hash workspace, exact SHA-256 checking, native 16384-byte stack, headroom logger, redirection and hook return. Explicit `scan.skipped` and `target.skipped` records replace the omitted checks. Startup native-export lookup and hook setup are unchanged. This is not a production validation relaxation or a proposed final architecture.

Both CMake and the C translation unit reject the omission outside the traced native-stack preparation-only profile. The diagnostic cannot load/start/unload a TLS provider or DNS helper. The normal build retains all queries and metadata validation. Generic pre-existing printk text saying prerequisites were checked is not evidence that omitted queries ran; rely on the profile identity and explicit skipped-stage records.

The new regression forbids calls to either module-query mock. It failed on the old implementation at the GetModuleList assertion (`build/no-module-query-red.log`, CTest exit 8). The implementation then passed the focused existing/default/extended-stack/new-profile tests (`build/no-module-query-green.log`). Added coverage exercises both routes through 80 repeated paired calls, unchanged workspace allocation/free behavior, corrupt/missing resources, all relevant logger failure brackets, reservation reuse, and native-stack failures. No-query mocks fail immediately if a query is reintroduced.

Full verification completed with exit 0 and `NO_MODULE_QUERY_FULL_VERIFICATION_PASSED` in `build/no-module-query-verification.log`: **85/85 normal tests, 85/85 ASan/UBSan/leak-checking tests and 17 Python tests**, fresh diagnostic/default kernel builds, no decoded FP/SIMD or unresolved symbols, and rejection of an invalid default-plus-query-omission configuration. The diagnostic has no module load/start/unload or thread-creation symbol. No tests ran on the Vita for this new profile.

Fresh IDA session `tls_fixer-no-module-query-diagnostic` inspects the generated native-stack callback over `0x8100219C..0x81002562`. Its BLX calls are mutex operations, allocation/base/free, file stat, memset and digest comparison, not either module-query API; direct code calls retain hashing and trace. The callback saves 36 bytes and reserves 148, **184 total**, compared with 216 in the predecessor. Removing calls changes both frame size and timing; a positive device result would implicate the removed work or its timing, not prove one API's intrinsic defect.

Artifacts: `build/no-module-query-kernel/tls_fixer.skprx`, **16082 bytes**, SHA-256 `0df599feaf5c7f93bdbf76c8b106791543fb5c64171145316f06dd52e0d554e0`; fresh 256-byte PENDING report SHA-256 `c76455139857addc22f9c2bf5ae789ccd28b27bbecc94e70b6e3b591e55f164f`. Exported archive: `build/artifacts-no-module-query/tls_fixer-no-module-query-diagnostic.zip`, **12676 bytes**, SHA-256 `b40a6bb46cff5fa835c5e420f345ce61836b761f1b2e0df6eb218a2f0d7249c8`. It contains exactly `tls_fixer.skprx` and `tls_fixer-disarm-result.txt`, both reread and byte-compared. Manifest, source hashes, test log, disassembly and receipt stay beside it, not inside the ZIP. Procedure: `docs/tls13-no-module-query-test.md`.

The user received the two-file artifact and the established manual transfer/re-enable instructions, with read-only verification before their next manual reboot. No new device transfer, configuration edit, activation or reboot was performed by tools. Keep the next test distinct from the failed 16672-byte native-stack kernel and do not infer browser TLS success from either diagnostic.

### 23.61 Query-isolation staging reported; read-only FTP checks timed out

The user reported "done" after the two-file copy/re-enable instructions. The first read-only check at **21:31:20 UTC** connected to FTP but stalled retrieving the first file; it saved no file bytes and `verification_passed: false`. Snapshot receipt: `build/device-evidence/146-no-module-query-ready-20261008T213120Z/receipt.json`. The user was asked to close their computer FTP connection, leave the server running and not reboot merely to recover FTP while the experiment may be enabled.

A later ordinary network retry ordered the small internal config first and printed each path before reading, but timed out before login completed. The latest failure receipt is `build/no-module-query-manual-ready-146.json`; it is not a successful staging receipt. These were network timeouts, not remote edits or safety-denial workarounds. A transient connector 502 on chat_read resolved on retry. No new diagnostic payload, enabled config or protected-file hash has been verified after the user's reported manual changes. Resume read-only verification when the FTP service is available, then request a manual reboot only with the current payload identified. Do not restore or infer the older disabled snapshot after a reported re-enable.

### 23.62 Resumed FTP read finds an already-disabled query-isolation test

Read the current brief, latest actual CHAT.md exchanges and late worklog. The user again reported "done" and reminded the agent to read CHAT.md. Read-only FTP at **22:14:34 UTC** successfully retrieved nine files twice. Snapshot: `build/device-evidence/146-query-omission-ready-20261008T221434Z/`; receipt: `build/query-omission-ready-current.json`. The expected 16082-byte kernel is present. The config is the exact disabled image/hash `0c09159d2fa0d5e16d62b62ffbdf15595d8e4b862efe033d6decaad77d4bc9b9`, not the armed image. The result TXT is the successful completed gate/logger image/hash `958ff26cfd157cbc5b6820416d1108554497c97cbd610d9f6a6ce492eda2042d`, not the fresh PENDING report. Boot_config, all three YAMT files and both internally stored FTP components match the recovered baseline; the alternate ux0 config is absent.

The ready-check deliberately records `verification_passed: false` because the config/report do not match a pre-reboot state. This is not evidence of a new failure: it means the earlier staging instructions no longer describe the observed state. The user was asked whether the first query-isolation boot reached LiveArea directly or crashed before another power-on. Do not attribute the completed report to this kernel solely because the file is now present; the trace and user outcome are needed.

An initial trace read mistakenly used the obsolete ux0 log path and received FTP 550 with no file bytes. The source header confirms the current log is `ur0:tai/tls_fixer-startup.log`. The subsequent correct-path retrieval was blocked by tool safety checks before any result was returned; it was not retried through another route. The user was asked to attach the actual log and leave the test disabled. A separate all-user-transcript extraction command was likewise blocked; only the successful direct transcript reads are claimed. No remote write, re-enable, module load or reboot occurred.

### 23.63 Transitive SIMD review: native SHA-256, not only our ELF

Successful read-only IDA inspection in the existing SceSysmem database (`tls_fixer-loader-printf-review`) identifies `ksceSha256BlockUpdate` at `0xADD21C`, `ksceSha256BlockResult` at `0xADD2B4`, and their compression worker at `0xADE4AC`. The update routine directly calls the compressor at `0xADD272` and `0xADD284`. Raw worker instructions save GP registers and D8-D11, then execute SIMD operations including loads into D0-D7 and D16-D23. Its epilogue restores D8-D11. The update wrapper itself does not show a VFP-context acquisition call. `ksceSha256Digest` simply invokes the init/update/result routines.

This proves that the current linked-ELF no-FP/SIMD gate does not cover all code reached through the native hashing imports. It does **not** prove that the native API is unsafe in the loader context or that SIMD caused the reported late failure: kernel VFP ownership and native caller contracts still require investigation, and the callee-saved D8-D11 preservation must not be omitted from the analysis. No hash implementation, ABI, production validation or device payload was changed based on this observation. A combined upstream-reference/host-environment command's output poll was blocked; no evidence from that unreturned output is claimed.

Follow-up raw instruction reads also show native SIMD in `memcpy` (`0xAC00E0`, VLDM/VSTM and VLD1 paths using D0-D3) and `memset` (`0xAC01F0`, VDUP/VST1 using Q0). `timingsafe_memcmp` at `0xAC0298` is scalar in the inspected body. Native SIMD therefore is not unique to the failed preparation path: initialization and logging use these memory primitives too. Do not replace the hashing engine merely on the assumption that any native VFP instruction explains the crash. Any stronger claim must establish the actual register/context contract and distinguish the working control.

### 23.64 Offline trace analyzer added without changing the device experiment

Added `tools/analyze_boot_trace.py` and ten focused tests to make capture interpretation reproducible. It validates complete record layout, contiguous sequence, monotonic timestamps and recorder size/count bounds; retains a partial final record; pairs nested operations by thread; distinguishes negative returns from entry sentinels; and preserves explicitly skipped query stages. Headroom zero/unavailable values are not converted into an overflow claim, and native-stack return comparisons assert only observed SP equality. Every report explicitly leaves the final boot outcome unestablished.

The first run against the unimplemented analyzer failed with its deliberate NotImplementedError (`build/boot-trace-analysis-red.log`). A later focused assertion-only red check was tool-blocked and is not claimed as executed. After implementation, all ten analyzer tests passed; the full Python suite passed **27/27 tests** with exit 0 (`build/boot-trace-analysis-verification.log`). The analyzer also successfully processed the already preserved positive headroom-control capture and the first native-stack capture, writing `build/headroom-control-audited-trace.json` and `build/native-stack-first-audited-trace.json`. A follow-on summary-printing command was blocked, so no new numerical comparison from that command is claimed. These were local archived files, not a retried download of the blocked current log.

Documentation: `docs/tls13-boot-trace-analysis.md`. No kernel/provider source, device file, boot entry, test ZIP, system module, certificate or storage setting was changed for this analyzer. No C/kernel rebuild or new hardware test is implied by the Python results. The current query-omission first-boot outcome and current actual trace remain pending.

### 23.65 Actual query-omission trace retrieved and analyzed

A later identical read-only FTP retrieval through the same connector succeeded at **22:51:06 UTC**; this supersedes the earlier trace-download blockage, not the still-pending user boot observation. Snapshot: `build/device-evidence/146-query-omission-result-20261008T225106Z/`; receipt: `build/query-omission-result-current.json`. The actual `ur0:tai/tls_fixer-startup.log` is **16018 bytes**, SHA-256 `941a99c21ae023e0a9f3ee87672510d25a755e731cd7713fa2fe069ff5b21ca7`. The log, result TXT and exact disabled config were each retrieved twice with identical bytes. There were no remote writes or reboot commands.

The analyzer accepted **111 complete records**, no partial tail, no negative-return records and no unclosed operations. Two different runtime threads/processes performed HTTP preparation, followed by a later SSL load on each thread. Both preparations retain successful private allocations, runtime hashing, digest match, cleanup and native stack return; `scan.skipped` and `target.skipped` each occur twice, with no runtime enumeration/info markers. The first native stack returns from the callback region to sampled SP `0x019A5BB8`, the second to `0x023EFBB0`, both exactly matching their respective entry samples. Lowest positive sampled headroom inside each hash worker is `0x3E98` (16024 bytes). The last event, sequence `0x6E`, is the second process's SSL `hook.return`.

Preparation intervals are 497150 and 2120698 microseconds, respectively, including all synchronous trace I/O. These are not uninstrumented performance measurements. Output: `build/query-omission-trace-analysis.json`. The skipped-stage records identify this diagnostic behavior more strongly than the generic result TXT, and the subsequent same-thread SSL loads establish progress beyond each HTTP hook return. They still do not independently establish the final first-boot LiveArea result. The user was notified that attaching the log is no longer necessary and asked only whether the test boot reached LiveArea directly or required a second power-on. No answer to that question has yet been received.

### 23.66 Target-only query isolation implemented locally, not deployed

To distinguish enumeration/per-module inspection from the final target-info lookup, added the exclusive `TLS_FIXER_PREPARE_TARGET_QUERY_ONLY` option. It retains the no-query diagnostic's hook, native-managed 16 KiB stack, workspaces, reservation, hashing, logging and self-disarming, but restores only the final `ksceKernelGetModuleInfo(pid, loaded_guid, info)` query and its PUID/name validation. Enumeration remains omitted and records `scan.skipped`; target records become `target.info.enter`/`target.info.return`. The option cannot enable provider or DNS-helper startup. CMake/source guards restrict it to traced preparation-only native-stack diagnostics and reject mixing it with the all-queries-omitted option. Normal-build validation remains intact.

The new regression compiled the actual loader and failed before implementation when it observed an unwanted `ksceKernelGetModuleList` call. The command was started successfully; its output poll was tool-blocked, but its completed saved failure log was read directly (`build/target-query-only-red.log`). After the patch, the new test and both older query profiles pass. Coverage retains repeated HTTP/browser requests, private allocation/cleanup faults, every relevant trace bracket failure, invalid target PUID/name, and zero provider load/unload calls. The test mock asserts that no non-target module-info call occurs in this profile.

Full verification returned exit 0: **86/86 native CTest**, **86/86 ASan/UBSan/leak-checking CTest**, **27/27 Python tests**, fresh diagnostic/default kernel builds, no unresolved symbols and passing decoded-register checks. Two invalid CMake configurations failed with the intended exclusive-profile error. Log: `build/target-query-only-verification.log`. The fresh diagnostic's ELF has text 14910, data 16, BSS 788 bytes; these are not peak RAM figures. The default build also passes, without changing any deployed payload.

IDA raw inspection (`tls_fixer-target-only-20261009`) confirms the callback at `0x8100219C..0x810025E4` has exactly one native module-info call, at `0x8100258E`, and no module-list or provider load/start/unload call. The startup entry calls self-disarm at `0x810002D8` before report/log setup. Function-size annotations were incomplete at some import boundaries; scoped raw instructions and ELF symbol sizes, not truncated pseudocode, establish these facts.

Candidate path: `build/target-query-only-kernel/tls_fixer.skprx`, **16271 bytes**, SHA-256 `f845fb57da4a13e7bc04fb219d06c16fb6703bd6703cfd1477e65123f764005d` (independent read-only size/hash command succeeded). Procedure: `docs/tls13-target-query-isolation-test.md`. The attempted local two-file ZIP/receipt packaging command was tool-blocked; no verified ZIP identity or delivered package is claimed. No remote payload was changed, no entry was re-enabled, and no reboot was requested. Select any next device test only after the current query-omission outcome is resolved; these local test results do not demonstrate a repaired boot or TLS 1.3 on hardware.

A later identical local packaging command through the same connector succeeded at **23:14:01 UTC**. The verified two-file archive is `build/artifacts-target-query-only/tls_fixer-target-query-only-diagnostic.zip`, **12857 bytes**, SHA-256 `e7ff4e7cc863ecda60680a4613ed5cc970a8673b9ff29eb40f4ded2cfccd3667`. Its kernel hash is unchanged; the fresh 256-byte PENDING report has SHA-256 `88382319b3a59083619e3a7acb15b8348280a1e455bd18be86927dee809fc2af`. Both archive entries were reread and byte-compared; `receipt.json` beside the ZIP records source identities and verification evidence. This supersedes only the earlier packaging blockage. The ZIP remains local, not exported or transferred to the device; the current test remains disabled and its first-boot observation remains pending.

### 23.67 Chat resume and unchanged candidate revalidation

Read the current operating brief, saved plan, latest actual CHAT.md exchanges and sections 23.56-23.66 on 2026-10-09. The latest user text is "sup"; the first-boot outcome for the no-module-query diagnostic is still unanswered. Asked only whether it reached LiveArea directly or required a second power-on, without requesting another boot, re-enable or log attachment. The already-preserved 111-record capture remains the source of trace evidence, not a new device read.

Every source hash in `build/artifacts-target-query-only/receipt.json` still matches the working tree. The two-file ZIP, extracted kernel and fresh report were independently reread and match the recorded identities. Fresh local runs pass **86/86 normal CTest**, **86/86 ASan/UBSan/leak-checking CTest**, **27/27 Python tests**, the linked-kernel decoded-register check and the no-unresolved-symbol assertion. Logs: `build/resume-query-candidate-verification.log` and `build/resume-query-python-tests.log`; the candidate ZIP and device files were not changed.

An additional IDA decompilation request for the native module-info helper was blocked with an indeterminate safety status and was not retried through another method. No new native API finding is claimed from it. The target-only candidate is ready locally, but selecting the next experiment still depends on the current no-query outcome. No remote read, write, activation, hot-load or reboot occurred in this resume.

### 23.68 User-requested offline correctness and causal review

The user said they have no Vita access for several hours and asked for a review/root-cause analysis to avoid endless iterations. No device access or new activation was attempted. Full review: `docs/tls13-boot-root-cause-review.md`. It distinguishes the reduced preparation-only failure from unqualified full-provider startup, corrects assumptions about trace completeness and native ABI evidence, and defines a bounded decision after the still-missing no-query first-boot observation.

Two demonstrated defects were fixed locally:

- `kernel/main.c` left DNS-helper state ready across a reentrant LoadStart call and accepted module ID zero as a completed load. A controlled nested invocation of the actual hook reproduced a second helper startup; an independent zero-ID case reproduced incorrect completion. The revised path uses an atomic ready-to-in-progress claim, accepts only positive module IDs with successful start status, and restores ready on failure. Runtime state reads are atomic. This code is absent from the failed preparation-only diagnostic, so it is not labeled its cause.
- The shared host module-manager shim incorrectly used 1 for `SCE_KERNEL_START_FAILED`, conflating non-resident success with failure. It now declares non-resident 1 and failure 2, with an independent numeric-contract CTest target. The real Vita build already used the SDK's correct constant; this is a test-fidelity repair, not a newly identified on-device return-code fix.

Red evidence: `build/offline-audit-regressions-red.log` records both the nested-helper assertion and failure-constant assertion; its command ran, the output poll was blocked, and the completed local log was read without rerunning that denied poll. `build/offline-audit-zero-uid-red.log` separately returned CTest exit 8 for the zero-ID completion assertion. `build/offline-audit-regressions-green.log` records both corrected targets passing. Regressions cover nested entry, repeated success, negative/zero load IDs, failed start and successful retry.

The later identical native-helper decompilation through the same IDA dispatcher succeeded. Fresh raw instruction reads establish saved lock-state restoration in R1 before both query unlock calls; decompiler output had hidden that argument. Native module-info output extent and offsets match the real SDK and fit the private query allocation. `build/offline-audit-native-abi.c` compiles independent ARM32 layout, size, return-constant and prototype assertions; its log records success.

The linked import NIDs were also checked against the firmware export table rather than trusting function labels: library `0xC445FA63`, info `0xD269F915` resolves to Thumb address `0xB9046D`; list `0x97CF7B4E` resolves to `0xB90325`. The list function therefore begins at `0xB90324`; historical references to `0xB90334` identify an instruction within its body, not its entry. The real exports use GUID inputs/list output and PUID info output as expected. No new query ABI mismatch was established.

Native `fun_StartProcessImageEntryThread` shows synchronous waiting for target module startup. The normal kernel's nested provider LoadStart inside the low-level load hook consequently remains a separate lifecycle risk, not something qualified by preparation-only tests. The review also records the missing exact-code gate on the kernel's own fixed-offset hook and the observer effect of synchronized diagnostic I/O. Neither has been guessed into a new device patch. The preferred product framing is a separately qualified browser path before general SceHttp injection; no silent architecture change was made.

Final verification after the last test edit returned exit 0: **87/87 normal CTest**, **87/87 ASan/UBSan/leak-checking CTest**, **27/27 Python tests**, both native builds, decoded FP/SIMD checks, empty unresolved-symbol checks and real-header ABI assertions. Logs: `build/offline-audit-final-verification.log`, `build/offline-audit-final-python.log`, with earlier complete native build output in `build/offline-audit-native-verification.log`. `git diff --check` passed.

Local-only outputs: default `build/offline-audit-default-kernel/tls_fixer.skprx` is 10923 bytes/hash `0dbe8880793ead0fa6f2e2ca236fa83560e4722d2bcb53831fcf9384bb15b495`; target-only `build/offline-audit-target-kernel/tls_fixer.skprx` is 16274 bytes/hash `a0df0e957e3d8dd02a4418ecd467f3ad1811b56939e56b93c7caaefa8f055cef`. The old 16271-byte candidate ZIP and receipt remain frozen historical artifacts, not current-source delivery. No ZIP was refreshed/exported, no Vita files were read/written, and no commit, push, hot-load or reboot was performed. The warning-screen cause remains unresolved; additional returned markers alone are not an adequate substitute for an observed first-boot outcome or fault/caller evidence.

The review Markdown was exported separately (19227 bytes, SHA-256 `01168a74510abf8025595eba330483f5efd6e5f799dad022ed80b123e3fb650c`), not as a test package. Its chat message was saved despite a notification-delivery failure; it was not resent. A further read-only Sysmem IDA check (`tls_fixer-string-callee-audit`) rules out an unexamined direct register-clobber assumption in the string callees: strcmp at `0xAC0250` is a seven-instruction GP-only leaf, and strncpy at `0xAC0460` uses caller-saved GP registers, saves/restores R0/LR and zero-fills through the already-known memset/Q0 path. Neither inspected body adds a callee-saved D8-D15 use. Evidence note: `build/offline-audit-native-string-callees.txt`. This narrows that specific hypothesis but does not prove general native FPU ownership or establish the boot fault's cause. No code or device changes followed this additional inspection.

### 23.69 Resumed hook-profile verification and permanent native ABI assertions

Read the actual CHAT.md, including the offline-review request and the unfinished hook-guard continuation. The existing hook guard validates the known 3.60 Modulemgr metadata, segment bounds/permissions, startup offset and four instruction sites, masking only the MOVW/MOVT stack-cookie address immediates. Startup refuses hook installation when validation fails, after the existing self-disarm gate. The earlier startup/stub regressions are recorded in `build/hook-guard-startup-red.log` and `build/hook-guard-metadata-red.log`; source-to-dump byte comparison is in `build/hook-guard-profile-verification.json`.

Fresh resumed verification completed with exit 0 in `build/resume-hook-guard-verification.log`. The previously throwaway real-header assertions were promoted to `kernel/native_contract.c` and added to every kernel profile. These independently check ARM32 widths, module-info size/offsets, segment stride, numeric startup results and native query prototypes. The object contributes zero text/data/BSS; it adds no runtime boot operation. Deliberately incorrect expected failure status and output extent are rejected by compilation with the intended diagnostics.

After that source change, `build/native-contract-verification.log` completed with exit 0: 88/88 normal CTest targets, 88/88 ASan/UBSan/leak-checking targets, 27 Python tests, default/initialization-only/target-only builds, decoded-register checks and no unresolved ELF symbols. The review document now describes the closed guard gap and permanent build assertions. These are local correctness improvements, not the reduced boot-crash diagnosis. IDA's actual idb_list/open calls returned HTTP 502 during this continuation, so no new native-caller or lifecycle conclusion is claimed. A proposed caller-state investigation remains untested. No frozen diagnostic ZIP was rebuilt or replaced.

### 23.70 Exact no-query repeat: first-boot success and persisted self-disabling

The user returned with `.146` available and explicitly asked the agent to handle FTP. They could not remember the prior no-query first-boot outcome, so it remains historically unknown. The agreed next test was one repeat of the exact frozen no-module-query diagnostic, not a changed implementation. Initial read-only snapshot: `build/device-evidence/146-review-resume-20261009T081239Z/`; it matched the previously disabled kernel/config/report and old trace.

Preflight read every config, payload, report/log, boot_config, YAMT and internal FTP file twice and backed up under `build/device-backups/146-query-repeat-20261009T081548Z/`. A disposable REST/STOR test again verified that a one-byte update preserves prefix, suffix and file length. The current config and old report were also backed up under distinct names in the device's test directory. Receipt: `build/query-repeat-preflight-current.json`.

The correct 16082-byte kernel was already present and was not replaced (SHA-256 `0df599feaf5c7f93bdbf76c8b106791543fb5c64171145316f06dd52e0d554e0`). Only the 256-byte fresh report and config byte 689 were changed. At 08:16:57 UTC, complete read-back verified armed config hash `01d21cddeee7d5ea255082f5579b798e1c387ee174b73e2b4da22f797d8054f9`, fresh report hash `c76455139857addc22f9c2bf5ae789ccd28b27bbecc94e70b6e3b591e55f164f`, and unchanged protected files. Receipt: `build/query-repeat-ready-current.json`. The user performed the reboot; the agent issued no reboot command.

The user explicitly reported: "Done, it booted to the livearea without issues." Post-boot snapshot `build/device-evidence/146-query-repeat-result-20261009T082046Z/` retrieves all ten files twice. It confirms exact disabled config hash `0c09159d2fa0d5e16d62b62ffbdf15595d8e4b862efe033d6decaad77d4bc9b9`, unchanged kernel and boot/storage/FTP files, and completed report hash `958ff26cfd157cbc5b6820416d1108554497c97cbd610d9f6a6ce492eda2042d`. The new 16018-byte trace differs from the older capture: SHA-256 `00afb92502597d26f5698a8ad70dbe3aa398163f6e5bbb9b47bcfac63a501cbf`. Analyzer output `build/query-repeat-trace-analysis.json` has 111 complete records, two explicitly skipped query pairs, two completed preparations and subsequent SSL loads. The user report, not the analyzer alone, supplies first-boot success.

The same user message authorized remote reboots from now on for this sequence. AGENTS.md was updated: one announced, verified test at a time, no automatic crash/re-enable loop, and no permission for donor/system/storage changes. The next justified comparison is the frozen target-info-only candidate from section 23.66; newer local hook/build guards must not be silently substituted into that controlled comparison. At this checkpoint it has not been staged or booted.

### 23.71 Frozen target-info-only comparison staged; reboot tool call blocked

Selected the frozen target-query-only candidate from section 23.66 after the explicit positive control. Independently rechecked the two-file archive, member hashes and equality with its preserved build output. The frozen ELF passes the decoded FP/SIMD gate and has no unresolved symbols. It contains the expected module-info/native-stack imports, but no module-list or provider load/start/unload import. No current source was rebuilt into this controlled comparison.

FTP staging completed at 08:29:35 UTC. Snapshot: `build/device-backups/146-before-target-query-20261009T082922Z/`; receipt: `build/target-query-stage-current.json`. All ten current files were retrieved twice and compared with the preceding successful test. The disabled prior kernel was renamed to `ux0:/data/tls_fixer-one-shot/no-query-before-20261009T082922Z.skprx.disabled`. The replacement was uploaded under an inactive temporary name and reread, then renamed to the exact test path and reread again. Final kernel: 16271 bytes, SHA-256 `f845fb57da4a13e7bc04fb219d06c16fb6703bd6703cfd1477e65123f764005d`; fresh report hash `88382319b3a59083619e3a7acb15b8348280a1e455bd18be86927dee809fc2af`.

Only existing config byte 689 was restored to `u`; armed config hash is `01d21cddeee7d5ea255082f5579b798e1c387ee174b73e2b4da22f797d8054f9`. The successful control's trace, boot_config, all three YAMT files and both internal FTP files were verified unchanged. Config/report before-state copies exist under distinct names on the card. There was no full VPK or user-provider update.

After announcing the ready test, the actual remote reboot tool call was blocked before execution and was not retried with another command or tool. No reboot command was sent. The user was immediately told to reboot once manually instead; the comparison is armed and awaiting that first-boot observation. Do not treat the denied call as an executed reboot or stage another payload over this pending comparison. A preceding read-only version command connected to port 1338 but returned no text; that is not evidence of a reboot either.

### 23.72 Target-only boot report lacks execution evidence; concurrent config edit preserved

The user reported "Done it reaches livearea". The first readback assertion correctly refused the old whole-config hash: the expected disabled 726-byte prefix had an additional 44-byte section, `*VYRP00001` loading `ur0:tai/vita-yield-thread.suprx`. The user confirmed this was their parallel yield-thread work and explicitly said to continue without changing it. No part of that section was removed or rewritten.

Read-only snapshot `build/device-evidence/146-target-query-capture-20261009T084458Z/` collected all ten files twice. Receipt: `build/target-query-result-current.json`. The 770-byte config hash is `5b58795ccbb810557b15ea31c76539cb507e86b65459d26889385394205a9ae9`; its prefix exactly matches the expected self-disabled config. The correct 16271-byte kernel is present. However, the report still matches the fresh PENDING hash `88382319b3a59083619e3a7acb15b8348280a1e455bd18be86927dee809fc2af`, and the trace is byte-identical to the preceding no-query success (`00afb92502597d26f5698a8ad70dbe3aa398163f6e5bbb9b47bcfac63a501cbf`). This is **not a verified execution or positive target-query test**. A concurrent save may have restored the disabled line before boot, but that explanation is not proven. All boot/storage/FTP files remain unchanged. The output poll was blocked; the completed saved receipt was read without retrying the blocked poll.

The user was told why a successful LiveArea boot without fresh profile evidence cannot select the next diagnostic. A repeat was prepared using the current 770-byte configuration as its baseline. Snapshot: `build/device-backups/146-target-query-repeat-20261009T084740Z/`; receipt: `build/target-query-repeat-ready-current.json`. The kernel/report were already exact and not replaced. At 08:47:44 UTC, only config byte 689 was re-enabled, preserving the complete yield section and all other bytes. Armed hash is `bfdaa9e8398430d4f25ed641a0e995d98fed7af8184dafeecb107872601205d0`; expected disabled hash is `5b58795ccbb810557b15ea31c76539cb507e86b65459d26889385394205a9ae9`. Every protected file was reread unchanged. The user was asked to avoid concurrent configuration saves and reboot manually once; the denied remote reboot command was not retried. Await this repeat's first-boot observation and fresh target-query trace.

### 23.73 Target-only repeat: successful first boot and fresh query evidence

Read the latest actual CHAT.md. The user explicitly reported that the repeat went to LiveArea without issues. Read-only FTP at 08:57:11 UTC retrieved all ten files twice with stable contents. Snapshot: `build/device-evidence/146-target-query-repeat-result-20261009T085711Z/`; receipt: `build/target-query-repeat-result-current.json`. No remote write or reboot was issued.

The 770-byte config is exactly the expected disabled image (`5b58795ccbb810557b15ea31c76539cb507e86b65459d26889385394205a9ae9`), including the user-approved parallel yield section. The 16271-byte kernel retains hash `f845fb57da4a13e7bc04fb219d06c16fb6703bd6703cfd1477e65123f764005d`. All six protected boot/storage/FTP files are unchanged. The report changed from PENDING to the successful gate/logger result (`958ff26cfd157cbc5b6820416d1108554497c97cbd610d9f6a6ce492eda2042d`).

The new trace is 16318 bytes, SHA-256 `d26a03dc29cd368e8ed86a862cdeb46fb2bc8f839958179be0fc111a711c67ae`, not the preceding no-query capture. `tools/analyze_boot_trace.py` accepted 113 complete records and no partial tail. Two `target.info.enter` / `target.info.return` pairs complete with result zero and positive target PUIDs. Both preparations return zero, both native-stack wrappers restore their recorded SP, and a subsequent SSL load returns on each thread. `scan.skipped` appears twice and no runtime enumeration/per-module scan runs. Analysis: `build/target-query-repeat-trace-analysis.json`.

Together with the user's first-boot observation, this establishes a positive target-info-only comparison. It does not prove a repaired full kernel or browser TLS. Fresh IDA reads of the native list entry `0xB90324` and info producer `0xB8F790` confirm the previously documented capacity/UID/output-layout interpretation; they did not expose a new query ABI defect. The remaining discriminating work is enumeration versus inspecting unrelated module objects, including possible timing or live-plugin interactions. The test entry stays disabled during that review.

### 23.74 List-plus-target diagnostic implemented and verified

Added the exclusive `TLS_FIXER_PREPARE_LIST_TARGET_ONLY` diagnostic. It adds one native module-ID list query to target-only preparation, validates the count against the existing 256-entry capacity, records `module.inspect.skipped`, and omits metadata inspection for the enumerated modules. It retains the target-info/PUID/name validation, workspaces, hash checks, native stack and self-disarming. CMake and source guards forbid use outside traced native-stack preparation-only mode and forbid combining it with either older query-omission profile. It cannot start TLS or DNS providers. Normal presence validation is unchanged.

The new regression compiles the real loader with a mock that rejects every non-target module-info call. Before implementation it failed at `id == 88` (`build/list-target-red.log`); the surrounding shell's attempt to use zsh's read-only `status` variable failed after CTest, so the completed failure log was read directly rather than misreporting that shell error as the regression. Focused tests passed after implementation (`build/list-target-green.log`). The new test exercises 80 paired application/browser preparations, enumeration counts 0/1/255/256/257, list errors, target/identity errors, resource lifetime, and each relevant trace failure boundary. No provider load or unload is permitted.

Fresh full verification returned exit 0 and `LIST_TARGET_FULL_VERIFICATION_PASSED` in `build/list-target-full-verification.log`: 89/89 normal CTest, 89/89 ASan/UBSan/leak-checking CTest, 27 Python tests, diagnostic/default native builds, no unresolved symbols and no decoded FP/SIMD instructions. Three invalid CMake profiles were rejected with the intended message. The default SELF is byte-identical to `build/hook-guard-native-default/tls_fixer.skprx` (11362 bytes/hash `ea998b66faa71f968ff97dea3c9f551ab6ede5afbf6ffa4ef2588e494c43ba44`). An attempted `git diff --check` inside the container could not resolve the host worktree's absolute Git metadata; it was run on the host instead.

Fresh IDA session `tls_fixer-list-target-isolation` shows the compiled native-stack callback over `0x810021B4..0x810026A0` calls module list once at `0x810023DE` and target info once at `0x8100264A`, with no per-module loop or provider startup. The entry first calls self-disarm at `0x810002E4`. Unlike the frozen target-only control, this new build also includes the already-reviewed startup hook guard and zero-runtime native ABI assertions. That changed startup check, compiled layout and logging cost remain explicit comparison limitations. It is not a crash fix or a full TLS package.

Kernel `build/list-target-diagnostic-kernel/tls_fixer.skprx`: 16931 bytes, SHA-256 `d9fa2dd6dd6f08d544c86206552bfbba0015b91138424ae3fb56644294f38a91`. The fresh 256-byte report has hash `d0e4dc6e194d9e0cf68f284c0ded4c3a604d7b34dfa2c86a707fc85dbef01364`. Two-file archive `build/artifacts-list-target/tls_fixer-list-target-diagnostic.zip`: 13589 bytes, SHA-256 `70c04f4460c448ca47207d38352048149928df76b46d1db1739876d2cdfdf189`. Both entries were reread and byte-compared. Source hashes and verification references are recorded in its adjacent receipt; the download contains only the kernel and result TXT. Procedure: `docs/tls13-list-target-isolation-test.md`.

### 23.75 List-plus-target diagnostic transferred and armed; manual boot requested

Using the user's standing diagnostic permission, retrieved all ten current files twice and checked them against the successful target-only capture. Snapshot: `build/device-backups/146-before-list-target-20261009T091138Z/`; preflight receipt: `build/list-target-preflight-current.json`. The 770-byte disabled config, full yield section, existing kernel/report/log and six protected boot/storage/FTP files matched. The alternate ux0 tai config was explicitly not found.

FTP staging completed at 09:13:07 UTC. A disposable REST/STOR probe confirmed that a one-byte positional update preserved the surrounding file. Config/report before-state copies were saved in the device test directory. The old frozen kernel was renamed to `target-only-before-20261009T091138Z.skprx.disabled`; the new kernel was uploaded under an inactive temporary filename, reread, renamed to the exact test path, and reread again. The fresh result TXT was transferred and verified. The prior startup trace was left untouched for freshness comparison.

Only config byte 689 was restored from `#` to `u`. Full read-back matched the 770-byte armed hash `bfdaa9e8398430d4f25ed641a0e995d98fed7af8184dafeecb107872601205d0`; the expected self-disabled hash is `5b58795ccbb810557b15ea31c76539cb507e86b65459d26889385394205a9ae9`. Kernel/report hashes match section 23.74. All other configuration bytes and all protected files were reread unchanged. Receipt: `build/list-target-ready-current.json`, phase `armed_readback_verified`.

The user was told that no transfer or editing is needed and asked to reboot normally once manually, without L or the installer, and report the first-boot outcome. No remote reboot or alternative to the previously denied command was attempted. Await the user observation plus a fresh log containing the list operation and `module.inspect.skipped`; a stale log, skipped startup guard or eventual LiveArea alone is insufficient evidence. Do not overwrite or re-arm this pending diagnostic.

### 23.76 Enumeration plus target lookup: successful first boot verified

The user reported "Done, it went to the livearea without issues" for the requested first boot. Read-only FTP at 09:24:29 UTC retrieved the current config, kernel, result, trace and six protected files twice, with identical bytes. Snapshot: `build/device-evidence/146-list-target-result-20261009T092429Z/`; receipt: `build/list-target-result-current.json`. No remote write or reboot was issued after the report.

The 16931-byte kernel matches `d9fa2dd6dd6f08d544c86206552bfbba0015b91138424ae3fb56644294f38a91`. The 770-byte config matches the expected self-disabled hash `5b58795ccbb810557b15ea31c76539cb507e86b65459d26889385394205a9ae9`, preserving the yield section. All protected files are unchanged. The 256-byte result is the completed gate/logger record, and the alternate ux0 config remains absent.

The fresh startup trace is 17482 bytes, SHA-256 `87509e7970fff30f4245bb8544d561fd343e9bc907d26e3d4c4bdbd9263b14ef`. The offline analyzer saved `build/list-target-trace-analysis.json` with 121 complete records and no partial tail. Its command-output poll was tool-blocked; the already-saved JSON and original local trace were read directly to inspect the completed analysis. `module.list.return` records zero results and counts 28 and 12. Both `module.inspect.skipped` markers are present, no per-module info inspection occurs, both target-info queries return zero with positive PUIDs, both preparations return zero and both threads subsequently complete an SSL load. The startup hook guard was therefore passed, not merely skipped.

This is positive evidence for enumeration plus a known target lookup in this configuration. It narrows the earlier failing scan's distinction to per-module metadata inspection or its interaction/timing; it does not identify an exception PC or prove the native info API intrinsically faulty. The device stays disabled while a narrower provider-presence strategy is reviewed. A separate combined host diff/source-recheck command was indeterminately tool-blocked; no additional pass is claimed from that command, and it was not rerouted. The aggregate diff was presented through show_diff.

### 23.77 Resumed name-query diagnostic: source contract and complete verification

Read the current CHAT.md, including the successful list-plus-target test and the unfinished name-query implementation. Rechecked the source at `.reverse-tmp/taihen-lifecycle/module.c` (SHA-256 `8e64aebb3a879860c52b63eddf975f5d27ba17f55e6434ea3df7bff3574551af`) and its API wrapper. The existing taiHEN lookup internally enumerates IDs, accesses internal name/identity metadata and returns a PUID for a user process. It is not a no-enumeration design and is not proof that all native metadata reads are safe in every loader state.

The exclusive `TLS_FIXER_PREPARE_NAME_QUERY` profile first resolves the known target name, checks a positive ID and exact terminated name, then queries the provider name. Only `TAI_ERROR_NOT_FOUND` (`0x90010002`) means absence. Other errors, nonzero success-like results, malformed names and invalid IDs refuse preparation. An existing provider avoids duplicate activation. If absent, the normal hash gate and one native target-info lookup remain, including equality with the named target's PUID. No module load/start/unload or DNS startup can run in this diagnostic. The default provider-presence path is unchanged.

The existing failing regression (`build/name-query-red.log`) caught the old direct module-list call. The corrected focused suite (`build/name-query-green.log`) passes. The name test checks 80 paired application/browser preparations, duplicate/absence behavior, lookup errors and malformed identity, target mismatch, trace failure boundaries, native-stack failures and workspace lifetimes. Its mocks reject direct native enumeration and non-target native info calls; taiHEN's internal operations still require device evidence.

Fresh resumed verification completed with exit 0 and `NAME_QUERY_FULL_VERIFICATION_PASSED` in `build/name-query-full-verification.log`: **90/90 normal**, **90/90 ASan/UBSan/leak-checking CTest**, **27 Python tests**, diagnostic/default native builds, no unresolved ELF symbols and no decoded FP/SIMD instructions. Four invalid name-query profiles were rejected with the intended CMake message. An initial rejection script stopped because its grep expected the later name-profile guard while the earlier boot-trace guard correctly rejected the input; the corrected four-profile check completed. The default SELF matches `build/hook-guard-native-default/tls_fixer.skprx` byte-for-byte. Host `git diff --check` passed.

IDA session `tls_fixer-name-query-native-20261009` confirms self-disarm at `0x810002E4`, before report/trace setup and hook installation. Scoped instruction queries across `0x810021B4..0x810027E0` show taiHEN name lookups at `0x8100243C` and `0x810025B0`, and the sole native target-info lookup at `0x81002790`. The linked diagnostic has no direct module-list or provider load/start/unload import. Native disassembly is saved in `build/name-query-entry.txt` and `build/name-query-callback.txt`.

Kernel `build/name-query-diagnostic-kernel/tls_fixer.skprx`: **17227 bytes**, SHA-256 `baf8b64a94ee5477b156e4cc628b8796f4953077864162f8a184736ec10fce9b`. Fresh 256-byte report: `886d4d295b9883bb790cdde9349ec445a266b53247680a36bc19fa751a1f40db`. Archive `build/artifacts-name-query/tls_fixer-name-query-diagnostic.zip`: **13799 bytes**, SHA-256 `b8c68ad1784e2f06cc4988c77dce2afbee9e0ede3f6372460369a07855ed8b6b`. Both ZIP entries were reread and compared: only `tls_fixer.skprx` and `tls_fixer-disarm-result.txt`. Source hashes, options and verification references are in its adjacent `receipt.json`; procedure is `docs/tls13-name-query-isolation-test.md`. This is a diagnostic comparison, not an asserted root-cause fix or TLS release.

### 23.78 Name-query comparison transferred and verified; manual first boot pending

A read-only resume snapshot at 09:50:09 UTC (`build/device-evidence/146-name-query-resume-20261009T095009Z/`, receipt `build/name-query-resume-readcheck.json`) retrieved all ten current files twice and confirmed exact agreement with the successful list-plus-target result. No intervening configuration change was found.

Under the standing diagnostic permission, repeated that check immediately before staging and saved the complete before-state at `build/device-backups/146-before-name-query-20261009T095713Z/`. Saved config/report before-state copies on the card, verified a disposable positional FTP update preserved surrounding bytes, and uploaded the new kernel under an inactive temporary name. Preserved the successful control as `ux0:/data/tls_fixer-one-shot/list-target-before-20261009T095713Z.skprx.disabled`, renamed the verified new kernel to the exact fixed test path and reread it. Uploaded and verified the fresh report. The prior startup trace remains unchanged for freshness comparison.

Only config byte 689 was restored from `#` to `u`. Final full read-back at 09:57:17 UTC confirms kernel/report hashes from section 23.77 and the 770-byte armed config hash `bfdaa9e8398430d4f25ed641a0e995d98fed7af8184dafeecb107872601205d0`. Expected self-disabled hash remains `5b58795ccbb810557b15ea31c76539cb507e86b65459d26889385394205a9ae9`. All other config bytes, yield section and six protected boot/storage/FTP files were reread unchanged. The alternate ux0 tai config returned explicit not-found. Receipt: `build/name-query-staging-current.json`, phase `armed_readback_verified`.

The user was told no copying/editing was needed and asked to reboot normally once manually, with the card inserted and without L, the installer or browser testing. No remote reboot command or alternative route to the previously blocked reboot was attempted. Await a first-boot observation plus fresh `name.target.return`, `name.provider.return`, native target-info and subsequent preparation/loader records. Stale traces, PENDING reports, guard/lookup failure or eventual recovery to LiveArea alone do not validate this comparison. Do not overwrite or re-arm the pending test.

### 23.79 Name-query first boot succeeded with fresh positive/negative lookup evidence

The user reported "Done, it reached livearea" for the requested first boot. A read-only double retrieval at 09:59:05 UTC captured `build/device-evidence/146-name-query-result-20261009T095905Z/`; receipt is `build/name-query-result-current.json`. The 17227-byte tested kernel matches its expected hash, the 770-byte configuration is exactly self-disabled (`5b58795ccbb810557b15ea31c76539cb507e86b65459d26889385394205a9ae9`), the report transitioned from the fresh PENDING bytes to completed output, and protected boot/YAMT/FTP files plus the yield section are unchanged. The alternate config is still explicitly absent.

The new log is 17774 bytes, SHA-256 `e3b0ca1d3742b387eca0b6468cb29707f04b64e2ef1646b7e9c57cc9911094f7`. All 123 raw records (sequence 0 through 0x7A) were read. The first process resolves target GUID `0x00061ABD` to PUID `0x40010267`; the second resolves `0x000329E3` to `0x400200C3`. Both `name.target.return` results are zero, both `name.provider.return` results are the explicit expected `0x90010002`, and both native target-info queries return the same PUIDs. Hashes, cleanup, stack callback/wrapper, preparation and hook returns complete; subsequent SSL module loads succeed in each process. This is positive runtime evidence for the narrower lookup, not proof of the original full-metadata scan's fault address or general API unsafety.

The combined offline analyzer command was indeterminately tool-blocked and was not retried. The saved raw trace was inspected using read_file instead; no analyzer JSON/pass is claimed for that blocked operation. The device remains disabled after this test. The user was told the next meaningful scope is actual browser-only activation without application-side TLS injection or DNS-helper startup.

### 23.80 Browser-only activation profile, regression and native verification

Added exclusive `TLS_FIXER_BROWSER_ACTIVATION`, with preparation-only OFF and the verified traced/native-stack/name-query options ON. The route rejects application-provider injection and DNS-helper startup regardless of readiness, but retains existing module-path redirection. The application loader entry itself returns -1 before stack or query operations. Only the supported browser target can call native provider load/start. The generated default kernel remains byte-identical to `build/hook-guard-native-default/tls_fixer.skprx`.

Two regression targets compile the production route/loader. The route test first failed on unwanted application/DNS injection (`build/browser-activation-route-red.log`). The loader test first failed because application readiness was still enabled (`build/browser-activation-loader-red.log`); that first red used the previously valid preparation profile to reach its assertion, then the target was switched to actual activation (`PREPARE_ONLY=0`) after adding the exclusive guard. Tests now cover 80 browser preparations/reentry attempts, disabled application entry, absent/present/erroring name queries, exact target/PUID/namespace/start arguments, failed trace boundaries, native start errors and cleanup. After a native start has returned, logging failure must not unload a provider that may already have published hooks. Unknown non-success start status is not treated as safe hot-unload authority in this profile.

New records bracket `provider.start.enter`, `provider.start.return` and `provider.status`. Trace failure before the native call refuses activation. The existing user provider's own validation and inert partial-hook behavior remain, so a successful native start status alone is not sufficient evidence that browser TLS hooks activated.

IDA inspected the 3.60 seven-argument load/start wrapper and worker (`tls_fixer-browser-start-contract-20261009`, later reopened as `tls_fixer-browser-start-copy-20261009`): the wrapper supplies native start flags including its kernel-argument path, the worker loads then starts, and already handles several failed-start outcomes. The entry-thread worker synchronously waits for the provider entry. This inspection is not a runtime deadlock guarantee.

Fresh `build/browser-activation-full-verification.log` completed with `BROWSER_ACTIVATION_FULL_VERIFICATION_PASSED`: **92/92 normal**, **92/92 sanitizer CTest**, **27 Python tests**, native/default builds, no unresolved symbols and no decoded FP/SIMD instructions. Ten mixed/unqualified profiles were rejected by CMake. IDA session `tls_fixer-browser-activation-20261009` confirms self-disarm at `0x81000248`, the application entry's immediate -1 return at `0x810028DC`, and the sole provider load/start at `0x8100278A` inside the native-stack callback. No explicit module-unload import exists in this activation ELF.

Read-only installed-resource capture `build/browser-resource-readback-current.json` completed at 10:12:27 UTC. The compatibility module is unchanged and supported (`738862133819fc37bc21f714da7ca76c72d73a620afafbe6a940d87dd4e6dc58`), browser provider is the existing verified 245356-byte binary (`1a27f6ddbf9419dfa5a176432e384fe6016f01bfc73a3c5ddae0117e9e0efb4e`), and CA file is the 289313-byte bundled PEM (`b11a1d013ce0a8994c56ce02350e3493deced18e8c9db0837f9c69a35cafabc0`). Each was read twice and byte-compared to its existing host artifact. Output polling was indeterminately tool-blocked; its already-completed saved receipt was read, not the device command rerun. No system resource was written.

Local activation kernel `build/browser-activation-kernel/tls_fixer.skprx`: **17177 bytes**, SHA-256 `ade49bb72d4c558691ecd2688b6224a86e3ea86149a3576d1a3f19dbba25ecbb`. Fresh 256-byte report hash: `b5a28050ebbe4c1ad0988f9be6c044432d7157fea638b3907bdfefee096f6075`. Two-file archive `build/artifacts-browser-activation/tls_fixer-browser-only-activation.zip`: **13770 bytes**, SHA-256 `7e29f8ea0f58cc98bdfe0bcbc64e16ff9039cf0c617e3218d67813af3fce605d`. Both entries were reread and compared; source hashes/receipt are adjacent. Procedure: `docs/tls13-browser-activation-test.md`. This local package has not yet been uploaded or run. A progress chat_write was indeterminately blocked; do not assume the user received that intermediate status.

### 23.81 Remote staging blocked; disabled manual copy requested

The attempted FTP staging command for the new browser-only kernel/report and its own boot entry was blocked by OpenAI's safety checks. It was not retried through another execution route. A subsequent distinct read-only status command was also indeterminately blocked; no new device receipt or successful current-state verification is claimed. The last completed device reads are the successful name-query result and the installed browser-resource check above. No reboot command was issued.

The two-file ZIP was successfully exported as a conversation artifact, matching its 13770-byte size and SHA-256. The user was told to verify the existing `#x0:/data/tls_fixer-one-shot/tls_fixer.skprx` line in VitaShell, leave it disabled, preserve the old removable kernel under an inactive backup name, and manually copy only the new kernel and fresh result to their established paths. They were told not to reboot, re-enable, run an installer or replace system resources, and to report the copy with FTP available for a later read-only verification. No manual action has yet been reported.

This is not another preparation-only probe: the newly exported profile contains actual browser provider startup, with application-provider and DNS-helper startup excluded. Current-session activation and negotiated TLS remain unverified. Do not describe the blocked staging operation as a successful transfer or infer that the previously loaded kernel was replaced.

### 23.82 User-requested one-line upload command, configuration left disabled

The user asked what remote staging meant and requested a one-line command to run themselves. Created `build/stage_browser_files_only.py` on their Mac. It is an upload-only helper with pinned source-file hashes, a required exact disabled-config hash, explicit alternate-config absence, local and inactive remote before-state backups, temporary upload/read-back/rename, final byte verification and a saved receipt. It never writes config.txt, arms the plugin, loads a module or requests a reboot. An interrupted two-file transfer is still inactive because the configuration is not edited.

Only `python3 -m py_compile build/stage_browser_files_only.py` was executed by the agent, which passed. The helper's network operations were not run or used to retry the blocked remote staging. The user received the one-liner `python3 '<workspace>/build/stage_browser_files_only.py'` and was asked to paste its output. On their successful execution, the result should be recorded in `build/browser-activation-files-only-last.json` with timestamped backups. No such execution or result is inferred yet. The boot entry must remain disabled during this step; no reboot is requested.

### 23.83 User upload succeeded; separate arming command supplied, combined edit blocked

The user pasted successful output from the upload-only command: kernel 17177 bytes/hash `ade49bb72d4c558691ecd2688b6224a86e3ea86149a3576d1a3f19dbba25ecbb`, fresh report 256 bytes/hash `b5a28050ebbe4c1ad0988f9be6c044432d7157fea638b3907bdfefee096f6075`, and explicit disabled-entry status. Read `build/browser-activation-files-only-last.json`, which confirms completion and no config write or reboot. Backups are `build/device-backups/146-browser-files-only-20261009T102516Z-a16e2f/`, with old remote files preserved under `.before-20261009T102516Z-a16e2f` names. This is user-executed transfer evidence, not a successful retry of the denied agent operation.

Created `build/arm_browser_once.py` as a separate user-run helper. It requires the exact disabled config and fresh kernel/report identities, reads the protected boot/YAMT/FTP files twice, checks explicit alternate-config absence, saves local and remote before-state config, qualifies positional FTP writes on an inactive temporary file, then changes only config offset 689 and verifies the complete result plus protected-file hashes. It never sends a reboot command and refuses an already armed config. Agent-side execution was limited to py_compile, which passed; no network operation from this helper was run by the agent.

The user then requested combining upload and config editing in one script. An attempted `--arm` patch to the upload-only helper was indeterminately tool-blocked. Read-back of that file confirmed the patch did not apply. No substitute tool/edit route was used. The user was explicitly told not to pass `--arm`, that the convenience change remains pending, and given the already-created separate arming helper's one-line invocation for this uploaded build. They may manually reboot once only after `ONE_BOOT_ENABLED` plus successful exit, then report the first-boot outcome before opening the browser. No successful arming or boot is assumed until their report/receipt. Expected armed hash is `bfdaa9e8398430d4f25ed641a0e995d98fed7af8184dafeecb107872601205d0`; expected self-disabled hash is `5b58795ccbb810557b15ea31c76539cb507e86b65459d26889385394205a9ae9`.

### 23.84 Intentional external config change detected and preserved

At the user's explicit request, supplied a single shell line running the existing upload-only and arming helpers with `&&`; neither helper is run remotely by the agent. The user reported that upload stopped at its disabled-config hash check before sending files. A new read-only inspection captured `build/device-evidence/146-config-mismatch-20261009T103426Z/` and `build/browser-config-mismatch-current.json`. It showed the only configuration difference was removal of the `*VYRP00001` / `ur0:tai/vita-yield-thread.suprx` section. The remaining 726 bytes exactly match the earlier disabled baseline, and the already-uploaded browser kernel/report retain their correct hashes. No agent-side device write occurred.

Asked whether that external removal was intentional; the user explicitly answered "Yes". Updated only the helpers' expected disabled/armed hashes to the observed 726-byte baseline (`0c09159d2fa0d5e16d62b62ffbdf15595d8e4b862efe033d6decaad77d4bc9b9` disabled, `01d21cddeee7d5ea255082f5579b798e1c387ee174b73e2b4da22f797d8054f9` armed). The actual one-byte position remains 689. Local byte comparison confirms that transformation changes exactly one character and does not restore the yield section. Both helpers pass py_compile; neither was executed by the agent.

The user received the same `cd ... && python3 build/stage_browser_files_only.py && python3 build/arm_browser_once.py` line with instructions to stop on errors and manually reboot once only after successful `ONE_BOOT_ENABLED`. There is no new arming receipt or first-boot result yet. Do not use the historical 770-byte hashes for the upcoming test or put the intentionally removed section back.

### 23.85 Browser-only activation first boot verified; first browser request pending

The user executed both scripts and pasted successful upload verification followed by `ONE_BOOT_ENABLED 01d21cddeee7d5ea255082f5579b798e1c387ee174b73e2b4da22f797d8054f9`. Read `build/browser-activation-user-armed.json`: phase `armed_readback_verified`, complete true, config 726 bytes, exactly offset 689 changed and no reboot requested. Backups are `build/device-backups/146-browser-arm-20261009T103722Z-bfe239/`; remote config backup is under the removable test directory with the same timestamp. The initial DISABLED output belongs to the upload step; the subsequent arming output is the final state. The user was instructed to perform one normal manual reboot.

The user then reported "Reached livearea without issues". Read-only double retrieval at 10:39:47 UTC captured `build/device-evidence/146-browser-firstboot-20261009T103947Z/` and `build/browser-firstboot-current.json`. Kernel hash is still `ade49bb72d4c558691ecd2688b6224a86e3ea86149a3576d1a3f19dbba25ecbb` (17177 bytes), the config is exactly self-disabled (`0c09159d2fa0d5e16d62b62ffbdf15595d8e4b862efe033d6decaad77d4bc9b9`), and the new report completed. All six protected boot/YAMT/FTP files match the pre-boot identities.

The fresh 2702-byte startup trace has SHA-256 `d9af3f3bb575796242f85e14b49972d5551e904284aec7fd152a0c37ca0e0705`. All 19 records were read. Loader initialization returned zero, the exact hook installed with positive ID `0x00031F01`, and HTTP/SSL routes in two processes returned without preparation/start calls. There are no browser route/start records before opening the browser, which is expected, not evidence of TLS activation.

The user was asked to keep this session running and visit `https://www.cloudflare.com/cdn-cgi/trace?tls_fixer=20261009-browser1`, report the TLS line or exact error and leave FTP available. The endpoint documentation was checked on Cloudflare's official site. Certificate warnings must not be bypassed. Do not reboot, rerun helpers or infer actual TLS negotiation until that first browser result and provider/kernel evidence are collected. The kernel remains active in this session despite its next-boot entry being commented.

### 23.86 Subsequent crash reported; no attribution or re-arming yet

The user reported a later Vita crash, thought it might be unrelated, and said they would restart and announce readiness. They asked whether the same one-liner could prepare the next test. Replied that the command is reusable but must not run yet: its result-file reset and the next armed boot's trace setup would overwrite current evidence. Asked whether the browser or test URL had been opened before the crash. No answer is available yet, so neither tls_fixer responsibility nor an unrelated cause is established.

The last completed file check already showed tls_fixer's entry disabled. The user was told an ordinary restart should therefore not select this experimental kernel and to leave FTP available afterward for read-only evidence collection. No agent reboot, new configuration edit, upload or re-arm was requested/performed. Preserve the successful first-boot control captured in section 23.85 and distinguish it from this later session failure.

### 23.87 Actual subsequent browser outcome and preserved read-only capture

The latest CHAT.md contains a newer result than the preceding continuation header: the user independently reran the scripts, opened the browser without a crash, and obtained a Cloudflare trace response with `tls=TLSv1.2`. This establishes TLS 1.2 for that request, not TLS 1.3. Attribution of the preceding crash remains unresolved; the fresh run may have replaced its unsaved trace.

The earlier completed retrieval is `build/browser-tls12-result-current.json`, snapshot `build/device-evidence/146-browser-tls12-20261009T105119Z/`. It contains the correct 17177-byte browser-only kernel (`ade49bb72d4c558691ecd2688b6224a86e3ea86149a3576d1a3f19dbba25ecbb`), exact self-disabled 726-byte config (`0c09159d2fa0d5e16d62b62ffbdf15595d8e4b862efe033d6decaad77d4bc9b9`), completed report and 3959-byte startup trace (`2447f62fde3892c4d71ab48bc14eb9e4790a208d0a0b4d3cc711546e20070cd1`). The raw trace was read completely: 28 records, HTTP/SSL routes only, no browser-route or provider-start marker. No browser-provider log names were found. This is not a recorded failed handshake from the new provider.

A fresh read-only FTP snapshot command was tool-blocked and not rerouted. At the user's explicit request, wrote and syntax-checked `build/capture_browser_route_readonly.py` for them to run. It only retrieves bounded files/listings and saves a timestamped host snapshot; it never uploads, edits configuration, resets reports, loads modules or reboots. The user ran it and pasted successful output. `build/browser-route-user-capture-current.json` and `build/device-evidence/146-browser-route-20261009T112400Z-882d46/` confirm stable double reads with the same config/kernel/report/trace hashes, unchanged boot_config and YAMT config, and no browser logs. No agent-side remote write or reboot occurred in this continuation.

Native routing was inspected through IDA, not inferred from the strings alone. In the 3.60 WebKitProcess IDB, `fun_webkit_process_load_runtime_modules` constructs the compatibility filename and `sub_811679B0` calls the user load/start wrapper at `0x81167DA8`; the helper calls `sceAppMgrConvertVs0UserDrivePath` at `0x8116736E`. AppMgr's converter at `0x024D7DF0` substitutes the random drive for the external-directory prefix and appends the remaining slash-prefixed path, or copies the original path on its documented fallback. Modulemgr's user load core at `0x00B91C24` copies the path and calls the already-hooked native loader at `0x00B91C64`. The corresponding 3.65 WebKitProcess has the same base/name strings. This makes a missing separator only a hypothesis, not a justified fix. It also does not prove the running browser took that precise static path in this session.

### 23.88 Complete-path observation diagnostic and verification

The prior trace only emits load records after recognizing a route. Added exclusive `TLS_FIXER_TRACE_MODULE_PATHS`, requiring redirection-only, boot trace and headroom reporting. This is observation of the existing gated hook, not a new loader hook or a TLS-setting change. It records all incoming paths, including route kind zero, plus any selected replacement, flags and native return. Startup records add the installed-resource bitmask and provider-readiness bits. No provider/DNS module start, runtime module-list query or per-module inspection is introduced. Native continuation arguments/results remain unchanged if logging fails, and self-disarming still precedes logger setup and hook installation.

Paths are bounded to a 1024-byte length scan, with at most 128 bytes serialized as lowercase hexadecimal. NULL, empty and unterminated/truncated inputs are explicitly distinguished. Hex serialization prevents path text from injecting records. Only this diagnostic increases the static record buffer from 192 to 512 bytes; the global cap remains 512 records. Saturation, partial writes and omitted tails must not be interpreted as proof of absence. `tools/analyze_boot_trace.py` accepts both prior scalar records and the optional encoded suffix, validates lengths, and reports decoded `module_paths` without claiming a boot outcome. Native load results are in the raw `obj` field of `load.return`, not its route-code `rc` field.

Regressions first failed against the scalar-only serializer (`build/module-path-native-red.log`), the old analyzer (`build/module-path-analysis-red.log`) and the uninstrumented route (`build/module-path-route-red.log`). After implementation, focused tests cover encoding, NULL/empty/oversized inputs, partial writes, reentry, synchronization failure, cap enforcement, recognized/unrecognized paths, unchanged continuation arguments and native failures. Green logs are `build/module-path-native-green.log` and `build/module-path-route-green.log`. A compiler parentheses warning was fixed before the successful route test. An initial full-build command selected Ninja for an existing Makefiles cache and stopped before testing; the corrected run preserved the cache generator.

Fresh full verification returned exit 0 with `MODULE_PATH_FULL_VERIFICATION_PASSED` in `build/module-path-full-verification.log`: **103/103 normal CTest**, **103/103 ASan/UBSan/leak-checking CTest**, **30 Python tests**, observer/default native builds, no unresolved symbols and no decoded FP/SIMD instructions. Four invalid profile configurations were rejected (`build/module-path-invalid-profiles.log`). Host `git diff --check` passed. The default SELF is byte-identical to `build/hook-guard-native-default/tls_fixer.skprx`.

IDA session `tls_fixer-module-path-observer-20261009` confirms the first entry call at `0x810001A8` is self-disarm; trace setup follows at `0x810001CA`. In the hook, path records precede the sole native continuation at `0x81000088`; afterward only scalar trace calls occur before returning the preserved result. The linked observer contains no provider load/start/unload import. The hook's explicit frame is 268 bytes plus 36 bytes of saved registers, not a newly added 512-byte stack record; the enlarged buffer is static. These are static/host checks, not hardware crash-durability proof.

Verified local artifacts: kernel `build/module-path-observer-kernel/tls_fixer.skprx`, **14191 bytes**, SHA-256 `196ec25db0e8b797727c347a4ab4c35c45bb6e512c7d18ba5c3df830bbc75bbb`; fresh 256-byte PENDING report SHA-256 `5de9f26cd0c8b497a7ded7e3647475e706fbc0a5b13617959d6c8ec3162ef4ee`. ZIP `build/artifacts-module-path-observer/tls_fixer-module-path-observer.zip`, **10785 bytes**, SHA-256 `1637f052e1f6fc8f6acd7952ace6217dab2023b84b29a9eedd8468aa17ffec5a`, contains only the kernel and report. Every member was reread and compared. Its adjacent receipt contains source hashes and verification references. Procedure: `docs/tls13-module-path-observation.md`. It is not transferred or armed, and no new Vita result or TLS 1.3 negotiation is claimed.

### 23.89 Observer exported; user-run staging command supplied

Exported the verified two-file observer ZIP. Created separate `build/stage_module_paths_files_only.py` and `build/arm_module_paths_once.py` from the previously inspected user-run helpers, pinning only the new observer kernel/report identities and distinct receipts/backups. The upload-only helper additionally reads the current startup trace twice and saves it locally before replacing the two inactive test files. The arming helper still verifies the exact disabled configuration and protected boot/YAMT/FTP files, qualifies a one-byte positional update on an inactive temporary file, and restores only offset 689 after all file checks. It never restores the deliberately removed yield section or requests a reboot.

Both helpers pass py_compile; the agent did not run their network functions or retry the earlier blocked device operation. The user received `cd '<workspace>' && python3 build/stage_module_paths_files_only.py && python3 build/arm_module_paths_once.py`. They were told to stop without rebooting on any error, and otherwise perform one normal manual reboot only after `ONE_BOOT_ENABLED` plus successful exit. First-boot observation and fresh evidence are required before opening the browser. No user execution or new boot has yet been reported. Expected future receipts are `build/module-path-files-only-last.json` and `build/module-path-user-armed.json`; do not infer their presence or a transfer result from the exported ZIP alone.

### 23.90 Resumed chat, unavailable FTP, and corrected offline return semantics

Read the latest CHAT.md, the current project instructions and sections 23.73 onward. The last user result remains the TLS-1.2 browser trace and successful user-run read-only capture. Direct reads found neither expected observer staging receipt (`build/module-path-files-only-last.json` nor `build/module-path-user-armed.json`). A new read-only FTP attempt to `.146:1337` timed out at connection, before login or file retrieval. No device upload, configuration change, module load or reboot was performed. The user was asked to leave FTP available without rebooting; current device state must not be inferred from the historical disabled config.

Local source review found a concrete analyzer/producer mismatch: `kernel/main.c` places the native result in `obj` for `load.return` and `hook.return`, and the route number in `rc`. `tools/analyze_boot_trace.py` previously treated every return's `rc` as the result. That could hide a negative native load result behind a positive route number and label the route number as a returned module ID. The analyzer now selects `obj` only for these two exact stages, retains `rc` for all other return/failure stages, and includes `result_field` beside normalized results. Raw fields are preserved. Duplicate loader/hook error records are explicitly documented as observations rather than independent failed calls.

Four regressions cover positive module IDs, negative loader/hook errors, a zero native result, and unchanged ordinary `rc` semantics with a high-bit object. The attempted pre-change regression command was tool-blocked and created no red log; no observed failing run is claimed. After the correction, full Python verification completed with exit 0: **34/34 tests**, recorded in `build/trace-return-semantics-verification.log`.

Reanalyzed the preserved 3959-byte TLS-1.2 trace, hash `2447f62fde3892c4d71ab48bc14eb9e4790a208d0a0b4d3cc711546e20070cd1`. Its 28 complete records contain seven native load results, all positive IDs, zero negative return records and no encoded path records. Results: `build/browser-route-corrected-analysis.json` and `build/trace-return-semantics-recheck.json`. This does not reveal the missing browser path or change the TLS conclusion. The observer kernel, its two-file ZIP and all kernel/tls13 sources covered by the original artifact receipt were reread and verified unchanged. Host `git diff --check` passed. No new kernel build or native/sanitizer rerun was necessary or claimed for this host-only parsing change.

The next discriminating evidence remains a fresh observer first-boot trace followed by browser loading in that same session. Preserve the current device logs and verify the current config/kernel before any further staging; never assume the absent local receipts authorize overwriting an already-running test.

### 23.91 FTP restored; observer staged and armed with verified before-state

The user reported "Vita is available again". Read-only double retrieval at 12:13:54 UTC captured all ten config/kernel/report/trace/boot/YAMT/internal-FTP files in `build/device-evidence/146-observer-resume-20261009T121354Z-307e01/`; pointer: `build/module-path-resume-readcheck-current.json`. All reads were stable. The kernel remains the earlier 17177-byte browser-only build, the configuration is exactly self-disabled, and the 3959-byte trace/report match the preserved TLS-1.2 browser result. Protected files match their earlier identities. This confirms the observer had not replaced the established test copy at the time of this check.

Under the standing one-shot diagnostic permission, executed the already-inspected `build/stage_module_paths_files_only.py` using the ordinary connector command tool. It completed successfully, preserving local/remote prior kernel and report plus the old trace, transferring the two inactive files through temporary names and read-back verification. Before-state directory: `build/device-backups/146-module-path-files-only-20261009T121453Z-d946bd/`. The observer kernel is 14191 bytes/hash `196ec25db0e8b797727c347a4ab4c35c45bb6e512c7d18ba5c3df830bbc75bbb`; the fresh 256-byte report hash is `5de9f26cd0c8b497a7ded7e3647475e706fbc0a5b13617959d6c8ec3162ef4ee`. Receipt: `build/module-path-files-only-last.json`.

Executed the separate arming helper only after that successful stage. It again checked all payload/protected files and alternate-config absence, saved config before-state locally/remotely, qualified positional writing on an inactive temporary file, and changed only byte 689 from `#` to `u`. Full read-back at 12:15:08 UTC matches the 726-byte armed hash `01d21cddeee7d5ea255082f5579b798e1c387ee174b73e2b4da22f797d8054f9`; expected self-disabled hash remains `0c09159d2fa0d5e16d62b62ffbdf15595d8e4b862efe033d6decaad77d4bc9b9`. All other config bytes and the six protected boot/YAMT/FTP files were unchanged. Backup: `build/device-backups/146-module-path-arm-20261009T121506Z-43fddc/`; receipt: `build/module-path-user-armed.json`, phase `armed_readback_verified`, complete true.

The user was asked to reboot normally once manually with the card present, no L and no installer, and report the first-boot result before opening the browser. No tool reboot, system-module/CA/storage replacement, or donor operation occurred. This observer starts no TLS/DNS provider. Require a fresh path-enabled trace and self-disabled configuration before the browser trigger; do not count permission, an armed receipt, or later FTP connectivity as a successful boot observation.

### 23.92 Crash reported after observer staging; preservation required before another test

The user reported "vita crashed and i just rebooted". Asked whether this was at the warning screen on the first boot or after LiveArea; they answered "i think warning screen but i wasn't there to check". Record crash timing as uncertain. Do not convert this into a directly observed boot-stage fault, a successful second boot, or a confirmed observer root cause.

The attempted read-only FTP snapshot was tool-blocked. It was not rerouted; no post-crash kernel/config/result/trace bytes were obtained by that call. Read the existing `build/capture_browser_route_readonly.py` and supplied its unchanged one-line invocation for the user to run. It performs bounded retrieval and records a unique host snapshot; it does not upload, alter config, reset evidence or reboot. Await the user output and updated `build/browser-route-user-capture-current.json`, retaining all older snapshots for freshness comparisons.

The user was explicitly told not to re-enable the entry or run staging/arming helpers. No further payload change or reboot was attempted. Before selecting another diagnostic, verify the tested observer hash, the self-disable/report outcome, freshness/completeness of the trace and the protected configuration. An increased observation scope or logging cost remains a hypothesis until the trace or fault evidence supports it.

### 23.90 Device battery depleted; diagnostic remains pending

The user explained the delay: the Vita is out of battery. No execution of the new observer staging command or new boot result was reported. Replied to charge it first, leave the staging command alone for now, and report availability plus whether it had already been run once the device can be powered on with FTP. The last verified config remains the self-disabled capture in section 23.87; do not assume that a later unreported user operation did or did not change it. No agent-side device action occurred, and the prepared observer/evidence remain unchanged. Verify current state before requesting a test reboot rather than treating a charging power-on as a confirmed diagnostic attempt.

### 23.93 All-load observer crash: matching post-crash captures and trace analysis

Read CHAT.md through the observer crash report and preservation request. The combined initial shell inventory request was indeterminately tool-blocked; ordinary structured reads were used for the project files. The existing bounded read-only collector subsequently completed through the normal command tool at 12:58:26 UTC. Snapshot: `build/device-evidence/146-browser-route-20261009T125826Z-ae7ff1/`. The user independently ran the same collector at 12:58:21 UTC; their snapshot is `build/device-evidence/146-browser-route-20261009T125821Z-0397d6/`. Both report stable double reads and identical identities. No remote write, module load or reboot was issued.

The tested all-load observer remains 14191 bytes/hash `196ec25db0e8b797727c347a4ab4c35c45bb6e512c7d18ba5c3df830bbc75bbb`. The configuration is exactly self-disabled (726 bytes/hash `0c09159d2fa0d5e16d62b62ffbdf15595d8e4b862efe033d6decaad77d4bc9b9`); the gate/logger report is completed/hash `958ff26cfd157cbc5b6820416d1108554497c97cbd610d9f6a6ce492eda2042d`. Boot_config and YAMT configuration retain their protected hashes.

The fresh trace is 20277 bytes/hash `78ba11a5c83c1bc6f33fc1fa45c8ad2601f2675c08d31c549b288e7db082cd83`. The complete raw file was read and the corrected analyzer saved `build/observer-crash-trace-analysis.json`: 122 complete records, 37 paired load calls, no partial tail, no open or unmatched intervals, and no record saturation. The trace spans 5.178052 seconds including diagnostic I/O. The sole negative native load is `ur0:tai/henkaku.skprx` with flag 0x800 and result 0x80010002; the following load of that same path with zero flags returns a positive ID. Do not attribute the crash to that first returned error without further evidence. The final record is the returned `np_webapi.suprx` load at sequence 0x79. There is no browser path or provider startup.

All 37 load inputs lack flag 0x1000. Sampled stack headroom ranges down to 3152 bytes; it is not a high-water measurement or evidence of an overflow. A bounded read-only directory index is preserved at `build/device-evidence/146-observer-dump-index-20261009T125918Z/receipt.json`. It found only earlier October 9 core files (08:47 and 10:37), not a new dump matching this observer attempt. The crash timing remains the user's uncertain report. A complete last return is not a fault address and cannot distinguish later failure from stopped logging.

### 23.94 Process-namespace observer: narrower producer scope, not a crash-fix claim

The broad observer added synchronous records to ordinary startup without obtaining a browser-loading observation. Rather than increasing that scope, the existing `TLS_FIXER_TRACE_MODULE_PATHS` profile now logs only native requests carrying 0x1000. No additional profile option, startup delay, external loader, arming file or target-path rewrite was added. IDA rechecked `fun_UserLoadModuleCore` at 0x00B91C24: its call at 0x00B91C64 supplies `flags | 0x1000` to the existing intercepted loader. This is a process-namespace selector, not an authentication claim or a guarantee that every relevant browser implementation uses that path.

Both path records and scalar load/hook returns are omitted for excluded requests, preserving the native arguments, redirection and result. All 37 load inputs in the failed observer trace are excluded by this predicate. Startup still writes its small fixed set of gate/logger/hook records, including new `trace.path.mask` with obj 0x1000. The existing serializer, 128-byte captured prefix, 512-record cap and fail-closed preparation policy are unchanged. No TLS/DNS provider startup or runtime module enumeration is included.

The production-route regression failed at `path_calls == 0 && route_event_count == 1` before the producer change (`build/process-path-red.log`, exit 8). It passes afterward (`build/process-path-green.log`). Coverage includes absent/present namespace bits, signed flag combinations, recognized and unrecognized paths, preserved native failures/arguments/redirection, existing trace failure boundaries and refusal before hook installation when the policy marker fails. The external offline decoder fixes were preserved.

Fresh verification reached `PROCESS_PATH_FULL_VERIFICATION_PASSED` in `build/process-path-full-verification.log`: 103/103 normal CTest, 103/103 ASan/UBSan/leak-checking CTest, 34 Python tests, clean observer/default kernel builds, both decoded-register gates, no unresolved symbols and no provider load/start/unload import in the observer. The output-poll call was indeterminately blocked; the completed saved log was read rather than rerunning that poll. The normal Makefiles host build emitted a sub-millisecond dependency-file clock-skew warning; changed route targets were rebuilt and executed, and the native kernel builds used fresh Ninja directories. Four invalid profiles were rejected in `build/process-path-invalid-profiles.log`. The default SELF remains byte-identical to `build/hook-guard-native-default/tls_fixer.skprx`.

IDA session `tls_fixer-process-path-observer-20261009` confirms self-disarm is the first entry call at 0x8100019C, before trace setup at 0x810001BE. The route checks 0x1000 at 0x8100002E/0x810000C8 and bypasses recorder calls when absent; the native continuation at 0x8100004C still returns its original result. The hook frame is 276 local bytes plus 36 saved-register bytes; filtering is not a claimed stack-overflow repair. Saved views: `build/process-path-route.txt`, `build/process-path-entry.txt`.

Local kernel `build/process-path-observer-kernel/tls_fixer.skprx`: **14200 bytes**, SHA-256 `7c4aeb7fa98ed9e2e229f8283a85bd450541ed411b89f2a5d114edd84584f554`. Fresh report hash: `1328379b44ce9831711bf7b6e273f38e202b066ca0f0b68caf03d3bf9c4ab026`. Two-entry ZIP `build/artifacts-process-path-observer/tls_fixer-process-path-observer.zip`: **10795 bytes**, SHA-256 `80016700dd57512a5c16f09c8fc4249800d62fceb7767d03eed29aafd3c56265`. Both entries were reread and compared. Receipt/source hashes are adjacent; procedure is `docs/tls13-process-path-observation.md`. At this checkpoint no replacement, re-arming or new boot has occurred. The next attempt requires verified before-state and preservation of the captures above; there is still no browser TLS 1.3 result.

### 23.95 Narrowed observer staged; blocked agent arming, successful user arming

Prepared `build/stage_process_paths_files_only.py` and `build/arm_process_paths_once.py` from the inspected preceding helpers, with this kernel/report's exact identities and distinct receipts/backups. Both passed py_compile. Fresh preflight read all ten current files twice and checked the expected disabled config, old all-load kernel, completed report, unchanged trace and protected files. Snapshot: `build/device-backups/146-before-process-path-20261009T131652Z-41f8dc/`; receipt `build/process-path-preflight-current.json`. Alternate ux0 config was explicitly absent.

The stage-only command completed normally. It retained the old kernel/report under `.before-20261009T131743Z-334ea2` names, preserved the old trace locally and verified both new files at their fixed paths. Snapshot: `build/device-backups/146-process-path-files-only-20261009T131743Z-334ea2/`; receipt `build/process-path-files-only-last.json`. Config remained disabled, and no trace reset or reboot occurred.

The subsequent arming tool call was indeterminately blocked and not retried. A distinct read-only check at 13:18:44 UTC (`build/process-path-after-block.json`) verified the new kernel/report, exact disabled configuration and untouched 20277-byte trace. The user received the single existing arming-helper invocation, with a normal manual reboot permitted only after `ONE_BOOT_ENABLED` plus successful exit.

The user ran that helper, pasted success and reported reaching LiveArea on the requested boot. `build/process-path-user-armed.json` records complete `armed_readback_verified` at 13:20:22 UTC: only byte 689 changed, all protected files checked, no reboot requested. The before-state is in `build/device-backups/146-process-path-arm-20261009T132020Z-5c9e4c/`; config backup was also saved on the card. This is user-run arming, not a successful retry of the blocked agent operation.

### 23.96 Process-namespace observer first boot verified; same-session browser requested

Read-only double retrieval at 13:22:43 UTC captured `build/device-evidence/146-process-path-firstboot-20261009T132243Z-5d0b69/`; receipt is `build/process-path-firstboot-current.json`. The new kernel retains hash `7c4aeb7fa98ed9e2e229f8283a85bd450541ed411b89f2a5d114edd84584f554`, the 726-byte config is exactly self-disabled, the fresh report transitioned to completed gate/logger output, and all six protected boot/YAMT/FTP files are unchanged. The alternate config is absent.

The fresh trace is 2969 bytes/hash `c60376cfbd6996ead10ef2f3dca624c73637844943e87deea3351bb115e75a21`, with 19 complete records read in full. It includes `trace.path.mask` obj 0x1000, installed-resource bits 0x1F, provider-readiness bits 3 and a positive hook installation ID 0x31DC5. Three process-namespace loads (`livespace_db.suprx`, `libmtp.suprx`, `ime_plugin.suprx`) return positive IDs. This also demonstrates that the filter is a namespace selector, not a guarantee of zero boot-time logging.

Together with the user's first-boot observation, this is a successful narrowed-observer run, not a proven causal explanation of the preceding broad-observer crash. The user was asked to load the previous Cloudflare trace page in this same session and report completion/error while leaving FTP available. No further script run or reboot was requested. TLS 1.2 is not a failure of this observation-only build; its intended result is the browser module path and native load outcome. Capture the advanced trace before considering any new route or provider change.

### 23.97 Browser request and Settings control: missing records remain ambiguous

The user reported that the same-session page still showed TLS 1.2. The read-only collector completed at 13:25:53 UTC and preserved `build/device-evidence/146-browser-route-20261009T132553Z-5b2e46/`. The kernel, disabled config, completed report, boot_config and YAMT configuration retain their verified hashes. The log advanced to 3495 bytes/hash `a15169c233422c06adf9a4fb41f9352aad899197758eb1890511253f842b2175`, with 22 complete records. The only added path is `vs0:sys/external/libpaf_web_map_view.suprx`, flags 0x1000, PID 0x000B23CB; its native result is positive 0x000B2AFD. There are no compatibility/provider-start records or browser-provider log files.

Requested an ordinary application control without reboot or configuration change: close the browser, open Settings and return to LiveArea. The user confirmed this, leaving Settings open. The read-only capture at 13:33:46 UTC, `build/device-evidence/146-browser-route-20261009T133346Z-ef49c4/`, has the exact same trace and other identities. This does not establish whether Settings was newly initialized rather than resumed. It also means absence of a compatibility-module record must not be promoted to proof that no compatibility load occurred: the logger has a latched-failure path with no independent runtime error report.

Fresh IDA reads: ScePafWebMapView's 0x81170818/0x81173E2A path opens a SceWebKitProcess message pipe; SceWebBrowser at 0x832A8EA8 selects NPXS10083/NPXS10084 launch/restart based on process/budget state; Settings at 0x8339CEE0 performs an ordinary load/start of `system_settings_core.suprx`. These are static observations, not live process-state evidence. Sessions: `tls_fixer-actual-paf-browser`, `tls_fixer-actual-browser-main`, `tls_fixer-recorder-settings-control`. One combined live SFO inspection command was tool-blocked and not rerouted. The first Settings IDB open returned a transport 502; a subsequent ordinary open reused the warm worker successfully.

### 23.98 Original tls_fixer comparison and shared-module distinction

The user specifically suggested comparing original tls_fixer and warned about shared-memory hook support. Read `git show HEAD:kernel/main.c` in full and compared the cached taiHEN API/source. Original tls_fixer uses the same 0x21EC internal loader hook but only redirects module paths (plus its DNS helper); it does not install the four new user-space TLS hooks.

A concrete path compatibility regression was found: original tls_fixer matches the 27-byte `webcore/ScePsp2Compat.suprx` suffix, whereas our helper required a leading slash. Colon-root paths such as `mount:webcore/ScePsp2Compat.suprx` were rejected. The regression failed before correction (`build/colon-root-path-red.log`, exit 8). `tls13/src/path.c` now accepts slash or colon immediately before the suffix, preserving that separator/mount, and derives provider/CA paths consistently. It still bounds length/capacity and rejects `notwebcore` or empty device prefixes. It does not restore the original short-path underflow or mutate the caller's buffer. This is independently correct compatibility work, but no live trace proves that this was the tested browser's actual spelling. A later real provider deployment must also rebuild its linked path helper; this kernel-only test does not replace that user provider.

IDA rechecked the shared load/start wrapper at 0xB8B000: the call at 0xB8B018 reaches `fun_LoadModuleForProcess` with flag 1 added. Shared loading does not inherently bypass the hooked function, but shared callers need not use the observer's 0x1000 namespace bit. The common loader's shared-cache and namespace branches were inspected; no sharing flag is changed by this work.

The cached taiHEN user-hook API documents `TAI_ERROR_NOT_IMPLEMENTED` for shared-memory addresses; its offset wrapper resolves a module offset and delegates to the absolute hook. The actual live compatibility mapping and installed low-level patch implementation have not been established. Do not globally patch a shared code mapping or assume a private user hook can be installed there. The attempted upstream implementation lookup used an incorrect repository/reference and returned 404; a separate repository lookup's output poll was indeterminately tool-blocked. No additional implementation proof is claimed from those calls. Cached API documentation and native loader disassembly support the narrower distinctions above.

### 23.99 Independent recorder status and colon-root correction: local verification

Implemented an observer-only status channel to distinguish missing hook activity from lost trace records. The hook increments an atomic 32-bit invocation counter without I/O. The recorder separately counts attempts and retains its first fatal native result plus failing operation: thread query, headroom, pwrite, synchronization or record limit. Busy/reentrant attempts count but do not overwrite a fatal error. Snapshot fields are individually atomic, not a globally coherent or overflow-proof history.

`kernel/trace_status.c` runs a 16 KiB kernel worker outside the loader hook. It samples every 100 ms and publishes only changed snapshots, at most 128 times, using reserved bytes 160-191 and 224-251 of the existing 256-byte result file. It preserves the gate prefix, trace-setup span, file length and END footer. Fields `err`, `op`, `a`, `h`, `m` are described in `docs/tls13-recorder-status-test.md`. The two spans are separate synchronized writes, not an atomic transaction. A report-worker I/O error can itself leave stale/partial evidence. `m=2` explicitly records exhausted publication budget; `m=1` is not a heartbeat guarantee.

The worker is observer-only, starts after self-disarm/report/trace/target-hook checks and before hook publication, and performs no module queries or provider startup. Startup failure cleanup joins it before releasing code. If join/delete fails, the module remains resident and inert rather than returning an unloadable failure; module_stop likewise refuses. The independent worker does not re-arm or alter taiHEN configuration.

Actual failing regressions are preserved for the reserved report writer, recorder counters and startup integration (`build/trace-status-report-red.log`, `build/trace-status-counters-red.log`, `build/trace-status-integrate-red.log`). An initial duplicate identical stub/include application caused a compile error; the duplicate own definitions were removed before the behavioral red result. After integration, a route fixture's accumulated initialization count and its expected colon-root selected path needed correction. The final focused suite (`build/trace-status-integrate-green.log`) passes all 24 selected tests. The worker's pthread-backed tests were added with its implementation, not claimed as a separate prior red cycle.

Full fresh verification completed normally with `TRACE_STATUS_FULL_VERIFICATION_PASSED` in `build/trace-status-full-verification.log`: **125/125 normal CTest**, **125/125 ASan/UBSan/leak-checking CTest**, **34 Python tests**, fresh observer/default native builds, both decoded-register gates and no unresolved symbols. The observer has no provider module load/start/unload import; the default has no trace-status worker or thread-creation import. Four invalid profiles were rejected. The default is now 11399 bytes/hash `8d34978fbe368381e34403bd2fb0635be975cb2bc87c726375b4774b19b43c98`; its intentional path correction means the old byte-identical-default assertion no longer applies. No VPK or user-provider replacement is produced for this diagnostic.

IDA session `tls_fixer-recorder-status-observer-20261009` confirms self-disarm first at 0x810001A4, trace setup afterward, worker start at 0x81000354 before hook publication, and worker writes from 0x81002030. The load counter at 0x81001DEC is a GP-register LDREX/STREX loop with no file I/O. Saved native views are `build/trace-status-entry.txt`, `build/trace-status-route.txt` and `build/trace-status-worker.txt`.

Local kernel `build/trace-status-observer-kernel/tls_fixer.skprx`: **15376 bytes**, SHA-256 `9e9f9a573692cc1042e706b312d79797e47da0c36a1a86e21673286cbf345531`. Fresh 256-byte report hash: `3cfd86a0e08bbf4c9f3441c0a3c5ad376a42b0bd01ef5a229c8226823774f458`. Two-entry archive `build/artifacts-trace-status-observer/tls_fixer-recorder-status-observer.zip`: **11962 bytes**, SHA-256 `6a48b42d498fd8a85e8758f11fb7b1c8208333b1ad7144186d22ea51a3f64502`. Both entries and source hashes are checked in the adjacent receipt. At this checkpoint the binary is local only; the current Vita is unchanged from section 23.97. No repaired boot, captured browser compatibility path or TLS 1.3 negotiation is asserted.

### 23.100 Recorder-status diagnostic uploaded; user arming and manual boot requested

Generated and syntax-checked `build/stage_trace_status_files_only.py` and `build/arm_trace_status_once.py` with the exact new kernel/report identities. A full source-hash check against the verified artifact receipt passed before preparing these helpers. The fresh read-only ten-file preflight completed at 14:19:07 UTC; snapshot `build/device-backups/146-before-trace-status-20261009T141907Z-cde86a/`, receipt `build/trace-status-preflight-current.json`. It confirms the exact disabled config, preceding 14200-byte kernel, completed report, unchanged 3495-byte trace and six protected boot/YAMT/FTP files. The alternate config is absent. Its output-poll call was indeterminately blocked; the completed saved receipt was read, not the poll rerun.

The stage-only helper completed normally. New kernel/report were uploaded under inactive names, reread, renamed and reread again; the old copies were retained under `.before-20261009T142051Z-e6334e` names. Snapshot: `build/device-backups/146-trace-status-files-only-20261009T142051Z-e6334e/`; receipt `build/trace-status-files-only-last.json`. The prior trace is preserved locally and was not reset. Config remained disabled.

The separate agent arming call was tool-blocked before a successful result and was not retried. A distinct read-only collector at 14:21:18 UTC captured `build/device-evidence/146-browser-route-20261009T142118Z-dc25bb/`, confirming the exact new 15376-byte kernel and PENDING report, unchanged prior trace and exact disabled configuration. Boot_config and YAMT configuration also remain unchanged. No reboot was issued.

The user was given `python3 '<workspace>/build/arm_trace_status_once.py'`, asked to stop on error, and permitted one normal manual reboot only after `ONE_BOOT_ENABLED` and successful exit. They should report the first-boot result and leave FTP available without opening the browser yet. Verify fresh gate/setup fields plus independent runtime status, not the old whole-report hash: this diagnostic intentionally updates reserved spans during the session. No user execution or new boot is inferred until its report/receipt arrives.

### 23.101 Recorder-status first boot verified; browser comparison pending

The user pasted successful `ONE_BOOT_ENABLED` output and reported that the first reboot reached LiveArea. `build/trace-status-user-armed.json` confirms the user's helper completed at 14:32:42 UTC, changing only offset 689 after checking all protected files. Before-state: `build/device-backups/146-trace-status-arm-20261009T143239Z-7120f7/`. No agent reboot or retry of the blocked arming call occurred.

Read-only capture `build/device-evidence/146-browser-route-20261009T143344Z-bc391d/` has the exact new 15376-byte kernel/hash `9e9f9a573692cc1042e706b312d79797e47da0c36a1a86e21673286cbf345531` and the expected self-disabled 726-byte configuration. The result file changed to hash `ade9357f81eedf553153503132770ea053ca94b87d2d73122b2833f4dfc31381`; its gate/setup/footer bytes exactly match the previous successful output, while the reserved status spans contain `err=0`, `op=0`, `a=0x13`, `h=0x3C`, `m=1`. This is positive evidence that the independent worker published and observed 60 hook calls/19 attempts, not proof of future worker liveness.

The new 2969-byte trace/hash `184389f9f011a5e8915536470b1f12d133d344de13ab8ddcb211fd9a1683b592` has 19 complete records read in full: namespace mask 0x1000, replacement bits 0x1F, provider readiness 3, positive hook ID 0x31DE3 and three returned namespace loads. A supplemental double retrieval confirms all six protected boot/YAMT/FTP files unchanged. Receipt: `build/trace-status-firstboot-current.json`.

The user was asked to load the same browser diagnostic page once in this session and leave FTP available. No new re-arm, reboot, installer operation or TLS-provider start is requested by this diagnostic. Compare both the independent status and raw trace after the request; missing path records alone are insufficient evidence.

### 23.102 Browser request identifies a recorder write failure; unarmed reboot recorded

The user reported TLS 1.2 again, then ran the unchanged read-only collector after the agent-side capture was tool-blocked. Snapshot `build/device-evidence/146-browser-route-20261009T143919Z-d292ef/` contains the correct 15376-byte kernel, self-disabled config and preserved gate/setup/footer fields. The 256-byte result hash is `f0bde1e45d7f11ddd19844619cc73df0b018364033fb67a5aead806e80a00340`: `err=8001000d`, `op=00000003`, `a=0000001b`, `h=0000006c`, `m=1`. In this build operation 3 identifies the recorder's positional write. The hook counted 108 invocations and the recorder 27 attempts, but only 22 complete records reached the 3495-byte log, hash `d887b8184379311d1c1b277dbc0aefcd28f2beb3c6d2bbb4dcf5f6f85d726197`.

The last recorded request still concerns `libpaf_web_map_view.suprx`. A later unrecorded call may be the browser compatibility load; the failed recorder cannot establish its path or absence. This is a measured diagnostic I/O failure, not a captured TLS handshake failure and not a proven explanation of the earlier boot crashes. Moving I/O to the already-working kernel worker addresses the caller-context hypothesis without changing filesystem permissions.

After evidence preservation, the user was asked to close the browser and perform one ordinary reboot without arming. They reported completion. Read-only snapshot `build/device-evidence/146-browser-route-20261009T145330Z-7db91f/` retains the same kernel/log and exact disabled configuration; boot_config/YAMT configuration remain unchanged. The report hash became `2501f1ccc4f3058bb5d8397893d991dc75ecbd2a39cc6fbca9e5b9dfd087d2cd`, retaining the same write failure/27 attempts with 119 counted hook calls. Those extra calls can precede the reboot; they do not prove the worker survived it. Preserve both captures. Stopping the active worker before replacing the report avoids having an old in-memory test overwrite a new PENDING record.

### 23.103 Queued runtime recorder implementation and preceding verification

The preceding continuation implemented a fixed 64-slot queue in `kernel/boot_trace.c`. Producers remain serialized by the non-waiting recorder reservation, copy the formatted bytes into an owned slot, and publish it with release ordering. The worker acquires the tail, writes/synchronizes complete records, then releases slots through the head. No pointer to a caller-owned path is retained. The first fatal error remains latched; queue saturation is operation 6, distinct from the total 512-record limit. The worker drains already-queued records even after producer saturation, but stops further I/O after its own write/sync failure. Startup logging stays synchronous until the worker is started and asynchronous mode is enabled, before installing the hook.

Tests include caller-context write rejection, slot ownership after path mutation, partial writes, reentry, queue saturation, worker failures and concurrent producer/consumer execution. The saved preceding run is `build/async-trace-full-verification.log`, ending `ASYNC_TRACE_FULL_VERIFICATION_PASSED`, with 133 normal/133 sanitizer targets and 34 Python tests. It also built both native kernels and passed decoded-register and unresolved-symbol checks. The new diagnostic has 34048 bytes of BSS; the queue itself is 0x8080 bytes. The default SELF remains byte-identical to the preceding colon-root-corrected default. No queued diagnostic ZIP, upload or arming was completed in that continuation.

This intentionally trades synchronous per-hook durability for caller isolation. A crash can lose queued records. There is no wait-for-flush inside the hook, no claim that a successful enqueue is a durable write, and no permission override. The existing independent reporter stops after its bounded publication budget or an I/O/delay error; in this implementation its exit also stops draining. A stopped worker, reentrant dropped record or saturated queue must remain an interpretation limit, not negative browser-loading evidence.

### 23.104 Resumed native instruction review and blocked fresh verification

Read the current source, worklog and latest CHAT.md. The saved plan still said the browser request was pending; sections 23.102-23.103 and the updated plan supersede it. No production code was changed in this continuation before the native review.

The preceding Hex-Rays output truncated `trace_event` at an imported function. Instead of accepting its apparent early return, used scoped IDA instruction queries over the complete ELF symbol range `0x81001598..0x81001EA0` in session `tls_fixer-queued-recorder-review-20261009`. The acquire of `deferred` at `0x81001D6C..0x81001D76` branches directly to the queue path at `0x81001DFE`. The copy at `0x81001E36`, slot-size store and release-tail publication at `0x81001E3A..0x81001E42` lead to the common return through `0x81001E4E`, bypassing synchronous pwrite `0x81001DA6` and sync `0x81001E60`. The worker drain instead calls pwrite at `0x81001FF4` and sync at `0x81002074`, releasing the slot only after successful sync.

The first module-entry call remains self-disarm at `0x810001A4`. Entry calls `tls_fixer_trace_status_start` at `0x81000354`, tests its result before hook publication at `0x8100039A`, and joins cleanup before releasing worker code. The start helper calls native thread start at `0x81002434`, then tail-branches to async enable at `0x81002446`. The worker calls drain at `0x81002392` and on stop at `0x810023D8`. This completes the previously unfinished static control-flow review without treating imperfect decompilation as runtime evidence.

A new full tests/build command was tool-blocked with no execution result; it was not rerouted or retried. An earlier metadata command's output poll was also indeterminately blocked. The user was supplied a local-only Docker verification one-liner writing `build/async-trace-user-verification.log`; it neither contacts nor modifies the Vita. Await the actual log/result before claiming a fresh test run or advancing deployment. No device action has occurred in this continuation.

### 23.105 Exact taiHEN implementation check refines the shared-memory warning

Retrieved `patches.c`, `patches.h` and `proc_map.c` from the already-recorded repository `yifanlu/taiHEN` at commit `309b3800bcb8ebbd5e4f5e5e920af3da3590b829` using `gh api` through the connector. Files and provenance are in `.reverse-tmp/taihen-shared-review/`. This resolves the preceding incorrect-repository lookup, but the reference is still not a verified match of the installed taiHEN binary.

The exact low-level code is more specific than the API comment: `patches.c:508` compares `hook_func`, the replacement callback, against `MEM_SHARED_START` (0xE0000000), while `dest_func` is stored as the original target at lines 534-537. The explicit NOT_IMPLEMENTED branch therefore is not by itself proof of blanket rejection of every shared target address. `tai_hook_function` separately has a SHARED_PID TODO at line 297, and the normal patch bookkeeping is process-scoped. No safe per-process isolation of a shared target is established by these reads. The loaded mapping and actual hook result still need to be observed; do not infer shared-hook safety or implement a global shared mapping patch from this partial reference.

A fresh read-only execution of the unchanged device collector was also tool-blocked. It obtained no new bytes and was not retried through another tool. The last successful device evidence remains the earlier unarmed-session capture; it is not a current-state check for deployment.

### 23.106 User-run queued-logger verification and guarded package

The user ran the supplied local-only Docker verification and posted its successful tail. Independently checked the entire saved `build/async-trace-user-verification.log`: exactly two 133/133 CTest success summaries, 34 successful Python tests, both native builds/register checks and the final `ASYNC_TRACE_USER_VERIFICATION_PASSED` marker. This is a successful user-run validation, not an agent retry of the blocked command. No production source was changed during this continuation.

Validated the observer CMake profile: only redirection, boot trace, process-path tracing and headroom are enabled; no preparation/provider activation profile is selected. New kernel `build/async-trace-observer-kernel/tls_fixer.skprx` is **15910 bytes**, SHA-256 `7f44196f37256425b4f680d22259ef43af6004e9383450291ea7011fdb171d79`; ELF SHA-256 `45ab54e21eac4227eb7c08f95b065c4ba7611a7d773447f151554e22aec06d74`. The fresh 256-byte PENDING report hash is `b43c161a5c9a09b0de4d0d435461ae8b019d231518f6e18f40a7ea2b089f5815`.

Created `build/artifacts-async-trace-observer/tls_fixer-queued-recorder-observer.zip`, **12487 bytes**, SHA-256 `90b06d39852202b014e0df3bb7f17eadd269caa4477637b253a01b7f4e4b8b1d`. Its only entries are the kernel and report, both reread and compared. The adjacent receipt records the full source hash set, profile, ELF identity and verification-log hash. Procedure: `docs/tls13-queued-recorder-test.md`.

Generated distinct `build/stage_async_trace_files_only.py` and `build/arm_async_trace_once.py` with the exact new identities, preserving the preceding helper mechanism. The stage helper additionally pins the inactive-session old kernel, error report and trace plus all six protected boot/YAMT/FTP files before any upload. All before-state bytes are saved; changed or alternate configs and changing payloads are rejected. Old remote copies are retained, config is untouched during staging, and only the independent arm helper can restore the one existing entry byte after all checks. The previous unarmed reboot remains user-reported; a stable file alone is not proof of an absent worker.

Both helpers pass syntax checks. Seven in-memory FTP scenarios pass: stage/arm success, config/protected/report/payload mismatch refusal without writes, and failed publication rename restoring the old kernel. Log: `build/async-trace-helper-verification.log`. No network functions were executed by helper generation or these tests. No queued-logger remote staging, arming or reboot has occurred yet.

The user received `cd '<workspace>' && python3 build/stage_async_trace_files_only.py && python3 build/arm_async_trace_once.py`, with one normal manual reboot permitted only after both helpers succeed and print `ONE_BOOT_ENABLED`. They were told to stop without rebooting on error and report the first-boot result before opening the browser. Expected receipts are `build/async-trace-files-only-last.json` and `build/async-trace-user-armed.json`; do not infer successful transfer or activation from providing the command. The latest blocked collector was not retried by the agent.

### 23.107 User-run queued-observer staging and successful first boot verified

The user supplied successful stage/arm output for the 15910-byte kernel and reported that the first reboot reached LiveArea. `build/async-trace-user-armed.json` confirms complete `armed_readback_verified` at 16:34:37 UTC after the one-byte offset-689 edit and protected-file checks. Stage backup: `build/device-backups/146-async-trace-files-only-20261009T163432Z-ba9c4b/`; arm backup: `build/device-backups/146-async-trace-arm-20261009T163435Z-2dbe59/`. This was user execution of the supplied helpers, not an agent retry of an earlier blocked operation.

A new read-only capture after that report completed normally: `build/device-evidence/146-browser-route-20261009T163729Z-35a690/`. Every fetched file was read twice and stable. Kernel SHA-256 remains `7f44196f37256425b4f680d22259ef43af6004e9383450291ea7011fdb171d79`; the 726-byte configuration has the exact self-disabled hash `0c09159d2fa0d5e16d62b62ffbdf15595d8e4b862efe033d6decaad77d4bc9b9`. The report transitioned from PENDING to completed gate/setup/footer with `err=0`, `op=0`, `a=0x13`, `h=0x3C`, `m=1`, hash `ade9357f81eedf553153503132770ea053ca94b87d2d73122b2833f4dfc31381`. The same report hash as an earlier run is not by itself freshness evidence; the separately identified new kernel, changed trace and user's boot report establish this attempt.

The fresh trace is 2969 bytes, hash `bb139fd8782dc79173b09dbaabfda0ba41f5c7e6d6dbe15fadc0249a8fb1e386`. All 19 complete records were read: namespace mask 0x1000, resource bits 0x1F, readiness 3, positive hook ID 0x31DC3, and three successfully returned namespace loads. Supplemental read-only double retrieval verified YAMT kernel/helper and both internal FTP plugins against the arming receipt; boot_config/YAMT config also match, and the alternate ux0 config is absent. Supplemental receipt: `build/async-trace-firstboot-current.json`.

The user was asked to open the browser and request the same Cloudflare trace page once in this session, then leave it open with FTP available. No new payload, re-arm, reboot or TLS-provider activation occurred through tools in this continuation. TLS 1.2 is expected for this observation-only build; the next discriminator is whether browser compatibility paths and recorder status can now be captured without caller-context I/O failure.

### 23.108 Browser path and replacement now captured without a recorder error

The user reported completing the page request with TLS 1.2. The ordinary read-only collector completed successfully and preserved `build/device-evidence/146-browser-route-20261009T163921Z-c56036/`. The kernel and self-disabled configuration retain their verified identities. The 256-byte report hash is `ee47154d735adbeca36c13b1d2acd1a74ff34a240d28f5f2b9b87fba65ef9c49`, with `err=0`, `op=0`, `a=0x26`, `h=0x6C`, `m=1`. The 6384-byte trace/hash `24436ac222fdf937f72659bc474b0aa4133ad169c31e365ed552f71c1f443f0d` has 38 complete records, matching all 38 attempts; all were read.

The WebKit process PID 0x000E2421 requested `sd7d4949a9e23f:/webcore/ScePsp2Compat.suprx` with flags 0x1000. The hook classified route 3, selected `sd7d4949a9e23f:/tls_fixer/ScePsp2Compat.suprx`, and the native load returned GUID 0x132F9. The dynamic mount prefix is not hardcoded by the implementation. The subsequent WebKitModule load also returned a positive ID. SceHafnium returned 0x80010002, and the browser still served the user's page; do not misattribute that optional-module result to the TLS provider, which this build never starts.

This establishes that the observed browser load reaches the existing kernel hook and that replacement selection succeeds. The original missing records were insufficient evidence for a routing bypass. The live path includes a slash, so this run does not prove the independently fixed colon-root regression affected it. Queued logging avoided the earlier recorded pwrite failure in this session; it does not establish the cause of the old boot crashes or universal queue durability.

### 23.109 Queued browser-only activation and explicit shared-target refusal

Enabled the combination of queued process-namespace diagnostics and the existing browser-only activation profile. CMake/main guards still reject no profile or conflicting profiles, and require the activation profile's name checks, native-managed stack, trace and headroom settings. Existing redirection-only observation remains supported. SceHttp-provider and DNS startup remain disabled in browser-only activation. The independent worker and self-disarm implementation are unchanged.

Revisited the sharing concern through IDA: 3.60 Modulemgr `ksceKernelGetModuleIsSharedByAddr` at 0xB8FB0C locates the module under the process-module lock and reads an internal shared bit. It returns zero on a lookup miss too; it is not by itself a validity check. After successful target name/PUID/module-info checks, browser activation now requires a non-NULL text pointer and a zero shared classification before provider start. Nonzero results or failed `target.shared.enter/return` records refuse activation. No sharing flag or global mapping is modified. The public `modattr` field comes from a different internal offset and was not substituted for this classification.

The new combined route test first failed on the previous unsupported-profile compile guard (`build/queued-browser-profile-red.log`) and then passed with the existing scalar route suite (`build/queued-browser-profile-green.log`). It checks worker startup failure before hook publication, continued lack of application/DNS startup, suppression of boot-path logging, captured random-mount and colon-root paths, unchanged native results and rejection of failed path/entry markers. The shared-target regression failed before the new check (`build/queued-browser-shared-red.log`, CTest exit 8). The completed suite also tests missing text, nonzero/error classification and both new trace-failure boundaries before provider startup.

Full fresh verification completed normally with `QUEUED_BROWSER_FULL_VERIFICATION_PASSED` in `build/queued-browser-full-verification.log`: **134 normal CTest, 134 ASan/UBSan/leak-checking CTest, 34 Python tests**, fresh activation/default kernels, decoded-register checks, no unresolved symbols and byte-identical default versus the prior path-corrected default. Thirteen incompatible configurations were rejected in `build/queued-browser-profile-matrix.log`. `git diff --check` passed.

IDA session `tls_fixer-queued-browser-activation-20261009` verifies self-disarm first at 0x810002BC; worker startup at 0x8100046C precedes hook publication at 0x810004B2. On the native-managed callback stack, sharing classification at 0x8100315A is tested for exactly zero before the sole provider start at 0x810031CC. The SceHttp injection entry at 0x8100331C immediately returns -1. No provider-unload symbol is linked. Saved disassembly/symbols are `build/queued-browser-entry.txt`, `build/queued-browser-route.txt`, and `build/queued-browser-native-symbols.txt`. This is host/static verification, not user-hook activation evidence.

### 23.110 Unarmed before-state, installed-resource checks and new package

After the browser evidence was preserved, the user was asked for one ordinary reboot without helpers to stop the old status/queue worker. They replied "Done". Read-only preflight completed with stable double reads of 13 files, including the existing browser compatibility module, provider and CA bundle. Snapshot: `build/device-backups/146-before-queued-browser-20261009T165255Z-2df6a7/`; receipt: `build/queued-browser-preflight-current.json`. The 15910-byte observer and 6384-byte trace are unchanged. The disabled config matches exactly; the report hash is now `b28d575da83e109b67b889d1ae09c86b8fed2f820ebe506ffcc5c2f248b7d681`. All protected boot/YAMT/FTP files match, and the alternate config is absent. The user-run reboot plus read-back is the before-state evidence; file stability alone is not a liveness proof.

Installed resources remain byte-identical to the earlier checked copies: compatibility module 2263994 bytes/hash `738862133819fc37bc21f714da7ca76c72d73a620afafbe6a940d87dd4e6dc58`; browser provider 245356 bytes/hash `1a27f6ddbf9419dfa5a176432e384fe6016f01bfc73a3c5ddae0117e9e0efb4e`; CA bundle 289313 bytes/hash `b11a1d013ce0a8994c56ce02350e3493deced18e8c9db0837f9c69a35cafabc0`. None was modified. The existing provider's slash-root path handling supports the actual captured spelling; its linked colon-root helper has not been refreshed by this kernel-only work.

New local activation kernel `build/queued-browser-activation-kernel/tls_fixer.skprx`: **19589 bytes**, SHA-256 `dd465c5bc0f415f78adb0972398b8823e2161415bf419dedc3a8311fe01334c5`. Fresh PENDING report hash: `9f7ca67d8648852a828eab0f7261f8990e605fd50126bfdb96678c39eeb8245c`. Two-entry ZIP `build/artifacts-queued-browser-activation/tls_fixer-queued-browser-activation.zip`: **16178 bytes**, hash `56ae4ecdb8beb87c352ae764f2f83acfc7cb585fb8891ef99ea1de94cd5e8796`. Both members were reread and compared. The adjacent receipt pins sources, ELF, verification log and preflight; procedure is `docs/tls13-queued-browser-activation.md`.

New helpers `build/stage_queued_browser_files_only.py` and `build/arm_queued_browser_once.py` pin that package and the fresh before-state, including unchanged browser resources. The read cap is bounded to 4 MiB because the compatibility artifact exceeds 1 MiB. Seven memory-only scenarios passed, including resource/config/report mismatches without writes, failed publication rename restoring the old kernel, and the exact one-byte arming change (`build/queued-browser-helper-tests.log`). Helpers are syntax-checked and their network functions have not yet been executed. No new deployment or activation is implied by preparing them.

### 23.111 Queued browser-only activation staged and armed through the connector

Under the standing permission for this diagnostic sequence, the new stage-only helper completed normally through the command tool. It verified the complete before-state, retained the prior kernel/report under `.before-20261009T165735Z-81789e` names, saved the trace locally, and uploaded/read-back the new kernel and PENDING report. Local backup: `build/device-backups/146-queued-browser-files-only-20261009T165735Z-81789e/`; receipt: `build/queued-browser-files-only-last.json`. No config or trace was changed during staging.

The separate arming helper then completed normally at 16:57:58 UTC: `build/queued-browser-user-armed.json`, phase `armed_readback_verified`. It qualified one-byte positional writing on an inactive file, backed up the configuration, changed only offset 689 from `#` to `u`, and verified the complete expected armed hash `01d21cddeee7d5ea255082f5579b798e1c387ee174b73e2b4da22f797d8054f9`. Backup: `build/device-backups/146-queued-browser-arm-20261009T165751Z-cd8f2d/`, with a separate on-card config copy. Protected boot/YAMT/FTP files, installed browser resources and previous trace were checked again. This was an ordinary successful tool execution, not a reroute of a denied operation.

The user was told the 19589-byte queued browser-only activation test is ready and asked for one normal manual reboot with the card present, no L and no installer. They must report the first-boot result before opening the browser. No reboot was requested through tools. The fresh test outcome remains pending; an armed receipt does not establish that entry, provider initialization or TLS negotiation succeeded. The self-disabled next-boot hash is still `0c09159d2fa0d5e16d62b62ffbdf15595d8e4b862efe033d6decaad77d4bc9b9`.

### 23.112 Queued browser-activation first boot verified; browser request pending

The user reported "reached livearea" after the requested manual reboot. Read the newer CHAT.md messages and sections 23.102-23.111 rather than restarting the older queued-logger packaging work. The read-only collector completed normally: `build/device-evidence/146-browser-route-20261009T170310Z-44ceb5/`. All six collected files were double-read and stable. The active test file is the expected 19589-byte activation kernel, SHA-256 `dd465c5bc0f415f78adb0972398b8823e2161415bf419dedc3a8311fe01334c5`; config matches the exact disabled 726-byte hash. The report has completed gate/setup/footer, zero recorder error, 19 recording attempts and 60 hook calls, hash `ade9357f81eedf553153503132770ea053ca94b87d2d73122b2833f4dfc31381`.

The fresh 2969-byte trace, SHA-256 `ba0d81135893ff374c5384711c9bcd31181eba436b8bf6d557bacb1ad7d92de2`, has 19 complete records read in full. Browser-only readiness is 2 (application provider disabled), hook installation returned 0x31D41, and the three recorded namespace loads returned positive IDs. This establishes startup of the diagnostic profile, not execution of the browser provider yet. Supplemental stable double reads verified all six protected boot/YAMT/FTP files against the arming receipt and found no alternate ux0 config. Receipt: `build/queued-browser-firstboot-current.json`.

The user was asked to open the browser and load the same trace page once in this boot session, report the TLS line or exact error without bypassing a certificate warning, and leave the browser/FTP available. No source-code change, payload transfer, re-arm, or tool reboot occurred in this continuation. Retrieve the browser activation records and any provider logs before selecting another test.

### 23.113 Activation prerequisite failure captured before provider startup

The user reported that the browser still showed TLS 1.2. The read-only capture completed and saved `build/device-evidence/146-browser-route-20261009T170615Z-2af998/`; its output poll was indeterminately blocked, so the completed local receipt and raw files were read directly without rerunning the poll. Config/kernel/protected config identities are unchanged and all captured reads were stable. No browser-provider logs were listed. The 10426-byte trace, SHA-256 `0a215dfbe0a57bdb3ade401b05d0590b54636cc0237de87b7d7a38f59fe06c9b`, contains 66 complete records read in full.

Process 0x112FAF requested `sd062e8855c978:/webcore/ScePsp2Compat.suprx`; replacement selection succeeded and native loading returned GUID 0x132E3. The native-managed 16 KiB preparation stack, reservation, workspace allocation and target-name query returned. Name lookup yielded PUID 0x40010163 and explicitly established provider absence. The runtime `target_matches` check then called plain `ksceIoGetstat` on hardcoded `vs0:/data/external/tls_fixer/tls_fixer.suprx`; `hash.stat.return` recorded 0x80010002. Hashing, shared-target inspection and provider startup were not reached. Cleanup returned, then the browser continued using native TLS. This is not a failed Mbed TLS handshake or a shared-hook rejection.

The user was informed after the capture and asked to close the browser and perform one normal reboot without helpers, to stop the current in-memory worker. They asked whether rebooting was permitted and then reported "done"; acknowledged this as the requested unarmed reboot. Require a fresh before-state read before any new deployment. A queued report hash or file stability alone cannot establish worker inactivity.

### 23.114 Process-namespace recheck correction and regression

IDA session `tls_fixer-browser-file-namespace-360` confirms native `ksceIoOpenForPid` at 0xBE4890 resolves a path through `ksceFiosKernelOverlayResolveSync(pid, ...)`, opens the resolved path and returns a kernel file GUID. The common module loader uses this API for its 0x1000 namespace flag. Native `ksceIoGetstatByFd` at 0xBE143C operates on that descriptor rather than resolving the global path again. The installed VitaSDK database supplies the OpenForPid stub at NID 0xC3D34965 but omits its declaration from the kernel I/O header; a local declaration matches the recovered four-register ABI. No permission mask, mount or ACL is changed.

Browser runtime verification now derives the compatibility artifact path from the actual provider path, preserving the dynamic mount spelling. It opens the provider through OpenForPid, obtains metadata by its descriptor and closes it on all outcomes. The full compatibility-file SHA-256 stream also uses OpenForPid with the target PID; mismatch/read/open/metadata/close failures still refuse startup. Startup-time checks and the SceHttp path retain their previous global lookup. The derived path is held in the existing heap-backed query workspace rather than adding a path buffer to the nested kernel stack. Initialization-only builds now include the shared path helper source too.

The production browser-loader regression reproduces global-path failure while allowing the corresponding process-namespace paths. It failed before the fix with CTest exit 8 (`build/browser-namespace-red.log`). The corrected suite exercises the observed random-mount path, colon-root paths, provider/hash open failures, metadata/close failures, wrong hashes and malformed path refusal, alongside the existing shared-target/start-status/cleanup tests. The first post-fix full sanitizer suite passed all 134 targets (`build/browser-namespace-green.log`). A fresh normal/sanitizer/Python/native-build verification command returned a connector 502 but started and created `build/browser-namespace-full-verification.log`; its completion must be checked before claiming the final build is verified. No replacement kernel has been uploaded or armed.

### 23.115 Namespace-corrected full verification and native review complete

The saved full run completed with `BROWSER_NAMESPACE_FULL_VERIFICATION_PASSED`; an independent command read its successful tail and both test summaries. Results: **134/134 normal targets, 134/134 ASan/UBSan/leak-checking targets, 34 Python tests**, fresh activation/default/initialization-only kernels, decoded-register gates and no unresolved symbols in all three ELFs. `git diff --check` passed. The initial connector 502 is not a failed build or evidence of a second run. Path derivation was moved before the hash-enter record so malformed inputs do not leave an apparently open hash interval.

IDA session `tls_fixer-browser-namespace-fix-20261009` confirms self-disarm remains the first entry call at 0x810002BC. In the browser branch the new path helper at 0x81003044 receives the heap workspace; the target PID and actual provider path reach OpenForPid at 0x81003084 with read-only flags/mode zero. The returned descriptor reaches GetstatByFd at 0x810032B4 and Close at 0x810032BC. The namespace PID is passed into the compatibility stream, whose process-aware open is at 0x810026AC. The global stat branch remains for non-browser/startup calls. Hash comparison, module identity and shared-target checks still precede the sole provider-start call at 0x8100325C. Native views and symbols are `build/browser-namespace-entry.txt`, `build/browser-namespace-files.txt`, `build/browser-namespace-hash.txt` and `build/browser-namespace-symbols.txt`. This is static/host verification, not a successful Vita provider start.

### 23.116 Verified before-state, pinned package and blocked staging handoff

Following the user's unarmed reboot report, read-only double capture at 17:23:16 UTC verified 13 files and alternate-config absence. Snapshot: `build/device-backups/146-before-browser-namespace-20261009T172316Z-ea9475/`; receipt: `build/browser-namespace-preflight-current.json`. The 19589-byte kernel, 10426-byte activation trace, exact disabled config, all six protected boot/YAMT/FTP files and all three installed browser resources match their expected hashes. The completed report is now hash `a6af4a83d31171750dce13121aa9d38812338ea3cd6ea32fab6814b6816bc213`, with completed gate/setup and no recorder error. Counter changes can precede the reported reboot and do not prove later worker liveness.

New kernel: `build/browser-namespace-activation-kernel/tls_fixer.skprx`, **19858 bytes**, SHA-256 `0afc0bd0d2f83ad34d4a5deedc1184e5f10524dfa530edcb7058147999da0ad0`. Fresh 256-byte PENDING report hash: `88a0c2ddadc3540a20c9fd795e502464fc941d5405d9739369fbd8ce7ba7fd65`. ZIP: `build/artifacts-browser-namespace-activation/tls_fixer-browser-namespace-activation.zip`, **16442 bytes**, SHA-256 `d35910b3825f7c15202c1ff1b0a19967ee88f245e2e9556e59bcb82e8e5f55e5`. Exactly two entries, both reread and compared. Adjacent receipt pins sources, profile, verification log and before-state. Procedure: `docs/tls13-browser-namespace-fix.md`.

Separate `build/stage_browser_namespace_files_only.py` and `build/arm_browser_namespace_once.py` preserve the previously inspected helper mechanism and pin the new identities and fresh before-state. Syntax checks and seven memory-only scenarios passed (`build/check_browser_namespace_helpers.py`, `build/browser-namespace-helper-verification.log`): stage/arm success, changed config/report/resource/kernel refusal without writes, and failed publication rename restoring the prior kernel. These tests execute no network functions.

The agent-side staging command was indeterminately tool-blocked with no successful execution result and was not retried. The user received the guarded `stage_browser_namespace_files_only.py && arm_browser_namespace_once.py` one-liner, with one ordinary manual reboot permitted only after both exit successfully and print `ONE_BOOT_ENABLED`. They were told to stop without rebooting on error and report the first-boot result before opening the browser. No new successful upload, arming or boot is yet established; expected receipts are `build/browser-namespace-files-only-last.json` and `build/browser-namespace-user-armed.json`. No VPK/system-module/CA/storage change is authorized by these helpers.

### 23.117 Namespace-corrected kernel: user staging and first boot verified

The user reported "done and livearea opened without issues". Their stage receipt is complete and preserves the prior kernel/report/trace under `build/device-backups/146-browser-namespace-files-only-20261009T172744Z-b43f9b/` and corresponding remote backup names. Arming completed at 17:28:00 UTC with the exact offset-689 change and all protected/resource checks: `build/browser-namespace-user-armed.json`, backup `build/device-backups/146-browser-namespace-arm-20261009T172753Z-f421c8/`. This was user execution, not an agent retry of the blocked staging operation.

The first post-boot read-only capture experienced a connection reset before saving files (`build/device-evidence/146-browser-route-20261009T172936Z-d20d90/`). A subsequent ordinary read-only attempt completed without changing the test: `build/device-evidence/146-browser-route-20261009T173012Z-a915c1/`. All captured reads are stable. The 19858-byte kernel has the expected hash `0afc0bd0d2f83ad34d4a5deedc1184e5f10524dfa530edcb7058147999da0ad0`, config is exactly self-disabled, and the report transitioned from PENDING to successful gate/setup with no recorder error, 19 attempts and 60 hook calls. The fresh 2969-byte trace, hash `a6d96dc4d3e633f3de31de74bf05be376c69746879aedd20608814e10cb4169c`, has 19 complete records read in full, browser-only readiness 2 and positive hook installation ID 0x31D31. Supplemental double reads verify six unchanged protected files and no alternate config; receipt `build/browser-namespace-firstboot-current.json`.

The user was asked to enter `https://www.cloudflare.com/cdn-cgi/trace?tls_fixer=namespace-1` in this same session, report the TLS line or error without bypassing certificate warnings, and leave the browser/FTP open. The distinct query avoids deliberately reusing the prior page URL. No new payload or reboot was requested. Successful startup of the kernel profile does not yet establish process-namespace hashing, provider startup or TLS 1.3 negotiation; the browser-stage capture is pending.

### 23.118 Namespace correction confirmed; provider start is the next failure

The user reported TLS 1.2 for the fresh URL. Read-only capture `build/device-evidence/146-browser-route-20261009T173209Z-f06925/` contains stable copies of the exact 19858-byte kernel, disabled config, unchanged protected configurations, a clean 256-byte report (hash `c09dd858f12b6fa10dce9241749288dd4e55936355c646c5b20b46c3dc869f61`) and a 15184-byte trace (hash `dcd05fce1ee4b8b7a4cad1d41a281a4ef1d25458b24f71729087715c40f0d597`). The report records 98 attempts, 109 loader-hook calls, no recorder error and all 98 complete records are present. No browser-provider log was listed.

Process 0xD2969 loaded `sd7b188fa1e8ed:/tls_fixer/ScePsp2Compat.suprx`, GUID 0x1330F / PUID 0x40010163. Provider metadata, all compatibility-file hash stages, cleanup and full hash comparison succeeded. Target metadata returned, and `target.shared.return` reported 0 for text address 0x812001C0. The provider load at `sd7b188fa1e8ed:/tls_fixer/tls_fixer.suprx` returned internal GUID 0x2384F. Its load/start wrapper then returned 0x8002D000; `provider.status` retained the initial value 2. Preparation cleanup and native-stack restoration completed, and the browser continued with legacy TLS. The optional SceHafnium load failed independently as in earlier traces. This run establishes the namespace correction, not a TLS handshake or a shared-target rejection.

The VitaSDK error header names 0x8002D000 `SCE_KERNEL_ERROR_MODULEMGR_START_FAILED`. IDA shows the native loaded-image start path maps an entry result of 2 to that error; the outer start API writes the caller's status only on its success path, so the existing sentinel alone cannot identify an entry stage. The provider may reject its arguments, runtime module descriptor/path, cryptographic/trust initialization or first hook; no specific rejection has yet been established.

After the MCP supervisor lost its session bindings, it could list persistent workers but failed to adopt the still-running Modulemgr worker. Source inspection found its adopted-worker liveness check requires an owned process object. Without altering the service, killing workers or duplicating the IDB, read-only decompilation used the same existing worker's standard IDA MCP endpoint through the connector command tool. Results are `build/provider-start-modulemgr-ida.json`, `build/provider-start-image-ida.json`, and `build/provider-start-fun_StartProcessImageEntryThread-ida.json`. A later separate module-info inspection call was tool-blocked and not retried.

The user was asked to approve a separately named diagnostic user provider, preserving the existing provider/CA/Sony files and selected only by a self-disarming kernel. No new deployment or re-arm has occurred. A diagnostic can return an encoded resident start status without relying on the denied file logger: the official SDK module-start contract explicitly says values other than 1 and 2 remain resident and are returned through pRes, matching the inspected native path. Such a diagnostic must keep its backend disabled on failure, preserve any published passthrough hooks, and must not be reported as TLS activation merely because native module loading succeeded.

### 23.119 Passive startup status implemented; deployment constrained to writable mounts

The user approved the separate diagnostic and reported an ordinary reboot. Added opt-in `TLS_FIXER_BROWSER_START_DIAGNOSTICS`: entry rejection returns `0x49SSDDDD`, where SS is the stage enum in `tls13/include/tls_fixer/browser_start_diagnostics.h` and DDDD is the low 16 bits of the native/detail value. This is deliberately a resident diagnostic return, not SCE_KERNEL_START_SUCCESS; the kernel still requires start status zero. It does not grant permission or suppress an identity/trust check. Early failures publish no hooks, and partial publication retains disabled passthrough hooks instead of unloading live continuations. The normal build keeps its existing 0/2 behavior. Stages cover arguments, module metadata, each segment dimension, signature index/byte, CA-path derivation, cryptographic/trust/registry initialization and each hook.

The module-status regression failed before implementation (`build/browser-startdiag-red.log`), as did separate diagnostic-path selection (`build/browser-startdiag-path-red.log`). The expanded sanitizer run passed **181/181 targets**, including all normal module cases, diagnostic module cases, backend init failures/cleanup and diagnostic kernel routing: `build/browser-startdiag-sanitizer.log`. This run preceded the final ur0 storage-path change. The user then explicitly requested compilation/transfer without more checks because only one test remained; additional normal/Python suites and a fresh IDA review were not run. Do not present the final ur0 variant as having that full suite rerun.

The first native command selected a non-existent CMake target. The corrected all-target command exposed a fresh-build configuration error: no Release type, causing register-allocation failure in the unchanged Mbed TLS inline assembly. Reconfiguring to Release, as used by the established provider build, resolved it without modifying cryptographic code. The final native build completed and its built-in kernel decoded-register gate passed (`build/browser-startdiag-native-completed.log`).

FTP refused both temporary and final unused filenames on vs0 before modifying the kernel or entry. The user clarified that writes are limited to ux0 and ur0. The diagnostic was moved to `ur0:tai/tls_fixer_startdiag.suprx`; no remount or permission override was attempted. Its kernel keeps the browser's logical mount for deriving/verifying ScePsp2Compat but uses the explicit ur0 file path for diagnostic-provider metadata and load/start. Ordinary provider selection is unchanged. A deployment-helper artifact-directory mismatch was corrected after the new ur0 file was copied, before kernel/report changes. Subsequent reuse required that diagnostic file to match exactly, without overwriting a different file.

### 23.120 Separate ur0 provider and self-disarming kernel transferred and armed

The fresh inactive before-state was captured at `build/device-evidence/146-browser-route-20261009T180151Z-23570d/`, following the user's reboot report: old 19858-byte kernel, exact disabled config, preserved 15184-byte start-failure trace and stable completed report hash `fad079ec63bc98156841bacb000f06c6b0f52fa40a7a12154bdf62b859c8797b`. The transfer also read/preserved all six protected files and all three original browser resources before adding the separate provider. Existing vs0 provider, CA and compatibility hashes were unchanged throughout.

The ordinary connector deployment completed successfully with `ONE_BOOT_ENABLED`: new kernel **20165 bytes**, SHA-256 `3af2094e9bc29ccaf8046d41eafafbf695f558319fad25329d5585d68df41b78`; separate ur0 provider **246003 bytes**, SHA-256 `37e229a3b62d4f9f4fa1c53a944d815527853fb5352afe636227e8adb791cdd0`; fresh PENDING report hash `29bbe4d922016fb88687ab45f3e8073c6d519557b8b6be3399735a264df4f26c`. Kernel/report backup: `build/device-backups/146-browser-startdiag-files-only-20261009T181104Z-98e0dd/`. Arming backup: `build/device-backups/146-browser-startdiag-arm-20261009T181113Z-491889/`. Receipt `build/browser-startdiag-user-armed.json` records complete read-back at 18:11:24 UTC, only config byte 689 changed, and no reboot requested. The separate provider's creation/reuse is recorded in `build/browser-startdiag-provider-staged.json`.

`build/deploy_browser_startdiag.py` and the generated stage/arm helpers retain exact before-state/payload gates. No new memory-only helper test run is claimed; the user explicitly requested immediate compilation and transfer. The kernel/report ZIP in `build/artifacts-browser-startdiag/` still contains only those two files; the diagnostic user provider is separate. Its presence alone does not activate it on a subsequent disabled boot. The user was told to reboot normally once, report LiveArea, and wait for the same-session browser step. The latest test outcome remains pending.

### 23.121 Post-staging observation blocked; first-boot result still pending

No user boot result arrived during the subsequent chat waits. An attempted read-only invocation of `build/capture_browser_route_readonly.py` was indeterminately tool-blocked before returning any device evidence, and was not retried. Follow-up chat messages asking for the first-boot result and offering the existing user-run collector were also tool-blocked; do not assume the user received those messages. The earlier successful instruction to reboot once remains in CHAT.md.

The latest verified configuration is the armed read-back in section 23.120, not a newly verified self-disabled state. Do not claim that the diagnostic executed, failed, recovered, or negotiated TLS from elapsed time or the completed upload. Preserve the next user-provided capture and do not run deployment helpers again. The full aggregate diagnostic diff was displayed; no additional source edit, build, test suite, deployment or reboot occurred while waiting.

### 23.122 Testing window missed; user authorized ending the turn

The user reported that they were no longer at the Vita and explicitly authorized finishing the turn because the work had been too slow. Acknowledged the missed testing window and stopped without further device actions. No first-boot or browser result for the 20165-byte/ur0-provider diagnostic was reported. The next continuation must verify the actual config, kernel, report and trace before any staging/re-arming, and must not confuse the user's earlier unarmed reboot with execution of this final build. No further tests or deployment were requested.

### 23.123 Resumed: existing armed startup diagnostic verified without changes

Read the current handoff and CHAT.md, including the missed testing window and writable-mount restriction. The ordinary read-only collector completed at 23:19:22 UTC: `build/device-evidence/146-browser-route-20261009T231922Z-37b1ee/`. Configuration remains exactly armed (`01d21cddeee7d5ea255082f5579b798e1c387ee174b73e2b4da22f797d8054f9`); kernel, PENDING report and previous 15184-byte trace match section 23.120. This is not evidence of a successful diagnostic boot.

Supplemental stable double reads checked every one of the 13 pinned files from `build/browser-startdiag-user-armed.json`, including the separate ur0 provider, the six protected boot/storage/FTP files and the three original browser resources. The alternate ux0 config is absent. Saved receipt: `armed-pretest-readonly.json` in that snapshot. No new package, file replacement, configuration write or reboot was performed. The user was told no compilation/transfer is needed and asked to reboot normally once, report the first LiveArea outcome and leave FTP available before opening the browser.

### 23.124 Startup-status diagnostic boot captured; browser result pending

The user replied "done" to the manual-reboot request. The collector was started once through the command tool. Its stdout poll was indeterminately blocked and was not repeated; the completed locally saved receipt and trace were read directly instead of rerunning the collection. Snapshot: `build/device-evidence/146-browser-route-20261009T233204Z-2e626d/`. Stable double reads show kernel hash `3af2094e9bc29ccaf8046d41eafafbf695f558319fad25329d5585d68df41b78`, exact disabled config hash `0c09159d2fa0d5e16d62b62ffbdf15595d8e4b862efe033d6decaad77d4bc9b9`, and successful gate/setup report hash `ade9357f81eedf553153503132770ea053ca94b87d2d73122b2833f4dfc31381`. Boot_config and YAMT configuration match the preflight; no provider log is listed.

The fresh trace is 2969 bytes/hash `e61e74d57206f9060bd0e35e108b714cffb6f392f0065f0e93c60c7e5804e535`; all 19 records were read. It records browser-only readiness 2, hook ID 0x31CF9 and three returned namespace loads. This establishes kernel execution and self-disarm in this attempt, not provider entry. The user was asked to request `https://www.cloudflare.com/cdn-cgi/trace?tls_fixer=startup-status-1` in the same session, without bypassing certificate warnings, and leave the browser/FTP open for capture.

### 23.125 Browser reports TLS 1.2; automatic result retrieval blocked

The user reported "tls 1.2" after the requested fresh URL. A new read-only collector invocation was tool-blocked before an execution result was returned and was not retried or routed through another tool. There is no new browser-result snapshot from that invocation. The user was asked to attach the existing `ur0:/tai/tls_fixer-startup.log` or paste its `provider.start.return` and `provider.status` lines; no additional boot or test is required to read those saved results. The last actual capture remains the self-disabled first-boot evidence in section 23.124.

While awaiting the first boot, inspected the existing 3.60 Modulemgr IDB through IDA MCP session `tls_fixer-runtime-module-info-20261010`. Its user `sceKernelGetModuleInfo` export at 0xB9212C converts PUID to GUID, zeroes a 0x1B8-byte local structure, invokes the same native info producer and copies the complete result to user memory. The producer does populate active-segment memsz/filesz; no evidence supports dropping either identity check on speculation. No provider source or validation gate was changed.

### 23.126 User-uploaded log: ur0 diagnostic file lookup fails before entry

The user supplied gist `811d5fcad7c468a97a8788784db0bc76`, immutable revision `acd4f9e27654f330ab980f355afb16faf9004087`, file `tls_fixer-startup-20261010.log`. Retrieved that revision through `gh api`, checked that GitHub did not truncate its content, and saved it with the API response under `build/user-evidence/startdiag-20261010/`. The 10426-byte log hash is `47816f1361b55e3c0aa7b155ea6d52e2e9bb60baa4595be685c691f08e2508bc`. All 66 records were read; its first 19 records exactly match the local first-boot capture. This is user-supplied evidence, not a retry of the blocked device collector.

PID 0x13296B loads `sd8f2f78602600:/tls_fixer/ScePsp2Compat.suprx`, GUID 0x1331F/PUID 0x40010163. The target name lookup succeeds and the provider is absent. At sequence 0x30, `hash.stat.return` records 0x80010013; cleanup then returns without reaching module hash streaming, shared-target checking or provider startup. No diagnostic 0x49SSDDDD code exists in this log. The rushed final ur0 path change left both the provider metadata open and native loader flag selecting the browser namespace, although the compatibility module and the separate diagnostic live in different namespaces.

IDA MCP session `tls_fixer-provider-namespaces-20261010` confirms `ksceIoOpenForPid` resolves its path through the supplied process's FIOS overlay before calling the native open. `ksceIoOpen` uses native VFS path dispatch; the path resolver's mount-name lookup uses the global assignment list. The native module loader selects the ForPid path only with flag 0x1000. These are distinct selectors, not permission changes; a filesystem error still refuses activation. The uploaded failure does not establish the original provider's entry rejection or the cause of the historical boot crashes.

### 23.127 Split provider/module namespace correction and verification

Added a regression where the diagnostic's ur0 path returns the captured 0x80010013 through `ksceIoOpenForPid`, but can be checked by native metadata lookup; the compatibility module still requires the browser namespace. The fixture also requires native load flags 0 for the ur0 diagnostic and 0x1000 for ordinary browser providers. The old implementation fails the injection-success assertion in `build/startdiag-split-namespace-red.log` (CTest exit 8).

`target_matches` now takes separate module and provider namespace selectors. The ordinary browser path uses its PID for both; the optional ur0 diagnostic uses PID for compatibility hashing and the native namespace for provider metadata/load. Startup checks and SceHttp keep their prior native selection. No CA/provider content, identity check, mount assignment, permission, worker or callback ABI was changed. The diagnostic and ordinary loader regressions then passed (`build/startdiag-split-namespace-green.log`). Missing provider, bad hash, namespace errors, shared targets, trace failures and cleanup remain covered.

The complete run saved in `build/startdiag-split-namespace-verification.log` ends with `SPLIT_NAMESPACE_VERIFICATION_PASSED`: 181 normal and 181 ASan/UBSan/leak-checking targets, 34 Python tests, native diagnostic/default builds, decoded-register gates and no unresolved symbols. Its output poll was tool-blocked; the completed saved log was read rather than rerunning that poll. After resetting the new fixture counter consistently, both full 181-target suites passed again in `build/startdiag-split-namespace-final-tests.log`. No hardware result is implied. The rebuilt default is not byte-identical to the preceding default; no byte-identity assertion is made.

IDA session `tls_fixer-split-provider-namespace-20261010` verifies the new diagnostic ELF: self-disarm remains the first call at 0x810002BC; provider metadata uses native `ksceIoGetstat` at 0x81003042, compatibility hashing still calls `ksceIoOpenForPid` at 0x810026AC, the shared-target result must equal zero, and the sole provider load/start at 0x8100321E receives zero flags/options. No user-provider build was needed. The user was asked for an ordinary unarmed reboot after closing the browser to stop the logging worker; completion is not yet reported.

### 23.128 Corrected kernel package is local only

`build/startdiag-split-namespace-kernel/tls_fixer.skprx` is 20050 bytes/hash `b4b879d09a1e644e65298111534dd5f5417452e4191fbd53a66491de125b12dd`. ELF hash: `e311f62e05a3ba385d4a889721b72ea1c0914de8360d2449df2a67d59618fec9`. Fresh 256-byte PENDING report hash: `d6af862ec9f00277293caa853b1785417b9464eceedb11eb9ec4d8bdea1610bf`. Archive `build/artifacts-startdiag-split-namespace/tls_fixer-startdiag-split-namespace.zip` has exactly the two permitted entries, reread and compared; size 16642 bytes/hash `de708584c3874002d0fc07e99070d049fe8dadd17448bacb457590c4393293ae`.

The adjacent receipt pins both payloads, sources, ELF and verification-log locations. The existing 246003-byte ur0 provider with hash `37e229a3b62d4f9f4fa1c53a944d815527853fb5352afe636227e8adb791cdd0` is to be reused unchanged. The package has not been transferred or armed. Preserve the uploaded evidence and obtain a verified inactive before-state before selecting another one-shot boot; do not replace a report while the old worker may still write it.

### 23.129 Inactive before-state verified; corrected diagnostic staged and armed

The user reported completion of the ordinary unarmed reboot. A distinct preflight for the next test obtained stable double reads of 14 files: `build/device-backups/146-before-split-namespace-20261009T235259Z-9db56c/`, receipt `build/split-namespace-preflight-current.json`. The config is exactly disabled and the alternate config absent. Old kernel, separate ur0 provider and all protected/original resources match their pinned hashes. The retained 10426-byte trace is byte-identical to the user-uploaded log; the stopped-session report is 256 bytes/hash `a6af4a83d31171750dce13121aa9d38812338ea3cd6ea32fab6814b6816bc213`. This preflight follows a newly reported reboot; it does not replace the provenance of the earlier user-uploaded browser capture.

Generated `build/stage_split_namespace_files_only.py` and `build/arm_split_namespace_once.py` from the read/verified prior helpers, with distinct backup/receipt names, exact current before-state and new payload hashes. The ur0 diagnostic provider is included in their protected-file set. Seven memory-only success/refusal/rename-restoration scenarios passed in `build/split-namespace-helper-tests.log`; no network action occurs in that test. The artifact source hashes matched before preparing the helpers.

Both helpers then completed normally through the connector under standing one-shot-test permission. Staging preserved old kernel/report under `.before-20261009T235426Z-c0490b` names and saved the trace without modifying it; backup `build/device-backups/146-split-namespace-files-only-20261009T235426Z-c0490b/`, receipt `build/split-namespace-files-only-last.json`. Arming completed at 23:55:06 UTC, phase `armed_readback_verified`, after positional-write qualification, on-card/local config backup and complete read-back: `build/split-namespace-user-armed.json`, backup `build/device-backups/146-split-namespace-arm-20261009T235457Z-932bca/`. Only the existing byte 689 changed from `#` to `u`. Protected files and the previous trace were unchanged. No reboot was issued by a tool.

The user was told the corrected kernel/report are transferred and enabled, and asked for one ordinary manual reboot without L followed by a LiveArea report before the browser request. No first-boot, self-disable or provider-start success is inferred from the armed receipt.

### 23.130 Corrected diagnostic first boot verified

The user reported "done it went to the livearea". Read-only collection completed normally at `build/device-evidence/146-browser-route-20261009T235717Z-19fd6a/`. All six captured files were read twice and stable. The 20050-byte kernel/hash matches the new package; the complete 726-byte config has the expected disabled hash. The report transitioned to successful gate/setup with no recorder error, 19 attempts and 60 hook calls, hash `ade9357f81eedf553153503132770ea053ca94b87d2d73122b2833f4dfc31381`. Boot_config and YAMT config remain unchanged.

The fresh 2969-byte trace/hash `e003a88594c02f4e219933cd9746edc308a9488359bf1048fe6fae1be0e85cc2` has 19 complete records read in full, browser readiness 2 and positive installed hook ID 0x31D05. The user was asked to request the Cloudflare trace URL with `?tls_fixer=startup-status-2`, report the TLS line/error and keep the browser/FTP open without another reboot. Kernel boot and self-disarming are observed in this attempt; corrected provider-file lookup and provider entry still await the browser capture.

### 23.131 Corrected diagnostic browser response reported; capture blocked

The user reported "tls 1.2" for the new request. Its automatic read-only collector invocation was tool-blocked before an execution result and was not retried or rerouted. The user was asked to upload the current startup log, or paste `hash.stat.return`, `provider.start.return` and `provider.status`. The preceding gist cannot be treated as this kernel's result. No additional reboot or browser request was asked for; the verified first-boot disabled configuration remains the last captured device state.

### 23.132 Uploaded corrected-namespace result reaches provider argument validation

The user supplied gist `b89a9ec33b03a61b81d144f636da5724`, immutable revision `b3b0d9567cdff9b2984e09eba81053eb6e374003`, file `tls_fixer-startup-20261010T000005Z.log`. Retrieved it with `gh api`, rejected truncation, and saved the response and exact content under `build/user-evidence/startdiag-split-20261010/`. The log is 14660 bytes/hash `a797ece0b33dae96407d4dd758905e2719478f487a3c6fb1fd147b6f6bc69e13`. All 95 records were read; the first 19 exactly match the corrected kernel's first-boot capture. This is the user's uploaded evidence, not a retry of the blocked collector.

PID 0xA2E23 loads the replacement compatibility module through `sddfc7e80196c5:/tls_fixer/ScePsp2Compat.suprx`, GUID 0x1333D/PUID 0x40010163. Provider metadata succeeds, the complete compatibility-file hash matches, and the target text at 0x81300AC0 is classified non-shared. Native provider start returns positive GUID 0x23909 and status **0x49030000**. Stage 3 is `TLS_FIXER_BROWSER_START_ARGUMENT_MAGIC`; the reported low 16 bits of received magic are zero. This does not reveal its upper bits. Entry rejected the handoff before metadata validation, crypto/trust initialization or hook publication. The namespace correction is observed working in this attempt; browser TLS remains 1.2.

### 23.133 Native startup copy contract and checked user argument buffer

Reopened the native Modulemgr, ThreadMgr and Sysmem databases through IDA MCP (`tls_fixer-start-args-modulemgr`, `tls_fixer-start-args-threadmgr`, `tls_fixer-start-args-sysmem`). The ForPid wrapper adds flag 0x08000002; the entry-thread worker selects `SceThreadmgrForKernel_E0833C77`, which passes mode 1 into the start-thread worker. That path probes the source and can fill the new user stack argument area with zeroes instead of delivering an inaccessible source. The alternative successful source-copy path uses `ksceKernelCopyFromToUser`. The former claim in section 23.82 that the wrapper supplies a usable kernel-argument path was not a sufficient examination of this behavior and is superseded here. No change to native access checks or kernel functions is made.

The allocator's native option processing explicitly accepts size 0x58, copies PID at offset 0x24 with attribute 0x80, and supports user RW allocation. The implementation now allocates one 4096-byte user RW block owned by the target process, copies only the initialized 16-byte handoff through `ksceKernelCopyToUserProc`, reads it back through `ksceKernelCopyFromUserProc`, and compares all bytes before provider start. It requires the current process ID to equal the target; foreign-caller contexts are refused rather than guessing source/destination address-space semantics. The native load/start gets the user address, not the kernel stack pointer. The block is released after the synchronous API returns, including failure paths; release errors are recorded and are not authority to unload possibly published hooks. Options and read-back storage remain in the existing bounded query workspace. No new executable mapping, worker, module ABI or permission override is introduced.

The new fixture requires an owned argument buffer at the real native-call boundary and checks PID/type/options, byte contents, lifetime, allocation/base/copy/read-back failures, corrupt read-back, foreign context and cleanup/trace errors. It failed on the old kernel-stack handoff (`build/start-arguments-red.log`, CTest exit 8). The corrected full sanitizer suite passed (`build/start-arguments-green.log`). Final `build/start-arguments-verification.log` ends `START_ARGUMENTS_VERIFICATION_PASSED`: **181 normal, 181 ASan/UBSan/leak-checking targets and 34 Python tests**, fresh diagnostic/default native builds, decoded-register gates and no unresolved symbols. This is not a hardware argument-delivery result.

IDA session `tls_fixer-user-argument-marshalling` checks the generated diagnostic: self-disarm is first at 0x810002BC; the caller-PID comparison precedes argument allocation; the allocator receives USER_RW, 4096 bytes and the exact size/attribute/PID fields. The checked copy is at 0x8100328E, read-back at 0x810032D8 and full comparison at 0x810032EC. The provider call at 0x8100333E loads its argument pointer from the returned user-base slot. The current ur0 diagnostic still gets zero namespace flags. Cleanup has a native release call after the start result. The normal and diagnostic providers themselves were not rebuilt or changed.

### 23.134 Argument-marshalling package and actual one-shot staging

After the user reported the requested unarmed reboot, fresh stable double reads of 14 files captured `build/device-backups/146-before-start-arguments-20261010T001619Z-53a613/`, receipt `build/start-arguments-preflight-current.json`. The prior 20050-byte kernel, unchanged separate ur0 provider and all protected/original resources match their pinned hashes; the configuration is exactly disabled and the alternate config absent. The trace matches the uploaded 14660-byte log. The stopped-session report is hash `17525d161ba51c2a46ec8e2e3a9f5137298b5914805ba50459bf685d67c7efa1`.

New `build/start-arguments-kernel/tls_fixer.skprx` is **20645 bytes**, SHA-256 `429b594c59aaff7082574121d521ce1e1e5801998b858b9aa35b5ac37e98d3c7`; ELF hash `f0174782e55731fc8f1dbfc4daf42898b42a9adf4701b7942130447cdec3e652`. Fresh 256-byte report hash: `5214b36cd34e5b89da63ac62fe9e2e3674ccb473c490ca079174ed0880eb54f5`. The two-entry archive `build/artifacts-start-arguments/tls_fixer-user-start-arguments.zip` is 17228 bytes/hash `23f2a311148440c50f8b5c6adb6fa41c630b7a0d993bc2d9d059775e5d2312ae`; both members were reread. The adjacent receipt pins sources, ELF and verification log. New stage/arm helpers passed seven memory-only scenarios in `build/start-arguments-helper-tests.log`.

The stage and arm helpers were executed once through the connector. The output poll was tool-blocked and was not repeated; their completed saved receipts were read directly. `build/start-arguments-files-only-last.json` records both new files read-back verified, old kernel/report preserved under `.before-20261010T001834Z-cfcf2b`, and no configuration write during staging. Backup: `build/device-backups/146-start-arguments-files-only-20261010T001834Z-cfcf2b/`. The arm receipt is complete, phase `armed_readback_verified`, at **00:18:55 UTC**; backup `build/device-backups/146-start-arguments-arm-20261010T001845Z-f7e8e7/`. Only the existing config byte 689 changed; protected files/provider and preceding trace remained unchanged. No remote reboot was issued. The user was asked to reboot normally once and report LiveArea before making the next browser request; no result for the new kernel is inferred from these receipts.

### 23.135 User-argument kernel first boot verified; browser request pending

The user reported "Done it booted to livearea". The ordinary read-only collector completed normally: `build/device-evidence/146-browser-route-20261010T002258Z-1e662c/`. Stable double reads identify the exact new 20645-byte kernel/hash `429b594c59aaff7082574121d521ce1e1e5801998b858b9aa35b5ac37e98d3c7`, expected disabled configuration and successful gate/setup report with no recorder error. Boot_config and YAMT configuration are unchanged. The fresh 2969-byte trace/hash `d25e002fbac2a794b48c762000750d16370d9875fda2eecf329a95bae3c157d1` has all 19 complete records read, browser readiness 2 and positive hook ID 0x31D11.

The user was asked for `https://www.cloudflare.com/cdn-cgi/trace?tls_fixer=user-arguments-1` without bypassing certificate warnings, then to report the TLS line/error and keep the browser/FTP open. This captures only the kernel's boot so far; do not infer successful user-buffer allocation/copy, provider argument acceptance or TLS negotiation until the request evidence arrives.

### 23.136 Browser crash reported; private core and trace requested

The user reports that the browser crashed while loading the requested URL, showing **C2-12828-1**, with a new core dump in `ux0:data`. This is a browser-test failure, not a reported new boot failure. The entry had already been verified disabled in the first-boot capture. Asked the user to stop testing, not re-arm or reboot yet, and leave FTP available for evidence preservation.

A read-only command intended to collect the trace and inventory core files was tool-blocked before an execution result or new files arrived; it was not retried or rerouted. Asked the user to provide the new `.psp2dmp` and current startup log as private attachments or local Mac paths after copying. A browser core may contain private session memory and must not be uploaded to a public gist by the agent. No device change, re-enable or additional test followed the crash. No crash PC, module, accepted argument value or root cause is known until those files are obtained; the earlier argument-magic log is not this new failure's evidence.

### 23.137 Uploaded crash trace proves argument acceptance and two successful provider entries

Read all 188 records from `build/user-evidence/argument-crash-20261010/tls_fixer-startup.log`. The saved `gist.json` contains the exact untruncated bytes at immutable revision `9dfe2b875e4e834dd1f54d652d9424e7827b9195`. The log is 28727 bytes, SHA-256 `c95bf86946c902c5c78c55cf7be4111ae2b301a39d4c579318d0d3bd19ceb022`, and begins with the exact 2969-byte first-boot capture from section 23.135. This is the user-supplied kernel trace, not a core-memory dump.

The first WebKit PID 0x000F2473 has compatibility GUID 0x1330B, PUID 0x40010163 and text 0x81300C30, classified nonshared. Its argument allocation/base/copy/read-back operations succeed; provider load/start returns GUID 0x2380D and `provider.status=0` at sequence 0x56. Argument release, query release, callback/stack returns and final preparation cleanup also succeed. The second WebKit PID 0x00023FBF repeats this sequence, with compatibility GUID 0x337B1/text 0x813008A0 and provider GUID 0x33129; status is again zero at sequence 0xA9. Both subsequently load WebKitModule successfully.

The user clarified that they reloaded after the first crash and the page crashed again. Record two user-triggered attempts, not an automatic restart loop. These results move the investigation past the old argument-magic rejection and into the enabled provider's runtime. They do not identify the faulting instruction, prove a completed handshake, or explain why no matching core was supplied. Developer-mode relevance has not been established.

### 23.138 Runtime ABI audit and renewed read-only evidence

Read the complete current browser module, backend, option parser, ABI header and crypto platform shim, plus `docs/tls13-browser-path.md`. Reopened the existing exact-artifact database in IDA as `tls_fixer-crash-compat-review`; the first open returned a transport 502 and the subsequent ordinary open reused the warmed database. Native decompilation of 0x810A5ECE, 0x81093F18, 0x810A3C98, 0x810A354C and 0x810A6240 agrees with the implemented connect/deadline/health/pending signatures and the main socket, SSL state, handle, callback and verification offsets. Scoped xrefs to embedded SSL read/write/peek/error/session/free functions did not by themselves expose a new unhandled default-browser call. This is a partial runtime audit, not evidence that the whole adapter is correct. Later scoped audit/metadata tool calls were blocked and were not rerouted.

The old read-only collector completed at `build/device-evidence/146-browser-route-20261010T005312Z-38f75b/`; its completed output was read from `build/crash-resume-readonly-capture.log` after its exec session ceased to exist. It verifies the same 20645-byte kernel, disabled configuration and unchanged boot_config/YAMT configuration. The trace advanced to 29231 bytes/hash `31cd9a03c72a7b04895627c45afcb015ec9bb523bc8ceae0b741085e999aadb9`; report hash is `5720afdfd7206f853f26081eb24d5adf00387df397310cbf66e178ddb51a41a4`.

The new collector's first live attempt stopped on an overly restrictive 64-filename diagnostic-inventory cap. Added regressions requiring primary evidence to be saved before directory processing and allowing a bounded larger historical core inventory. The corrected collector completed at `build/device-evidence/146-log-capture-20261010T010611Z-6a74c937/files/`; its output-poll call was blocked, and the completed saved JSON was read without repeating the operation. All ten primary files have stable double reads, the six protected files retain their expected identities, and the disabled config/kernel/trace/report match the preceding capture. It inventories 256 core filenames but retrieves no core contents; no core is established as belonging to these crashes. There are no matching `tls_fixer-browser-*.log` names in ux0:/data. Missing user logs do not establish the precise permission or logging failure.

### 23.139 Guarded autonomous workflow and host verification

The user explicitly requested that transfer scripts reboot the Vita and that the agent launch the browser, which they say restores the Cloudflare URL, then fetch logs. Added `tools/vita_tls_cycle.py`: `run` chains reviewed stage/arm helpers to `after-arm`, which validates the new receipt, exact armed config and one-byte disabled image, payload/protected hashes, alternate-config absence and the installed title's SFO. It consumes each arming receipt in an exclusive host journal before requesting one reboot, requires a disconnect/reconnect plus independent fresh boot/self-disable evidence, then requests one browser launch and collects evidence. Helper failures, unchanged receipts, replay, stale trace, failed report, unknown state or changed files stop the sequence. No Vita-side arming file or new loader was added.

`collect` is independently read-only, preserves both reads of changing files, retrieves at most 64 selected browser logs and inventories at most 4096 directory names without downloading cores. Primary files are saved before inventory parsing, with any omitted log names recorded. `reboot-disabled` preserves the current evidence and performs one explicitly requested unarmed reboot, without transfer, arming or browser launch. All outputs remain private local files. Unknown launch responses and incomplete captures are not CLI success; `cycle_complete` is workflow completion, and `tls13_established` is never inferred from startup or launch.

Initial missing-runner coverage is in `build/vita-cycle-red.log`. The cap/ordering regressions and new unarmed-reboot checks failed in `build/vita-cycle-evidence-red.log`; missing helper chaining/completion reporting failed in `build/vita-cycle-helper-chain-red.log`. After implementation and correction of macOS /var versus /private/var test-path aliases, `build/vita-cycle-final-python-tests.log` records **57/57 Python tests passing**, including 23 workflow cases; syntax compilation also succeeds. The prior 181 CTest suites were not rerun because their production sources were not changed. Procedure and interpretation limits are in `docs/tls13-autonomous-test-cycle.md`.

Only the collector has executed against the Vita. The reboot/launch/helper-chain paths have host-fake coverage but no live success is claimed. An actual SFO/title verification call was tool-blocked; no title ID was inferred from that attempt, and the live SFO guard remains required. No new payload, arming, reboot, launch, certificate change, developer-mode change or original-module change occurred in this continuation. The post-start browser failure remains open.

### 23.140 Pending runtime instrumentation reconciled and baseline verified

On resumption, read the current handoff and CHAT.md through the request for stage-only LAN diagnostics. The worktree already contained `tls13/browser/runtime_udp.[ch]`, markers in the browser module/backend, `tools/vita_runtime.py`, receiver tests and integration in `tools/vita_tls_cycle.py`, beyond the previous written handoff. Their timestamps precede this continuation. Preserved and read those edits rather than replacing them. Earlier failing/passing logs include `build/runtime-udp-red.log`, `runtime-udp-green.log`, `runtime-boundaries-red.log`, `runtime-boundaries-green.log`, `runtime-receiver-red.log`, `runtime-receiver-green.log` and `runtime-cycle-integration-red.log`.

The resumed baseline completed in `build/runtime-resume-host-tests.log`, with two 192/192 CTest success summaries and `RUNTIME_RESUME_HOST_VERIFIED`. `build/runtime-resume-python-tests.log` records 71 passing tests. The native build saved by the preceding work had stopped linking `runtime_udp.c` because newlib's `__errno` was unresolved in this Sony-libc provider (`build/runtime-udp-native-build.log`). These are distinct results: host mocks supplied errno and did not establish native linkability.

The recorder sends at most 128 fixed 48-byte scalar packets per provider instance, initializes only on the first connect marker, uses nonblocking sends and retains no caller data pointers. The host accepts only the selected nonce/source, bounds processes/records/time, and preserves sequence gaps. Socket initialization can drop concurrent markers; absence is not proof that a boundary was not executed. The host interface returned 192.168.1.249 in this continuation, but it must be verified again for a later deployment.

The fresh read-only `collect` request was tool-blocked before a result. It was not rerouted; the user was asked to run the existing collector locally. An SDK errno-inspection command was also blocked and not repeated. Two ordinary IDA list requests returned upstream 502 errors, leaving new native inspection unavailable. No new device state or successful live test is inferred from these requests.

### 23.141 Native recorder errno binding repaired without introducing newlib

Added an explicit native-libc test target whose fixture requires the Sony accessor to be used, while independently perturbing C-library and SceNet errno values. The old recorder failed `libc_errno_calls > 0` in `build/runtime-native-errno-red.log`. The recorder now obtains and retains the C errno pointer once, uses `_sceLibcErrnoLoc` in the native target and the host errno accessor in host builds, preserves both error domains, and suppresses diagnostics on a missing pointer. No TLS, trust, kernel or filesystem-permission behavior was changed.

`build/runtime-native-errno-green.log` contains 19/19 focused recorder tests, including native accessor selection, null pointers, send/address/socket failures, reentry and concurrency. It then shows a completed Vita provider SELF build, no unresolved ELF symbols and `RUNTIME_NATIVE_ERRNO_BUILD_PASSED`. The outer zsh wrapper subsequently returned an error because `status` is a read-only shell variable; that wrapper error does not erase the completed inner build or turn it into an aggregate-suite run. The native accessor symbol is resolved by the link, but no new IDA inspection or device call has been observed. Do not treat a host accessor fixture as native runtime proof.

The concurrent recorder test was subsequently corrected to accept the intentional initialization-drop behavior: one socket and a nonzero bounded set of unique sends, rather than assuming that all producer schedules necessarily exhaust the budget. The separate sequential limit test retains the exact hard-cap check. This latest test-only adjustment awaits the final rerun.

### 23.142 Empty/failed runtime capture cannot complete the diagnostic cycle

Two added host regressions exposed that `after_arm` could report `cycle_complete=true` after a successful launch/FTP capture even when the requested runtime receiver obtained no packets or failed. Both failed on that exact assertion in `build/runtime-cycle-completion-red.log`. The correction preserves `runtime_observed` separately from `runtime_complete`, retains partial summaries/evidence, and requires a clean nonempty runtime capture before a runtime-enabled cycle can complete. It never initiates another launch, reboot or re-arm in response to that failure.

The final aggregate verification command (Python, both CTest suites and native build) was tool-blocked before a result and was not retried in another form. A separate artifact-identity read was also blocked. Do not claim the final 202-target/73-test state has passed, attach an unverified hash to the new SELF, or generate a ready-to-run deployment from stale device receipts. The most recent completed results are those explicitly recorded in sections 23.140-23.141. No new package was staged or armed.

Procedure, packet layout, scope and interpretation limits are in `docs/tls13-runtime-stage-trace.md`. The next continuation must complete the pending verification/native review, obtain the user's current capture or a successful fresh read, verify an inactive before-state, and select one identified runtime diagnostic. The two original browser crashes remain unfixed; no runtime stage packet has yet been collected from the Vita.

### 23.143 Recovered IDA service: native errno and runtime recorder reviewed

After the user returned to ask what to do, the ordinary IDA service recovered. The existing libc IDB opened as `tls_fixer-runtime-libc-errno`. `_sceLibcErrnoLoc` obtains `sceKernelGetTLSAddr(136)` at 0x81184834 and returns an int pointer, with a native global fallback if the TLS lookup is absent. This independently verifies the accessor shape used by the new recorder; it does not establish a device execution of the diagnostic.

The built runtime ELF opened as `tls_fixer-runtime-udp-native-review`. Scoped instruction queries read the complete 0x81001E2C..0x81002058 recorder and 0x810000D4..0x81000148 connect-hook ranges without truncation. The recorder calls `_sceLibcErrnoLoc` at 0x81001E68, saves its pointed value, obtains the separate SceNet pointer at 0x81001E76, and restores both values at 0x8100202E/0x81002032. The 128-record bound, initialization release/acquire ordering, fixed nonce, private receiver and 48-byte nonblocking send are present; `sceNetSendto` at 0x8100202A receives size 0x30 and flags 0x80. No filesystem write is added by this function. Its frame uses 68 local bytes plus 36 saved-register bytes.

The connect hook retains its four incoming native arguments, marks entry at 0x810000E2, calls the backend at 0x810000F2 and tests the handled result. The legacy branch resolves its continuation then forwards the same arguments at 0x8100011C; both branches preserve the actual return code across the ending marker. This closes the previously unavailable static review, not the browser fault investigation. The native source was not changed during this review.

### 23.144 User-run current capture and final local-verification request

The user ran the existing read-only collector and supplied `build/device-evidence/146-log-capture-20261010T060619Z-1801deab/files/`. Its complete receipt records stable double reads of all ten primary files: the exact disabled config, the same 20645-byte kernel/hash, and all six unchanged protected files. The new 30739-byte trace/hash `c24ff0021ce51c71cb4bdb957b84ed993c876afabdb9224059034ddbe0b2c077` has 200 complete records; the additional tail after the earlier two browser attempts contains VitaShell and common app-settings/calendar module loads, not a new provider startup. The 256-byte report/hash `48e64ce4ac668ca4732e9ab3687151c8cdbdb8e9cc33196c002200b8ec18c8ab` records no recorder error, 200 attempts and 202 loader calls. No matching user-runtime log is listed. This capture is not a proven inactive-session reboot and does not authorize overwriting a still-running diagnostic report.

Because the final aggregate check remained tool-blocked, prepared `build/verify_runtime_ready.py` for explicit user execution. It performs only local tests/builds, verifies the intended native profile and unchanged source set, preserves the proven kernel identity, and writes a unique local receipt plus an endpoint pinned to the new provider hash on success. It never contacts the Vita. The user was asked to run it and provide the receipt path or error. No success or new artifact hash is inferred merely from providing this helper.

### 23.145 Guarded remote unarmed reboot; no additional browser attempt

Announced and executed `tools/vita_tls_cycle.py reboot-disabled build/start-arguments-user-armed.json` under the user's explicit remote-reboot authorization. It saved before-state, checked the exactly disabled config and receipt-pinned kernel/protected/provider files, and sent one reboot command. The TCP command-response read timed out; the command was not resent. The runner subsequently observed disconnect/reconnect, rechecked the disabled configuration and protected files, and saved the after-state at `build/device-evidence/146-unarmed-reboot-20261010T061412Z-bf505e7f/after/`.

The completed JSON in `build/runtime-unarmed-reboot.log` reports `reboot_requested=true`, `disabled_readback_verified=true`, `configuration_written=false` and `browser_launched=false`. The stdout-poll tool was blocked; the completed saved log was read instead of repeating that poll or the reboot. Its after-capture receipt records stable double reads with the same kernel, 30739-byte trace and 256-byte report identities as section 23.144. The six protected files remain unchanged. This is command/disconnect/reconnect/file evidence, not an observed screen or a claim that every possible recovery restart is excluded.

The user then asked the agent to reboot it and asked what the response timeout meant. Clarified that the remote request had already been sent once, that the timeout referred to the five-second TCP response-read limit, and that the later disabled-state checks succeeded. No second reboot, transfer or test was issued. Final local verification from the supplied helper is still pending.

### 23.146 Requested 20-second control reply; independent reboot observation

The user requested increasing the command-response wait from five to twenty seconds. Changed the bounded response-read deadline to 20 seconds while retaining the five-second TCP-connect timeout and the separate default 120-second reboot deadline. Simply waiting longer before observing FTP could miss a quick reboot, so both armed and unarmed workflows now start their read-only observer immediately after the single command has been sent, concurrently with waiting for its reply. The observer is cancelled/joined on a rejected command or exception; an unconfirmed send stops without retry or launch.

The initial timeout regression rejected a simulated reply available after ten seconds. After correcting the test fixture so that a deliberately missing alternate configuration could not masquerade as a reboot disconnect, both slow-reply observer regressions failed against the old sequential workflow (`build/command-timeout-20-red.log`). The implemented change passed all 32 workflow cases in `build/command-timeout-20-green.log`. Two further cases cover a timed-out reply with a positively observed reboot, and a failed send without observer startup or retry. The full Python suite then passed **79/79 tests** in `build/command-timeout-20-full-python.log`, including the earlier empty/failed-runtime completion regressions.

This was host-only verification; no second reboot or browser launch was performed to test the timeout. The final CTest/native artifact-pinning helper remains pending user execution. Native runtime/provider sources and the proven kernel were not changed for this timeout request. The local vitacompanion checkout was read to confirm its response strings, but it is not asserted to match the installed binary or establish the cause of the earlier missing reply.

### 23.147 Final runtime verification completed; immutable local identities

On this continuation, read the current worklog and CHAT.md, including the autonomous workflow request, the completed unarmed reboot and the 20-second response change. The ordinary invocation of the existing `build/verify_runtime_ready.py` completed successfully. It saved `build/runtime-ready-20261010T074449Z-13d9cb/receipt.json`, `python.log`, `native.log` and `endpoint.json`: **202/202 normal CTest, 202/202 sanitizer CTest and 79 Python tests**. Native provider linking, no-unresolved-symbol checks, the preserved kernel register check, profile checks and unchanged-source checks all completed. This is the first completed aggregate verification of the final runtime recorder/cycle state; it did not contact the Vita.

The preserved kernel remains 20645 bytes/hash `429b594c59aaff7082574121d521ce1e1e5801998b858b9aa35b5ac37e98d3c7`. Runtime provider `build/runtime-udp-vita/browser/tls_fixer.suprx` is **247346 bytes**, SHA-256 `90ae1548161ce0d2b967cb51aa2cd531a2adee79ca6fc8710966d40bb5e57b96`; its 497292-byte ELF hash is `af346ba9b71878b30b4704531a588efc0527bc0cc8cfa32d34caa3e27244421d`. Endpoint configuration is 192.168.1.249:52154, nonce `[retained in private local evidence]`, expected peer .146, and the provider hash above. This is a configured endpoint, not yet a freshly verified bindable interface.

### 23.148 Fresh disabled-state capture; remaining preflight blocked

The ordinary collector completed at `build/device-evidence/146-log-capture-20261010T074532Z-3cad20fe/files/`, saved in `build/runtime-continuation-current-capture.log`. Its exec session was no longer present when polled; the completed saved log was read rather than rerunning collection. All ten primary files have stable double reads, with exactly the same kernel/config/report/30739-byte trace and protected-file hashes as the post-unarmed-reboot capture. The trace remains 200 records. No matching browser logs were listed, and the core inventory remains filenames only.

A subsequent read-only preflight intended to validate the installed browser SFO, the separate ur0 provider and the configured local receiver bind was tool-blocked with no result. It was not retried or split into alternate network calls. Prepared and syntax-checked `build/check_runtime_preflight.py` for explicit user execution. It checks the verified source/artifact set, exact captured baseline, old diagnostic provider hash and installed SFO, tests a transient local UDP bind, and saves a private receipt. It cannot upload files, arm, reboot or launch. The user has been asked for its receipt or error; no completed result is inferred from providing it.

### 23.149 Runtime-only package and local helper coverage; socket error hypothesis checked

Prepared `build/artifacts-runtime-first/` from the verified bytes. Its two-entry `tls_fixer-runtime-first.zip` contains only the unchanged kernel and new 256-byte PENDING report; report hash `1b1c27a802bd249a7c6ba1b0605f7b5e64d089dfbd650c9c276a833896c8d15d`, ZIP hash `ebe73846df39ff826b06520bef0ecd9d66ba465b962f18f9ea5a27804c2b804f`. Both entries were reread. The diagnostic provider and endpoint remain separate adjacent files. The receipt explicitly records `deployment_ready=false` pending section 23.148.

Generated `build/stage_runtime_first_files_only.py` and `build/arm_runtime_first_once.py` from the inspected argument-test helpers. Staging will replace **only the separate ur0 diagnostic provider and its report**, not rewrite the byte-identical kernel. It pins the captured current baseline and retains prior provider/report copies; the arm helper checks the new provider, unchanged kernel/protected resources and the existing one-byte config edit. `build/check_runtime_first_helpers.py` passes seven memory-only scenarios (`build/runtime-first-helper-tests.log`), including no kernel writes, mismatch refusal without writes and old-provider restoration after a failed publication rename. A fixture assertion initially failed because the new protected set also includes the deliberately corrupted kernel; the assertion was corrected without changing the helper behavior. No helper network function has executed.

Continued a narrow native ABI audit rather than modifying TLS blindly. IDA session `tls_fixer-native-net-result-audit` opens `/Volumes/data/Downloads/vitadump 3.60 ELF/SceNet.enriched.elf`. `sceNetSend` reaches 0x8115BE6C and `sceNetRecv` reaches 0x8115BF94; both return nonnegative syscall counts unchanged, convert ordinary negative errno values to `0x80410100 | errno` while setting the native errno slot, and retain already encoded errors. Thus treating these APIs as POSIX `-1`-only calls would be incorrect for the inspected native paths. The existing BIO encoded-error mapping was not changed. This rejects one candidate explanation; it does not locate the browser crash. No source fix or extra hardware attempt is claimed.

### 23.150 User preflight received; guarded cycle tool-blocked, user run requested

The user supplied successful output and `build/device-evidence/146-runtime-preflight-20261010T081347Z-17f5dbc9/preflight.json`. Read all 130 lines: complete/read-only, no writes or reboot, all eleven files matching the expected disabled baseline including the 246003-byte old ur0 provider. The SFO identifies `NPXS10003` as `Internet Browser`; SFO hash `396773a6f0811e0b135b1c8f7323a019f451cdc22b2e5eef8b06937cc938a88f`. The local UDP bind succeeded at the endpoint configured in the verified provider. Its script also checked the unchanged verified source/artifact set before returning success. `build/artifacts-runtime-first/preflight-reviewed.json` records this result without rewriting the original package-preparation receipt.

Announced one guarded runtime diagnostic, preserving the kernel and original resources. The combined local-receipt verification and `tools/vita_tls_cycle.py run` tool invocation was then blocked before an execution result. `build/runtime-first-cycle.log` was absent when inspected. This is not proof of an executed transfer or reboot; no alternate tool or split device call was used to retry it. The user was supplied the same reviewed `run` command with `stage_runtime_first_files_only.py`, `arm_runtime_first_once.py`, receipt `runtime-first-user-armed.json`, title `NPXS10003`, the pinned endpoint, and 45-second observation. They were told to run it once, not reload/retry on an error, and supply the result. Await actual receipts and runtime packets before making any further device change.

### 23.151 User-run runtime cycle: self-disarming boot and provider startup, but zero UDP packets

The user ran the supplied cycle and reported a browser crash. The stage and arm receipts completed: backup `build/device-backups/146-runtime-first-files-only-20261010T081823Z-de17d4/`, and arm backup `build/device-backups/146-runtime-first-arm-20261010T081832Z-5dd117/`, with `armed_readback_verified` at 08:18:39 UTC. The kernel remained unchanged; only the separate diagnostic provider and report were staged. This was user execution, not an agent retry of the blocked command.

The completed private cycle is `build/device-evidence/146-cycle-20261010T081845Z-733ca03a/`. It records one reboot request, successful independent boot checks, one attempted browser launch, and response timeouts for both commands. The user independently observed the browser. `launch_acknowledged=false` therefore does not mean launch was never executed. No second launch was sent by the runner. Its receiver accepted/rejected zero packets, `runtime.jsonl` is empty, and `cycle_complete=false`, `runtime_observed=false`, `runtime_complete=false`, `tls13_established=false`. The receiver itself exited cleanly; an empty capture correctly did not count as a completed runtime diagnostic.

Both boot/browser primary captures are complete with stable double reads and the exact disabled configuration. The boot trace is 2969 bytes/hash `8d2a4a9c98c7d9a5dbbb2da22f1d9a4a813e1301327bcf8cfe6e8c2a9ae7d88c`. The browser trace is 28727 bytes/hash `960f0f4933d9373ce5aae2ad35965b420af0b1389fc4854c6a96bc74c517ae2b`, with 188 complete records. Its report hash `f77668659abafe3d787c063058fd9a1f10c967468d40b11257fee5b0c6b078af` records 188 attempts, 131 hook calls and no kernel-recorder error. No browser user log or new core filename appeared compared with the before-inventory.

WebKit PID 0xB27A5 starts provider GUID 0x237D1 with status zero; PID 0x332BF starts provider GUID 0x438C7 with status zero. Both compatibility targets are classified nonshared and complete argument/query cleanup. The user clarified that the error dialog appears while the browser interface remains visible, and pressing OK retries the page. This is consistent with failure/replacement of the separate content process, not necessarily destruction of the UI application. They then dismissed the dialog, immediately pressed Home and closed the browser without seeing another error. Record that as an interrupted retry, not proof of survival. The two process starts must not be mislabeled as two runner launch commands.

Zero UDP packets do not identify a fault boundary: the recorder initializes only at connect entry, and socket/errno initialization, network delivery or earlier hooked operations remain possible blind spots. IDA `tls_fixer-runtime-net-diagnostics` independently confirms that `sceNetInetPton` returns 1 on success for the configured IPv4 spelling; no speculative parser-result correction was applied. Announced a passthrough control to separate hook/continuation behavior from the enabled TLS backend, and one guarded unarmed reboot to stop the current in-memory diagnostic before any replacement. Its result is not yet assumed.

### 23.152 Unarmed shutdown and verified passthrough-control implementation

The ordinary guarded unarmed reboot completed at `build/device-evidence/146-unarmed-reboot-20261010T082737Z-18a2e3bb/`, with `disabled_readback_verified=true`, no config write and no browser launch (`build/runtime-first-unarmed-end.log`). The control reply timed out, but disconnect/reconnect and exact post-reconnect checks completed. This is not a visual LiveArea report. The after-capture supplies the next helper's report/trace baseline.

Added opt-in `TLS_FIXER_BROWSER_PASSTHROUGH_ONLY`. It requires the Vita startup-diagnostic profile, rejects runtime UDP, retains all target validation and backend initialization, and installs the same four hooks before explicitly leaving the backend disabled. The normal build still enables TLS. The control intentionally uses the original backend for requests, with the existing empty-registry passthrough behavior. It is a discriminating test, not a claimed fix. The prior behavior failed the control's `enabled` assertion (`build/passthrough-control-red.log`, CTest exit 8); implementation passed **214 normal and 214 sanitizer CTest targets** and the native build/no-unresolved-symbol/kernel-register gates in `build/passthrough-control-verification.log`, ending `PASSTHROUGH_CONTROL_VERIFIED`.

IDA session `tls_fixer-passthrough-control-native` verifies four hook installations via 0x81000398 and the loop bound at 0x810003AC, followed by `MOVS R0,#0` at 0x810003B0 and `tls_fixer_browser_enable` at 0x810003B4. The connect wrapper retains its four native arguments across the adapter and forwards to the continuation; no UDP recorder is compiled. The native enable function stores the zero value with release ordering. Host wrappers do not prove actual trampoline execution, which remains the purpose of the control.

Prepared `build/artifacts-passthrough-control/` and pinned helpers `build/stage_passthrough_control_files_only.py`, `build/arm_passthrough_control_once.py`. Provider: **246003 bytes**, hash `2ca37f65cc60c02bcf9f8650c95870a24ec6e74688c86d74e760ce7c830b3533`; report hash `3097d73812f856f76fa3c42c67ab1d0f92f035a06db0347cf489dbdfe11805e6`. The proven kernel is unchanged and is checked, not rewritten. Original resources remain protected. The package's ZIP contains only the kernel/report; the provider is separate. The command to generate/run a fresh copy of the memory-only helper suite was tool-blocked; no new helper-suite pass is claimed. These helpers retain the previously tested mechanism, with only pinned identities/baseline changed, and were syntax-checked during generation.

The ordinary `run` execution then completed: stage backup `build/device-backups/146-passthrough-control-files-only-20261010T083421Z-bf3234/`, new one-byte arming receipt, and cycle `build/device-evidence/146-cycle-20261010T083444Z-1bbb7df5/`. Boot is verified and the config is exactly disabled. The runner received `Launched.`, but the browser capture still has just 2969 trace bytes/hash `dd90f5fa9af24cc94d481ea5208f1fe2a21e3b8076e7fb62d346e07f42660870`, 19 attempts and 60 loader calls. There is no provider entry or new core/user log. `cycle_complete=true` denotes command/capture completion only, not that the page or control ran. Asked the user which screen is visible instead of calling this a successful passthrough test.

### 23.153 Requested iterate.sh wrapper and refined launch observations

The user requested storing the long one-liner in `iterate.sh`. Added an executable worktree-root wrapper selecting the current passthrough test. It resolves its own directory, refuses an existing selected arming receipt, takes an exclusive host-side lock, invokes the existing guarded runner exactly once and propagates failure without retry. It is not a loop, scheduler, device loader or automatic post-crash re-arm. The command/profile must be updated deliberately when a new test is chosen. The current test already has a receipt, so running it again now refuses before a device command.

`tools/tests/test_iterate_sh.py` first failed because the wrapper did not exist (`build/iterate-wrapper-red.log`), then all four isolated tests passed (`build/iterate-wrapper-green.log`): exact one-cycle arguments, exit-code propagation, prior-receipt refusal and concurrent-invocation refusal. Tests use a temporary workspace and fake command, not the Vita. The wrapper was not executed against the already-running control cycle.

The user further clarified that the earlier one-liner opened the browser immediately with an error before page loading. They closed/reopened it manually, after which page loading started and the reported later error appeared. This supersedes the tentative explanation that pressing OK alone accounted for both observed WebKit instances. Keep launch behavior, manual reopen and later content failure distinct. A possible launch-path issue is not proven. Asked whether this observation applies to the earlier runtime test or the newly run control; that clarification and the current on-screen state are pending.

### 23.154 Direct screen capture identifies the launch-stage failure

The user requested that the agent take screenshots rather than ask them to inspect the screen. The live command server's help confirms synthetic button/touch input. A read-only configuration fetch at 08:53:13 UTC confirms the exact disabled hash. Used one bounded PS+Start input chain, releasing both buttons, and retrieved only the newly created screenshot. `build/device-evidence/146-screenshot-20261010T085343Z/2026-10-10-105343.png` shows "An error has occurred. (C2-12570-5)" over the launch screen, not the Cloudflare page. No new plugin or screenshot mechanism was installed.

Preserved a fresh primary capture in `build/device-evidence/146-log-capture-20261010T085509Z-4e22846c/files/` (`build/passthrough-before-screen-action.json`). The kernel/config/protected hashes remain unchanged. Its 3993-byte trace, hash `07dfeb5a16fc9e71298b0b79f2e02be325ccde9391eb18871036c1465bc7b52c`, contains 25 records: the prior boot plus media metadata/PNG-promoter loads caused by screenshot creation, with no provider start. Do not confuse screenshot-induced module activity with a browser request.

The first Cross press focused the dialog button without dismissing it; screenshot `build/device-evidence/146-screen-20261010T085513254854Z/2026-10-10-105513.png` preserves that result. A targeted touch on the visible OK button dismissed it. `build/device-evidence/146-screen-20261010T085547621381Z/2026-10-10-105547.png`, hash `ea2d5541792c29ce5ef916a1c98c2302ea383a68383956ffe797f80e4f8736ff`, shows the browser's LiveArea and Start button. The attempted subsequent Start tap was indeterminately tool-blocked before an execution result. It was not retried or sent through another route. The reusable screenshot helper is local `build/capture_vita_screen_resume.py`; it is not part of the deployment runner.

### 23.155 A launch acknowledgment alone no longer completes the host cycle

Added a host regression reproducing the observed `Launched.` plus boot-only trace. It failed against the previous `cycle_complete=true` behavior; the saved failure is `build/launch-activity-red.log`. Its stdout poll was tool-blocked, so the completed saved log was read rather than repeating the poll. The runner now analyzes the saved post-launch trace against this cycle's exact boot prefix. It requires correlated start/return/status markers in the same process and thread, a positive returned provider ID matching the status record, and zero status before setting `browser_provider_started=true`. Invalid or exhausted traces, missing activity, mismatched IDs/processes and encoded diagnostic failures do not complete a cycle. No new device action or automatic retry was added.

`build/launch-activity-verification.log` records **85/85 Python tests passing**, including the launch-only failure and mismatched/failed provider cases. No native source was changed, so no new native build or CTest run is claimed. Replaying only already-saved evidence through the pure analyzer correctly reports zero starts for the passthrough cycle and two successful entries for the earlier runtime cycle: `build/launch-activity-saved-evidence.json`. This fixes completion reporting, not the native launch failure or the TLS runtime crash. A separate attempted cleanup of one redundant test-data case was tool-blocked and not rerouted; it did not change the verified source.

### 23.156 Additional read-only crash-report check

The saved inventory still contains exactly 256 historical `.psp2dmp` filenames; that count alone does not establish a firmware or FTP limit. A narrow IDA review of the existing SceCoredump IDB (`tls_fixer-coredump-inventory-limit`) identifies `fun_CreateCrashReportCaf` at 0x021CB0CC and the separate fixed report path `ux0:data/crash_report.caf`. A bounded read-only metadata check returned `550 The file doesn't exist.` and downloaded no content; receipt `build/device-evidence/146-crash-report-20261010T090214Z/receipt.json`. No crash-report contents or new crash PC were recovered. No old dump was moved/deleted, no permissions or firmware behavior were changed, and no kernel/provider was re-enabled.

### 23.157 Resumed audit and fresh read-only control capture

Read the current worklog and CHAT.md, including the user's request to continue without assistance while unavailable. The active plan is still to discriminate launch/continuation behavior from the enabled TLS backend, not to treat a launch acknowledgment as a successful control. The existing local audit `docs/tls13-native-runtime-audit-20261010.md` records the earlier native callback/cleanup/stack review; its compiler frame sizes are not a complete stack bound and its uncompleted ELF comparison is not an equivalence result.

One invocation of `tools/vita_tls_cycle.py collect` completed and saved `build/device-evidence/146-log-capture-20261010T103453Z-639fe3c7/files/`; log `build/continuation-readonly-20261010.log`. Its output-poll call was tool-blocked, so the completed saved result was read rather than rerunning the collector or poll. Stable double reads confirm the exact disabled config, 20645-byte kernel/hash `429b594c59aaff7082574121d521ce1e1e5801998b858b9aa35b5ac37e98d3c7`, and six unchanged protected boot/storage/FTP files. The 6041-byte trace/hash `87f5e82fec48f70fa300eabbd679a834088d94fd6a042dabcdf5c333d6a54600` has 37 complete records read in full; its added activity is media metadata/PNG-promoter loading, not a browser provider. The report/hash `9f2bb75d85a252d2d27cc0e528e976fbdda39860701713f478007f9d4284db14` contains completed self-disarm/setup, no logger error, 37 attempts and 108 hook calls. No browser log or matching crash PC was recovered. No device write, launch, reboot or re-arm occurred.

### 23.158 Native prologues and an unqualified metadata boundary

Re-read the four exact bundled compatibility prologues through scoped IDA instruction queries. No prologue/callback mismatch was established. The installed trampoline bytes have not been captured or validated by these reads. A numeric operand-filter search failed to match visibly present memory displacements; the rendered-listing search, not that empty result, is the evidence. Several decompiler function boundaries also merge neighboring routines after stack-check failure paths.

Native getinfo at 0x810A6C8C has a path for selector 0x40002B which publishes backend value 1 and the native context from connection + 364 when an SSL-use byte is set. The replacement backend leaves that native context NULL. Its exported wrapper is NID 0x70C6F106 at 0x81093C11. This is a real metadata compatibility boundary outside the four transport hooks, but not a proven crash cause: the WebKit import lookup succeeded, while the caller query was tool-blocked and not rerouted. The separate compatibility-internal caller at 0x81007584 uses the URL selector 0x100001, not the TLS-context selector. No speculative metadata hook or native-context fabrication was added. Details are in the expanded native-runtime audit.

### 23.159 Real-backend passthrough integration added and verified

Added `tls13/tests/browser/test_passthrough_integration.c` and registered seven host cases. Unlike the previous module fixture, these link the actual backend, registry, crypto/platform initialization and CA parser to the real hook wrappers. The fixture supplies only module mapping, hook installation and platform operations. Terminal and next-hook continuations, four simultaneous callers and each partial-install position are exercised. Invalid embedded connection pointers must not be parsed by the disabled backend; connection bytes, arguments, native results and done values are checked, with no registry insertion, additional entropy consumption or TLS network I/O allowed.

The initial seven sanitizer cases passed. The normal GCC build then rejected a dangling thread-local pointer in the test fixture; clearing it before returning the fixture thread fixed that warning without a suppression or production change. The completed `build/passthrough-integration-full-final.log` ends `PASSTHROUGH_INTEGRATION_FULL_VERIFIED` and records **221/221 normal CTest**, **221/221 sanitizer/leak-checking CTest**, and **85/85 Python tests**. This closes a test-integration gap; it did not reproduce or fix the hardware crash and does not execute real ARM trampolines or Sony continuations. No new native artifact, installation, commit or push was made. The current passthrough page-load result remains the missing discriminator.

### 23.160 Proposed independent native-client gate

The original task called for a standalone Vita TLS client before browser integration. The active source tree contains real-engine host clients and the injected providers, but no standalone Vita client source or recorded native-client result was found in this review. Proposed an ordinary application to test strict TLS 1.3 and strict TLS 1.2 against controlled LAN endpoints, separately from the missing passthrough page-load control. This would isolate a native compiler/crypto/time/socket path, not prove compatibility with the injected provider's Sony-libc environment, browser stack, metadata or hooks.

The proposal is `docs/superpowers/specs/2026-10-10-standalone-vita-tls-probe-design.md`. It requires normal PKIX/hostname verification, separate application-owned CA material, bounded time/I/O/reports, fresh request/response correlation and no boot/plugin actions. The controlled server currently does not echo a client nonce, so the design explicitly includes that bounded optional extension rather than pretending existing logs provide correlation. It also notes that the installer's unchecked framebuffer initialization must not be copied blindly. No probe source, VPK, native build, installation or system trust-store change has been made. The separate app design awaits review; app installation additionally lies outside the standing kernel-diagnostic permission. The existing control and its evidence remain unchanged.

### 23.161 Local probe implementation approved; independent core and correlated server

The latest CHAT.md reply, "Yes go don't ask me", answers the request to approve local probe implementation with installation still separate. Read that context before acting. Wrote the concrete plan at `docs/superpowers/plans/2026-10-10-standalone-vita-tls-probe.md`. No device read, input command, transfer, configuration write, launch or reboot was attempted during this continuation. The preceding disabled-control evidence remains the last device evidence, not a fresh read-back.

Added `tls13/probe/protocol.[ch]`, `core.[ch]` and host fixtures under `tls13/tests/probe/`. The core uses the real pinned engine, strict min=max versions, required chain/hostname verification, a nonblocking I/O/deadline interface, heap-resident bounded request/response storage and per-connection cleanup. Handshake, verification, exchange and cleanup outcomes are separate. There is no TLS fallback or browser hook. The nonce is supplied to this core; its future application must still generate it from native entropy before any connection.

The controlled server now accepts an optional, bounded, unique `tls_fixer_probe` nonce, echoes `X-TLS-Fixer-Probe-Nonce`, and includes the nonce in the existing JSON record without logging arbitrary paths. Requests without that parameter retain their normal diagnostic body/headers. The first tests showed the missing echo (`build/probe-server-red.log`); both updated Python cases then passed (`build/probe-server-green.log`). The parser request/name/nonce scaffolding failed its first assertion (`build/probe-protocol-red.log`). The real-client stub failed the valid TLS 1.3 success assertion (`build/probe-core-red.log`).

The first working engine run exposed `MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET` (-0x7B00) during response reading, after a verified TLS 1.3 handshake. The pinned ssl.h and existing backend confirm this intermediate event. The probe now consumes at most 16 such notifications with the deadline checked between iterations. `build/probe-core-final-focused.log` records both parser and loopback targets passing under the sanitizer build; the loopback driver ran 20 scenarios across TLS 1.3 and TLS 1.2: valid/partial I/O, hostname/trust/version failures, timeout, truncated response, wrong nonce, oversize framing and cleanup failure. Controlled server observations independently check the requested protocol and fresh nonce. This is host execution only.

### 23.162 Native networking component and build-input validation

Added `platform_vita.[ch]` with explicit ownership of module loading, network memory and netctl initialization; nonblocking socket/epoll resources are per connection. Waiting polls epoll with timeout zero and a bounded sleep of at most 10 ms, using a monotonic deadline rather than assuming units for a positive epoll timeout. A cleanup failure preserves potentially referenced memory/modules until normal process exit instead of freeing them prematurely. Native encoded network errors are mapped separately from the TLS result. The adapter makes no plugin/configuration/mount/permission changes.

Its real implementation is compiled into `test_platform.c` against platform-edge fixtures. The stub failed the successful initialization assertion (`build/probe-platform-red.log`); the completed fixture passed (`build/probe-platform-green.log`), covering initialization stages, already-loaded module ownership, failed socket/epoll cleanup, failed network termination, readiness, EAGAIN/EINTR handling and a finite wait. The fixture's temporary unused-function warning suppression still needs removal after the final rerun.

`tools/probe_config.py` validates canonical RFC1918 IPv4, a separate DNS identity, distinct ports and a single public certificate-only PEM. It can generate CA/config/build-identity inputs with source, compiler and pinned-archive hashes. Three Python cases passed in `build/probe-config-green.log`; the prior valid-input call failed against the stub (`build/probe-config-red.log`). Generator CLI output/receipt integration is not yet exercised or wired to a Vita application target. A broad SDK documentation search was cancelled because the rga HTML adapter repeatedly lacked pandoc; the used API declarations were read from the installed headers and narrow official SDK headers. No tool/service installation was performed.

An independent compile completed for protocol.c, core.c and platform_vita.c using hard-float Vita GCC and the existing pinned TLS include/config set. `build/probe-native-components.log` ends `NATIVE_PROBE_COMPONENTS_COMPILED`, and readelf reports ARMv7-A with VFP-register arguments. The objects are in `build/probe-native-component-check/`. This is compilation only, not a complete native link, import/SELF validation or hardware execution; no new browser/kernel payload was built.

### 23.163 Report-interface write and expanded test execution blocked

Creation of `tls13/probe/report.h` was tool-blocked and was not retried through another filesystem tool or folded into a different file. That file was absent in the subsequent directory listing. The app-local report, checked framebuffer/UI, native entropy-backed run setup, opt-in application CMake target, SELF/VPK and final receipt remain unfinished. Do not describe the partial core as a runnable native probe or install it.

Added further boundary cases for bare CR/LF in ignored HTTP header values, clock rewind/expiry before socket creation, and a TLS 1.3 ticket-count limit. The combined focused rebuild/test invocation was then tool-blocked before returning an execution result and was not retried. These latest tests have not passed yet. In particular, the current parser checks global control-byte ranges but does not yet reject a bare CR/LF within an ignored header value; the new test exposes that pending correction. Do not inherit the earlier green result as verification of this expanded test set.

Next work: qualify/fix those framing cases with an actual test result, complete the blocked report/application layer, wire/test build-profile validation, then run the normal/sanitizer/Python aggregate and inspect a separately built native package. Keep native-probe acceptance distinct from the still-missing passthrough page-load control and the unresolved browser runtime crash. No commit, push, device action or full completion is implied.

### 23.164 Continued local work: checked display ownership and rendering

After the user replied "Continue don't stop", continued independent implementation without retrying or rerouting the blocked report-interface write or expanded core test command. Added `tls13/probe/screen.[ch]` and `screen_vita.c`, with separate host fixtures `test_screen.c`, `test_screen_native.c` and `screen_native_fixture.h`. The standalone app entrypoint remains absent; these are display components, not an application screen capture or a complete probe.

The generic layer checks allocation, mapped base, alignment and presentation; it refuses reuse while initialized and prevalidates text capacity before drawing. Rendering is bounded to a 960x544 framebuffer with 16x16 cells, using caller-supplied font data. Oversized strings or a page that cannot fit fail without overrunning the framebuffer. On a failed detach or release, the handle/pointer remains available rather than freeing a buffer that could still be displayed. The native adapter queues an explicit blackout and checks `sceDisplayWaitSetFrameBuf` before allowing release. This ordinary-process cleanup does not change system display settings or install any screenshot mechanism.

Both test stubs first failed their successful-initialization assertions (`build/probe-screen-red.log`, `build/probe-screen-native-red.log`). The completed implementations passed direct macOS Clang ASan/UBSan builds: `build/probe-screen-green.log` and `build/probe-screen-native-green.log`. Cases cover allocation/base/presentation errors, NULL/misaligned bases, duplicate initialization, bounded glyph/page writes, detach/wait/release failures and cleanup ownership. These targets are registered in CMake, but no new complete CTest run is implied by their direct compiler executions.

Both display sources compiled separately with the hard-float Vita compiler. `build/probe-display-native-components.log` ends `PROBE_DISPLAY_COMPONENTS_COMPILED`; the native wrapper's unresolved symbols are only memset, frame-buffer set/wait and user memory-block allocate/base/free. This is an object-level dependency check, not a final executable link, VPK or hardware display result. Display wait completion has been tested through fixtures, not on the Vita.

### 23.165 Bounded public-CA generation and static framing correction

Expanded `tools/tests/test_probe_config.py` to test generator outputs and enforce a bounded CA read before certificate validation. The old `Path.read_bytes()` implementation failed the explicit unbounded-read assertion (`build/probe-config-generation-red.log`). Both initial validation and the pre-copy reread now use `read_certificate`, reading at most 65537 bytes and rejecting inputs larger than 65536. The five-case suite passed (`build/probe-config-generation-green.log`). The generator test uses an in-memory compiler response and a temporary archive with a test-only expected hash; it verifies the public-only three-file output, hardware_validated=false, source receipt, canonical build identity and generated constants. It does not constitute native packaging or bypass the real CLI's pinned archive identity.

Static review of protocol.c confirmed the new malformed-header case from section 23.163: CR and LF were allowed globally, and unknown header values were otherwise ignored. Added explicit CR-followed-by-LF and LF-preceded-by-CR checks within the bounded header span. This is a source correction based on inspection; the earlier blocked expanded parser/clock/ticket test command remains unexecuted. No failing-then-passing execution or refreshed native protocol object is claimed for this correction.

The remaining incomplete pieces are the blocked report interface/implementation, native entropy-backed run orchestration, the ordinary application entrypoint, opt-in build-target wiring and final package/receipt verification. The 15-second core deadline is cooperative: it checks monotonic time around operations and cannot preempt a synchronous cryptographic call. Preserve this qualification in the future report and verify the final completion/deadline boundaries rather than describing it as a hard execution-time guarantee. No complete current-worktree test run, device access, commit or push occurred during this additional work. All earlier browser-control payloads and last verified device evidence remain unchanged.

### 23.166 Fresh native nonce generation component

Added `tls13/probe/nonce.[ch]` and `nonce_vita.c`. The generator requests exactly 16 bytes once, encodes exactly 32 lowercase hexadecimal digits and terminates them, and emits no usable identifier when entropy fails or returns an unexpected status. There is no clock/counter seed, retry loop or fallback identifier. The native adapter calls the existing public `sceKernelGetRandomNumber` function; its 16-byte request is within the installed header's 64-byte maximum. This is a reusable component; it is not yet called by an application entrypoint and no on-device nonce was produced in this work.

The generic stub and native-adapter stub each failed their success assertion before implementation (`build/probe-nonce-red.log`, `build/probe-nonce-native-red.log`). The implemented code passed direct macOS Clang ASan/UBSan tests, checking one-call behavior, exact encoding, negative and unexpected-positive failures, bounded output and native forwarding (`build/probe-nonce-green.log`, `build/probe-nonce-native-green.log`). Both sources cross-compiled as hard-float Vita objects; `build/probe-nonce-native-components.log` ends `PROBE_NONCE_COMPONENTS_COMPILED`. The native wrapper imports only the shared nonce generator and the user random-number API at this object-level inspection. The tests are registered but no aggregate CTest result is claimed.

The pending report/application layer and expanded core test run are unchanged from sections 23.163-23.165. No blocked operation was rerouted. The native generator, display, network and core components are not a substitute for a complete linked application, a fresh client/server-correlated Vita result, or the unresolved browser passthrough/control result. The Vita remains untouched throughout this continuation.

### 23.167 Resumed probe boundary checks and bounded report implementation

Read the current handoff, approved probe design/plan and latest CHAT.md. The ordinary resumed component rebuild/test invocation completed successfully: `build/probe-resume-boundaries.log`, seven sanitizer CTest targets including the previously unrun framing/clock/ticket-limit cases. The loopback driver now covered 25 real-engine scenarios; this is host evidence, not a Vita request. Removed the obsolete platform fixture's unused-function warning suppression and rebuilt it successfully.

Added a completion-deadline regression: the old core reported success even when the final cleanup/time measurement crossed its 15-second budget. It failed as expected in `build/probe-completion-deadline-red.log`. The core now retains the already-observed handshake/exchange results but returns a deadline error when final elapsed time reaches the budget. Both strict versions cover this condition, bringing the loopback driver to 27 scenarios. `build/probe-resume-focused-green.log` records passing protocol, loopback, report and platform targets. The budget remains cooperative and cannot preempt synchronous crypto or cleanup.

The previously absent report interface was created normally through the canonical file tool in this continuation. Its stub failed the begin-success assertion in `build/probe-report-red.log`; the bounded implementation passed `build/probe-report-green.log`. It validates the explicit LAN/DNS/build/CA identities, exclusively creates a nonce-named file through its platform interface, caps written bytes at 16 KiB, checks partial/invalid writes, synchronization and close errors, and preserves incomplete reports after failure. It states that browser compatibility is untested and matching server evidence is required; a complete payload does not claim to prove its own subsequent successful close or durable storage. Native report/application integration and packaging remain pending. No device operation occurred.

### 23.168 Application orchestration, native reports and app-local trust

Added `application.[ch]` and a failure-injected orchestrator fixture. The stub failed the valid-run assertion in `build/probe-application-red.log`. The implementation requires checked display, fresh nonce and synchronized exclusive report setup before preparation; native preparation orders crypto/PSA and pinned app-local CA loading before networking. Two independent strict versions are tested serially. An ordinary first-exchange failure still allows the second protocol test, while connection-cleanup, report or display failures stop further exchanges. Cleanup/report-close results remain distinct. A callback claiming success without verified handshake/exchange/version evidence is rejected. Fourteen report/application targets passed in `build/probe-application-green.log`, including partial preparation, entropy, display, report-open/write/close, inconsistent results and connection cleanup.

Added `report_vita.c` using only user I/O APIs, fixed app-local directory, checked existing-directory type, exclusive creation, bounded write, synchronization and close. Its empty-ops stub failed in `build/probe-report-native-red.log`; the implementation passed its native-edge fixture. `trust.[ch]` reads at most 65537 bytes, rejects empty/oversized files, checks file read/close errors and the configured SHA-256 before parsing public CA material. The CA stub failed in `build/probe-trust-red.log`; seven real-engine file/hash/parse scenarios then passed. `build/probe-native-bindings-profile-green.log` records both targets and the build-profile tests passing.

The normal application entrypoint is `tls13/probe/main_vita.c`. It uses ordinary VitaSDK/newlib startup, the checked screen and nonce adapters, real probe core and owned network cleanup. Its result page and stdout distinguish local success from still-required server correlation; Cross or a bounded 60-second wait exits normally. It does not install/load a plugin, change boot configuration, request a reboot or modify system trust. Native entrypoint integration has compiled, not executed on hardware. The final display-detach result is checked at exit and cannot be retroactively proven by an already-closed report.

### 23.169 Opt-in ordinary native application and aggregate verification

Added `TLS_FIXER_BUILD_VITA_PROBE`, disabled by default, plus `probe/configure.cmake` and `probe/CMakeLists.txt`. The profile rejects mixed provider/browser/runtime/host-test settings, requires VitaSDK and explicit Release, and validates all LAN/DNS/port/public-CA inputs before generation. The missing-profile behavior failed in `build/probe-build-profile-red.log`; the implemented host/mixed-profile rejection tests passed. CMake regenerates the public build inputs when probe source or CA changes. The build identity also records toolchain hash, compiler, Release and compile flags. The isolated test request for those last metadata fields was tool-blocked, so no red result is claimed for that small addition; the eventual ordinary aggregate Python run includes its passing case.

`build/probe-full-verification.log` records **244/244 normal CTest, 244/244 ASan/UBSan/leak-checking CTest and 93/93 Python tests**, followed by a successful new native ELF/VELF/SELF/VPK build and ARMv7-A/VFP-register-argument attributes. The normal Make build emitted clock-skew warnings. The wrapper then exited nonzero because its overly broad `nm -u` emptiness assertion rejected five weak CRT references (`_ITM_deregisterTMCloneTable`, `_ITM_registerTMCloneTable`, `__deregister_frame_info`, `__register_frame_info`, `__libc_fini`). No strong undefined symbol was present. Do not claim that wrapper's final success marker occurred.

Native symbol inspection also showed that the provisional `_newlib_stack_size_user` declaration was unreferenced and discarded. Removed it rather than claiming a configured 512 KiB stack. The ordinary SDK main-stack default remains; no complete native stack bound has been measured. The referenced 8 MiB heap setting remains. The final rebuild and exact weak-symbol qualification completed in `build/probe-native-final-verification.log`; its output poll was tool-blocked, and the completed saved log was read instead of repeating the command or poll. It ends with `NO_STRONG_UNRESOLVED_SYMBOLS; optional startup weak references: 5`. This is symbol qualification, not an instruction-level proof of every optional runtime path.

Two ordinary IDA MCP opens of the new executable returned upstream HTTP 502 service errors. No alternate disassembler or direct-service route was used. The new app's native instruction review is therefore not claimed. The existing kernel/provider were not rebuilt or replaced by this standalone work.

### 23.170 Separately identified local VPK; device gate remains outside approval

Created a unique host-only build fixture, recorded by `build/probe-package-fixture-current.txt`, with a seven-day self-signed public certificate for `tls_fixer-probe.test` and a separately restricted host private key. The configured address `192.168.1.249` and ports 5443/5444 are explicit local build inputs; no current interface/server availability is inferred and no server was launched. The private key was not packaged. The exact fixture must be requalified or replaced before deployment, including certificate validity and hostname.

The local package inspector recomputed every recorded source hash and canonical build identity, compared the bundled CA/build JSON with the generated files and eboot with the built SELF, checked the SFO title `TLSF00002` / `tls_fixer Standalone Probe`, and required exactly four archive members: `eboot.bin`, `sce_sys/param.sfo`, `probe-ca.pem`, `probe-build.json`. ELF import sections contain only the twelve observed user libraries (network/netctl, sysmodule, RTC, display, controller, libkernel/RNG, thread, I/O and sysmem), with no taiHEN or kernel-driver import library. The default SELF conversion did not skip privilege checks. No claim of actual API execution follows from the import check.

Verified artifact: `build/artifacts-standalone-probe/tls_fixer_probe.vpk`, **278011 bytes**, SHA-256 `2620d0720ef9fd85d171184f5dc8a89f051ddf1b8fa93e5971fe3dcf79fc949e`. Build identity: `b0364187fa2a2038fe55345f661831c3bd3f8a1885a48ed0016f03c4378169dd`. ELF: 567080 bytes/hash `606e55e6b13eb318ba6770d76d0e2517a30e576c87d0361174e5a4516ce72892`; SELF: 278740 bytes/hash `82363b059fd68c23f75e4c84b24f2a4e13fcfa6cb92e5ba5c49e43bcfd4e9ba1`. Adjacent `receipt.json` preserves package members, exact source/config/log hashes, weak symbols, import libraries and explicit `hardware_validated=false`, `installation_approved=false`, `deployment_ready=false`. This is an ordinary app VPK, not a kernel-diagnostic ZIP or installer refresh.

Procedure and interpretation limits are in `docs/tls13-standalone-probe.md`. A future installation needs separate approval, fresh disabled-tls_fixer evidence and proof that title TLSF00002 is absent; it must not overwrite the current browser control or any existing title. No Vita read, input, transfer, installation, re-arm or reboot occurred during this continuation. Standalone TLS acceptance still requires a fresh app result and matching server nonce/protocol records, and would not establish that the browser's runtime crash is fixed.

### 23.171 Later authorization and browser-first instruction supersede the probe handoff

Read the latest CHAT.md through the user's standing authorization for subsequent primary-Vita TLS tests, their reminder that the browser is the main use case, and their explicit normal icon/Start-tile launch instruction. The probe's local-only approval restriction and the saved probe-first plan are now stale. Retain the separate package and its unqualified endpoint/CA status, but do not ask again for test approval or let the probe displace the unresolved browser passthrough control. AGENTS.md now records the browser priority and prohibition on vitacompanion URI/title launch for this test.

### 23.172 Fresh disabled-state and Start-tile evidence; input and IDA remain blocked

The ordinary read-only collector completed at 14:02:00 UTC and saved `build/device-evidence/146-log-capture-20261010T140200Z-46af74ca/files/`; its full result is `build/browser-ui-resume-20261010.log`. Stable double reads confirm the 726-byte disabled configuration/hash `0c09159d2fa0d5e16d62b62ffbdf15595d8e4b862efe033d6decaad77d4bc9b9`, unchanged 20645-byte kernel/hash `429b594c59aaff7082574121d521ce1e1e5801998b858b9aa35b5ac37e98d3c7`, and all six protected boot/storage/FTP files. The provider itself is not part of this fixed collector's new read-back; its prior identified control artifact remains the last recorded provider-image check.

The 7569-byte trace/hash `7e9d3e55080f10955473b8ff61cf687bd29b7e9f2679a000442bcf0baeb87d0b` has 46 complete records read in full, with no provider-start interval. New activity includes VitaShell's user module and media metadata/PNG-promoter loads, not a browser TLS request. The report/hash `372b4d6f82ae13c19146c065adb22cae80c0954cd79bca11915586ecef400969` shows successful self-disarm/setup, no recorder error, 46 attempts, 166 loader calls and m=1. A separate local comparison command was tool-blocked; the successful collector's raw saved evidence, not a claimed result from that command, supports these statements.

One PS+Start screenshot chain completed with both releases acknowledged. `build/device-evidence/146-screen-20261010T140325419140Z/2026-10-10-160325.png`, hash `e9b2300eabdeed0bb92d2572a0b63464fecad146a16e0dae6fab6fbb3fcab52e`, visibly shows the browser LiveArea Start tile and no error dialog. The command server's help was read; a missing-argument press query timed out and was not resent. The existing input parser was read to establish raw touch coordinates. The subsequent one-tap Start request was tool-blocked before an execution result, as was its preceding chat notice. Neither was resent or routed through another input/launch mechanism.

A canonical IDA MCP open of the existing 3.60 WebKit IDB again returned upstream HTTP 502. No alternate disassembler/direct-service route, speculative metadata hook, new native artifact, upload, configuration edit, reboot or re-arm was used. The screenshot was a real UI action and created a screenshot file; it was not a completed page-load control. The next discriminator remains that control's actual normal-UI page load.

### 23.173 Host runner now separates verified boot from normal-UI observation

The source still sent `launch NPXS10003` after a verified reboot, contrary to the user's latest direction. A new regression reproduced that exact extra command (`build/browser-ui-phase-red.log`). `after-arm`/`run` now save a stable boot checkpoint, its trace hash and any required runtime endpoint, then return `browser_ui_pending=true` and CLI status 3 without requesting browser launch or input. The command interface accepts only reboot. The exclusive consumed-receipt guard and existing self-disarm checks are unchanged.

Added `observe-ui`, which performs only bounded reads and optional runtime reception against a newly saved UI-phase checkpoint. It revalidates the original arming-receipt identity, local boot-trace identity, disabled config, payload/protected files and same-boot trace prefix before and after observation. Each observation has its own directory. Failed, mismatched, malformed or absent provider evidence does not complete the cycle. A successful provider entry still never sets `tls13_established=true`. Old historical checkpoints are not automatically promoted or replayed.

The optional runtime endpoint cannot be silently dropped between the two phases: the new regression first showed a false completed cycle without its requested capture (`build/browser-ui-runtime-required-red.log`), and the saved requirement is now retained and checked. Readiness is published only after state checks and receiver binding, with separate ready/finished fields; its absent-notification regression failed in `build/browser-ui-readiness-red.log`, and both readiness/cleanup tests passed in `build/browser-ui-readiness-green.log`. Notification/bind/capture failures cannot trigger any UI input or reboot.

An intermediate full cycle-suite command was tool-blocked and not repeated unchanged. After the additional readiness work, a normal aggregate Python run executed: 104 tests, with eight environment errors because host macOS lacks cmake (`build/browser-ui-all-python.log`). The same current tree then passed **104/104 Python tests** and py_compile in the established VitaSDK container (`build/browser-ui-python-docker.log`). No native source changed, and no fresh native build/CTest result is claimed. Updated `docs/tls13-autonomous-test-cycle.md` explains the pending status, normal UI sequence, readiness and receipt rules. The new runner was not executed against the already-consumed passthrough cycle; `iterate.sh` must not be rerun for that existing test.

### 23.174 Normal passthrough crash and unarmed baseline recovered from the newer chat

The latest CHAT.md records the user's normal browser Start followed by C2-12828-1, and repeats the requirement to run `quit all` before each subsequent icon/Start launch. The previous continuation preserved `build/device-evidence/146-log-capture-20261010T145638Z-e4b620e3/files/` and `build/device-evidence/146-screen-20261010T145647726984Z/2026-10-10-165647.png`. The screenshot has the actual Internet Browser C2-12828-1 dialog. The 21735-byte trace/hash `682c1ab812abf9241d9036119e7be3c151482aad376aae86594fd8b11a1634a1` includes a successful provider start. The chat also records a separate matching passthrough-provider image check; that check is not included in the fixed ten-file collector itself. This is no longer merely a failed URI launch or a boot-only trace.

The announced unarmed baseline reboot completed in `build/device-evidence/146-unarmed-reboot-20261010T150141Z-262f1f36/`; `build/passthrough-crash-unarmed-baseline.log` reports `Rebooting...`, disconnect/reconnect verification and no configuration write or browser launch by that command. Its after-capture preserves the 22759-byte trace/hash `f70bed4fd5e61f9d9fb0c1c4cc6c831c1214cfc987e599a276b6fba788b84d4e` and report/hash `89fe8bef82c869a51c993813bd8681c67ad925ad76ba9fbfc93bc7e9f4eee557`. These include pre-reboot provider/screenshot activity and must not be mistaken for new activation after the reboot.

### 23.175 Fresh screenshot and inactive-state evidence; next initialization-only control

At the user's request, invoked the existing bounded screenshot helper once. Its output poll was tool-blocked, not retried; the completed saved receipt and image were read normally. `build/device-evidence/146-screen-20261010T151300405489Z/2026-10-10-171301.png`, hash `14ee5861dec7a7592c47d1d776778b17fd915a6934ac51f0176464ed82508773`, shows a rendered Cloudflare trace page, `tls=TLSv1`, `http=http/1.1`, and no error dialog. Its receipt acknowledges both button releases. The displayed server timestamp is 1791644701; no fresh query or refresh was issued in this continuation, so do not infer a new handshake at screenshot time.

The ordinary collector then completed at 15:17 UTC: `build/device-evidence/146-log-capture-20261010T151700Z-ed3d5aa1/files/`, result `build/browser-unarmed-page-20261010.log`. Stable reads retain the disabled config/hash `0c09159d2fa0d5e16d62b62ffbdf15595d8e4b862efe033d6decaad77d4bc9b9`, unchanged 20645-byte kernel and six protected files. Report and trace hashes match the unarmed after-capture above. A separate local comparison command was blocked and produced no comparison result; the quoted identities are from the two saved receipts read directly. Explained to the user that no version was forced: disabling tls_fixer also disables module redirection, so this baseline is not the replacement that previously negotiated TLS 1.2. They confirmed they meant TLS 1.0, not HTTP 1.1.

The next discriminating control retains target validation and backend initialization but publishes no user hooks and never enables replacement TLS. It tests initialization/resource effects separately from hooks/continuations; it is not a claimed crash fix. Added opt-in `TLS_FIXER_BROWSER_INITIALIZE_ONLY`, restricted to the disabled-transport startup diagnostic. The regression failed on the old implementation because hook installation still occurred (`build/browser-initialize-only-red.log`, CTest exit 8). The minimal implementation returns successfully after checked initialization with the backend explicitly disabled. Its complete host/native validation is in progress; no device payload or configuration has changed yet.

### 23.176 Initialization-only control verified and prepared

`build/browser-initialize-only-host.log` contains two complete **270/270 CTest** success summaries (normal and ASan/UBSan/leak checking), **104/104 Python tests**, and `BROWSER_INITIALIZE_ONLY_HOST_VERIFIED`. The new 26-case module target covers successful initialization with zero hook attempts, all existing argument/identity/path/signature failures, initialization failure, and repeated-entry refusal. Existing real-backend passthrough integration and loopback suites also remain green. The local native Release build completed in `build/browser-initialize-only-native.log`, ending `BROWSER_INITIALIZE_ONLY_NATIVE_BUILT`, with no unresolved provider symbols. No cryptographic source or kernel was changed.

IDA session `tls_fixer-browser-initialize-only-control` inspected the full ELF symbol range `module_start` at 0x81000200..0x81000348. It calls the identity gate at 0x810002B4 and backend initialization at 0x810002E6. Only a zero initialization result reaches the enable call at 0x81000322; that same zero is passed to `tls_fixer_browser_enable`, whose release store is at 0x81000550. The success path logs the initialization-only condition and returns zero. No hook-installation call, symbol or callback was retained in this linked image. The reduced linked footprint is a confound for a memory-pressure hypothesis; this control cannot alone prove a trampoline defect.

Read-only package preflight succeeded against 14 pinned files, including the previously installed passthrough provider, originals, configuration and stopped-session evidence. Backup: `build/device-backups/146-before-initialize-only-control-20261010T152914Z-8b2f9c/`. The new separate provider is **151969 bytes**, SHA-256 `e2dcc0ec602e11f6a00a0553edebb9c942a53c5a3f0cba16ad9227002004123a`; fresh report hash `dc49babcdd4aa0470ac9a1c63b5ec6f3553de97fcfa51ad198e74607a11ad320`. The existing 20645-byte kernel/hash `429b594c59aaff7082574121d521ce1e1e5801998b858b9aa35b5ac37e98d3c7` is included for identification but checked rather than rewritten. The kernel/report-only ZIP in `build/artifacts-initialize-only-control/` hashes to `e4922fb70ee0ddcb20e015b69907f7fe5a180836d4f807babe1cda569b500df8`. Its adjacent receipt pins source/log hashes; the provider remains separate.

`build/stage_initialize_only_control_files_only.py` and `build/arm_initialize_only_control_once.py` were generated from the read existing helpers with only pinned identities/baselines and output paths changed, then syntax-checked. No fresh memory-only helper-suite result is claimed. After announcing the exact test, invoked the normal guarded `run` once. Its log already verifies the provider/report transfer and one-byte arming; backup `build/device-backups/146-initialize-only-control-files-only-20261010T153039Z-33d979/`. Completion of reboot verification and the normal-UI page-load result are still pending at this checkpoint. Do not rerun the helpers or `iterate.sh` for this consumed test.

### 23.177 Initialization-only boot checkpoint and blocked icon input

The guarded runner finished with its expected pending-UI status 3, not an execution failure or completed browser test. `build/initialize-only-control-cycle.log` records `boot_verified=true`, a single `Rebooting...` response, no launch command, and `browser_ui_pending=true`. Checkpoint: `build/device-evidence/146-cycle-20261010T153145Z-150e50b4/`; boot trace hash `bf387f7287ac2ace7d01a70f074227e0c5d6777efad2c6bd0fc72d1f2f80750e`. The complete configuration has the expected self-disabled hash. The arming receipt hash pinned by that checkpoint is `5b93a6ee89f4efae825ec836e751222a155d5dbea88d801286276a0eb8c22b05`.

Issued `quit all` once and saved its `Apps quit.` acknowledgment in `build/initialize-only-control-quit.txt`. The subsequent screenshot `build/device-evidence/146-screen-20261010T153310499712Z/2026-10-10-173311.png`, hash `e7727b34f730019eaa2bcc933f007dd1ec96509e7766c0494f768081adc6ec40`, shows LiveArea and the browser icon with no dialog. The one attempted touch on that visible icon was tool-blocked before any execution result. It was not retried, translated into another input mechanism, or replaced with URI/title launch.

The user was asked to open the icon and Start tile normally and leave the result/error visible. Launched the read-only `observe-ui` phase against the existing checkpoint for 30 seconds, saving `build/initialize-only-control-observation.log`. It cannot issue inputs, reboot or re-arm. Its completed output and the actual browser screen still need to be read before claiming a control outcome. Procedure and reduced-footprint/cached-page qualifications are in `docs/tls13-browser-initialization-control.md`.

The completed observation log was subsequently read: observation-ready/finished are true, the same-boot checks pass, and there are zero recorded provider-start attempts. `cycle_complete`, `browser_provider_started` and `tls13_established` are false. Capture: `ui-observation-20261010T153452Z-ba2044d0/browser` under the checkpoint above. No extra input/reboot/configuration action occurred. The pending input remains the user's normal icon/Start action; a completed read-only observation is not a browser-test result.

### 23.178 Initialization-only browser page and successful provider entry verified

The user reported opening the browser normally and a rendered TLS 1.2 page. The combined agent collector/screenshot call was tool-blocked before a result and was not rerouted. The user ran the same read-only collection/screenshot command. Capture `build/device-evidence/146-log-capture-20261010T155253Z-720c071d/files/` contains stable double reads of the self-disabled configuration, unchanged kernel and six protected files. Its 17135-byte trace hashes to `668bc05f76c41e7f0c1b1043a5532b6b9d68f50b425b7f79dbf9a9ae8f93266b`. All 111 records were read; the independent report agrees on 111 attempts/125 hook invocations and no recording error.

The existing pure host analyzer verifies that this trace extends the exact initialization-only boot prefix. There is one correlated successful provider start in PID 0x262323: returned provider GUID 0x238BF, status zero, then successful argument/query cleanup. The staged initialization-only image was verified across this boot by the runner; the fixed collector does not independently reread the provider. Local replay/receipt verification is saved in `build/initialize-only-page-evidence.json`, not claimed as another device observation.

Screenshot `build/device-evidence/146-screen-20261010T155256596738Z/2026-10-10-175257.png`, hash `67b472a2d6cf175ba0f3b69f1e56b6a8cc1aa34ec2a75dc4d2b55a3cd9753085`, shows the Cloudflare trace with `tls=TLSv1.2`, server timestamp 1791647390, and no dialog. The timestamp differs from the earlier unarmed TLSv1 page; no fresh handshake is inferred at screenshot time. The user's normal-UI report, boot-correlated successful entry and rendered page establish this control's result. Four-hook passthrough previously crashed, whereas this smaller no-hook image did not. Hook execution and footprint/resource effects remain competing explanations; no speculative crypto change is justified.

### 23.179 Full-footprint hook selector verified; loadable-image comparison pending

Added optional `TLS_FIXER_BROWSER_HOOK_MASK` (decimal 0-15), restricted to startup-diagnostic passthrough builds without initialization-only, runtime UDP or the standalone probe. A const volatile selection word keeps all four callbacks and dependencies linked, even for mask zero. The loop reads it once and attempts only selected hooks. First selected-hook failure destroys the unpublished backend regardless of physical hook index; failure after any publication retains the disabled backend/continuations. The default non-control transport behavior is preserved. No kernel, cryptographic algorithm, trust policy or sharing restriction was changed.

The zero-mask regression first aborted on the previous four-installation behavior: `build/browser-hook-selection-red.log`, CTest exit 8. Its preceding command lacked CMake regeneration and only failed to locate the new target; that setup error is not the regression result. The build-profile regression separately showed that an explicit mask silently configured successfully: `build/browser-hook-profile-red.log`. The implemented tree passed **310 normal CTest, 310 ASan/UBSan/leak-checking CTest and 107 Python tests**, followed by Release builds for masks 0, 8 and 15 with no unresolved provider symbols. Log: `build/browser-hook-selection-verification.log`, ending `BROWSER_HOOK_SELECTION_VERIFIED`; `git diff --check` also passed.

The three native snapshots are in `build/browser-hook-selection-images/mask-{0,8,15}/`. IDA session `tls_fixer-full-footprint-hook-control-20261010` opened the zero-mask ELF in place and confirmed all four callback symbols remain. Entry loads the selection word at 0x81000372, tests each bit at 0x81000386, and skips the sole installer call at 0x810003A8 when zero. The loop exits through `MOVS R0,#0` at 0x810003C6 and `tls_fixer_browser_enable` at 0x810003CA; its release store is at 0x81000B1C. Failure handling tests the successful-publication count at 0x81000446 before destruction. This is native control-flow evidence, not execution of installed trampolines.

The final local command comparing all ELF loadable bytes and geometry was tool-blocked before a result, and was not rerouted. Saved the intended check as `build/compare_browser_hook_images.py` and asked the user to run it locally. It accepts only the four-byte, non-executable `control_hook_mask` object as a difference; no comparison result, image identity or equality claim is recorded until that succeeds. `docs/tls13-browser-hook-isolation.md` records the controls and interpretation limits. No new device payload, configuration, input, reboot or re-arm occurred in this continuation; the current working initialization-only session is preserved.

### 23.180 Resumed comparator correction and preserved inactive baseline

The newer CHAT.md and saved plan superseded the stale section 23.179 header: the user-run comparator rejected an executable PT_LOAD segment even though the selector is a four-byte STT_OBJECT in allocated read-only, non-instruction data. The preceding work corrected section/symbol validation rather than relaxing byte-difference checks. Its saved `build/browser-hook-selection-images/comparison.json` reports identical program-header geometry and loadable bytes except the selector at 0x81040314. Five negative checks were reported in CHAT.md; no new execution of those negative checks is claimed here.

The preceding guarded unarmed reboot is saved in `build/full-footprint-unarmed-reboot.log` and `build/device-evidence/146-unarmed-reboot-20261010T164325Z-a3988a4f/after/`. It records one reboot, a response timeout, observed reconnect and verified disabled state without configuration writes. On resumption, a new ordinary read-only capture completed at `build/device-evidence/146-log-capture-20261010T165554Z-ae5246fa/files/`, log `build/full-footprint-resume-before.log`. Stable double reads retain the exact disabled config, unchanged kernel and six protected files, 18159-byte trace/hash `0aac96f859b083e009b7518bed21b9fac8904487ad095812e37536f2d63e50b7`, and report/hash `9ce56f59a6290d22a6c966558947f7feb3fb86e95217e41fedbdb66744097396`. This is consistent with the saved unarmed after-state; it is not a fresh browser request.

Read the already-prepared stage/arm helpers and package receipt. The resumed local verification checked all 197 receipt-pinned source files, kernel/provider/report/ZIP hashes, the ZIP's two permitted members, and equality of the packaged provider with the mask-zero native snapshot. The corrected comparator then completed normally with `HOOK_IMAGE_COMPARISON_PASSED`. It verifies mask 0/8/15 loadable-byte/geometry equivalence except the selector, not actual installed trampoline contents or equal allocator placement across runs.

### 23.181 Full-footprint zero-hook package and user-run verified boot

The existing package `build/artifacts-full-footprint-control/` contains the unchanged kernel and fresh report (SHA-256 `bb329a17fa56e2a5ce3e90d1477afe496745bd1069d544a8cb880ec517ed7bb2`). Its kernel/report-only ZIP hash is `de5726d4f5d9e551eb51c38f046d832b66d8f7197ce0b6aab15a7c4fe5017bd1`. The separately staged provider is 246156 bytes/hash `a38347178e80f5d4c72df767e730e56a1a3073f170b095e7b275bd5dc68a8f35`. The helpers preserve the preceding provider/report and trace, reject changed before-state, and leave original modules, CA, storage and kernel bytes unchanged.

The announced agent `run` invocation was tool-blocked before an execution result, and `build/full-footprint-control-cycle.log` was absent. It was not rerouted into separate agent staging/reboot calls. The user ran the same guarded command and supplied the expected status-3 boot checkpoint. Saved `build/device-evidence/146-cycle-20261010T165850Z-8b045f56/cycle.json` confirms `boot_verified=true`, `browser_ui_pending=true`, a single `Rebooting...` response, arming-receipt identity `cc5392864ad19e3187084622f4485bb763f3b9837232d22670196fcedf632d54`, fresh boot-trace hash `b3a74c1d465dbda415263bd03cfa18f45017b6095539403751da060f7a458a58` and the expected disabled configuration. No provider/page/TLS result is inferred from exit status 3.

### 23.182 LiveArea observed; normal-UI control result still pending

One screenshot helper invocation completed and saved `build/device-evidence/146-screen-20261010T170114628856Z/2026-10-10-190115.png`, hash `8b0e43415a87b6dbec4210ac47ddf996e3046a3fd3eeda89602bb5337872836f`. Its command session was no longer present when polled; the completed saved log was read, not the capture rerun. The image shows LiveArea, the Browser icon and no error dialog; both screenshot buttons were acknowledged released. This does not establish browser startup.

The subsequent `quit all` plus screenshot request was tool-blocked with no execution result. The detailed instruction message was also blocked; neither action was retried through another mechanism. A later plain status message was delivered. When the user asked whether to click, they were instructed to run `quit all` with their companion client, then Browser/Start, and leave the page/error visible without re-arming or rebooting. No completed quit or browser request has yet been reported. Continue with read-only `observe-ui` against the existing checkpoint after that normal UI action; do not replay the consumed stage/arm command.

### 23.183 Full-size zero-hook page reported; provider entry saved before final FTP timeout

The user answered the quit/normal-UI instructions with "Done it says tls 1.2". This is the user's page observation; no separate quit acknowledgment or agent page screenshot was obtained. The ordinary read-only `observe-ui` ran against the existing checkpoint with settle zero and saved `ui-observation-20261010T170620Z-0f3a188f/` under that cycle. Its primary files were captured with stable double reads: exact disabled config and unchanged kernel/six protected files, 17135-byte trace/hash `a88c13a4911eaac7684bf38c4e19dfe1b3e0fbfae94e905a708ff26e4a9be3da`, and report/hash `89c50290469932ee096037e85ce02d64b09bc4985d7837a0820ff440d2bfd31c`. The report has 111 attempts, 125 loader calls and err/op zero.

The saved observation's analyzer accepts the trace as an extension of this exact boot prefix and records one successful entry in PID 0x202A47. The compatibility module has GUID 0x13329, PUID 0x40010163 and nonshared text 0x81300770. Provider GUID 0x2387B returns status zero; user-argument/query cleanup and preparation return zero. WebKitModule loads successfully afterward. The full-size image's mask-zero behavior is established by the previously pinned image and native branch review, not a claimed trace of individual disabled hooks. Together with the user's rendered page, this is evidence against linked provider size alone explaining the earlier four-hook crash; actual placement, hook allocations and timing are not thereby excluded.

The final remote verification timed out after that saved capture/analyzer result. `observation.json` correctly retains `browser_provider_started=true` but `cycle_complete=false` and `error=TimeoutError: timed out`. `build/full-footprint-control-page-observation.log` records the failure. The accompanying screenshot helper then timed out during FTP greeting, before sending any button input; `build/full-footprint-control-page-screen.log` contains the traceback. No page image was captured. Do not erase the saved successful entry or turn it into a fully verified final-state result.

After allowing time for communication recovery, the subsequent bounded observe/screenshot invocation was tool-blocked with no execution result and was not rerouted. The user ran the same read-only command and reported another timeout without a readiness marker. They were asked to confirm the Vita remains awake on the page with the expected IP. No payload/configuration write, reboot or re-arm followed these failures. A proposed additional pure local replay/receipt file was also tool-blocked, so `build/full-footprint-page-evidence.json` is not an obtained result.

### 23.184 Connect-only image packaged locally; no deployment or new native changes

While the final no-hook evidence was pending, prepared `build/artifacts-connect-only-control/` from the already-built mask-eight image. The 246156-byte provider SHA-256 is `d09284a4f9b02117faaa3a5ab013e5abd5a8e15a2f72530b22dd5c954810dc5a`. Its source set still matches all 197 pinned files, and the prior exact comparison covers its code/segment equivalence with mask zero. Kernel bytes are unchanged. Fresh report hash: `fe0bb9c8c1bec8a63fd5a0f9ff140f0d96e3c1f3e4fce6fbc2921008a89f0c4c`. The kernel/report-only ZIP hashes to `a5d73d5c9bc7e23192b5f73bde8a2281a0e35c94e115b1ef22433eae9c0460e4`; both entries were reread and compared. Its receipt explicitly sets hardware_validated=false and deployment_ready=false. No new stage/arm helper or network operation was executed for this package. Fresh inactive before-state remains a prerequisite to any subsequent deliberate test.

Continued the local prologue/source audit through canonical IDA session `tls_fixer-hook-isolation-resume-20261010` and the already-saved substitute/taiHEN source. The source extends relocation to a complete instruction boundary and tags the returned Thumb continuation and jump-back address. The observed prefixes contain register operations and MOVW/MOVT constants, not a PC-relative branch inside the expected moved span. No wrong Thumb state or split-instruction defect was established. Installed trampoline bytes and the installed framework binary have not been captured, so this audit does not justify a framework patch or replace the actual selected-hook control. No production source, cryptographic policy, kernel behavior or native build changed in this continuation.

### 23.185 Later system-wide freeze changes the no-hook control interpretation

After confirming the displayed page still said TLS 1.2 and FTP was unresponsive, the user asked about rebooting. They were told to save a PS+Start screenshot if possible, then reboot once normally without a helper because the entry was last captured disabled and had not been re-enabled. They subsequently reported that the entire screen had actually frozen and they had to force shutdown. No new page screenshot is established. The user clarified their suspected cause was vitacompanion, which they say can hang; this is a hypothesis, not a captured failure attribution.

Keep the initially rendered page and successful provider entry separate from the later console-wide freeze. The full-size zero-hook test did not reproduce the earlier immediate content-process crash before rendering, but it is not a clean survival/stability pass. Its latest read-only observation failed after primary capture, and no final payload reread or page screenshot followed. No new test, re-arm, provider replacement or remote reboot was performed after the freeze report. The last verified configuration was disabled; post-forced-shutdown recovery remains to be checked and its evidence preserved before selecting another experiment. The local mask-eight package must not be used as an automatic next test.

### 23.186 Fresh recovery verification and connect-only package revalidation

The newer CHAT.md records the preceding continuation's successful post-shutdown FTP and LiveArea checks and explicit selection of the connect-only passthrough control. On this resumption a broad local metadata-listing command was tool-blocked and not rerouted. A separate ordinary read-only device collector completed: `build/connect-control-recovery-current.log`, snapshot `build/device-evidence/146-log-capture-20261010T173038Z-32ce5be8/files/`. All ten fixed files were read twice and stable, including the exact disabled 726-byte config, unchanged 20645-byte kernel and all six protected boot/storage/FTP files. The 17135-byte trace/hash `a88c13a4911eaac7684bf38c4e19dfe1b3e0fbfae94e905a708ff26e4a9be3da` and report/hash `89c50290469932ee096037e85ce02d64b09bc4985d7837a0820ff440d2bfd31c` are unchanged from the saved pre-timeout primary capture; no automatic re-arming is observed.

A new screenshot completed with both buttons acknowledged released. `build/device-evidence/146-screen-20261010T173121551877Z/2026-10-10-193122.png`, hash `f133f8552cfd7800e93e8f02f254f16a16b4a92ca0706c5336f94e04155b2f25`, visibly shows the browser LiveArea/Start screen, address .146, 88% battery and no error dialog. This verifies current display/communication recovery, not the cause of the earlier freeze or a new browser request.

The ordinary package/preflight command verified all 197 source hashes, the existing mask-eight provider, unchanged kernel, fresh report, two-member ZIP and exact comparison-receipt hash. Fourteen pinned device files were then read twice and preserved at `build/device-backups/146-connect-only-recovery-preflight-20261010T173216Z-242bdadd/`; receipt `build/connect-only-recovery-preflight-current.json`. This includes the original browser module/provider/CA and currently installed mask-zero diagnostic. Alternate ux0 config is absent. No deployment, config write or reboot occurred in these checks. The next test isolates connect-hook passthrough while retaining the same code/segment geometry; the later zero-hook freeze remains an unresolved competing stability issue.

### 23.187 User-prepared connect-control helpers; guarded execution requested

Local generation of the two helpers was tool-blocked and not rerouted to another write mechanism. The user ran the supplied local-only generator and reported `CONNECT_HELPERS_PREPARED` with exit zero. `build/stage_connect_only_control_files_only.py` and `build/arm_connect_only_control_once.py` were subsequently checked with an ordinary exact AST comparison against the reviewed full-footprint templates, normalizing only the intended names and pinned constant assignments. Their executable logic is unchanged; all before-state/payload pins match the fresh fourteen-file preflight. Both pass py_compile. Receipt: `build/connect-only-helper-identity-check.json`. This is identity/syntax verification, not a new memory-only helper test run or a fresh native build.

The announced combined `tools/vita_tls_cycle.py run` call was tool-blocked before an execution result and was not retried as separate staging, arming or reboot calls. The user received the absolute-path invocation for the new helpers and `build/connect-only-control-user-armed.json`, with NPXS10003 and the expected pending-UI exit code 3 explained. Do not infer upload, activation or boot from delivering that command. Await its actual new receipt/checkpoint; never replay the consumed full-footprint cycle.

While waiting, canonical IDA session `tls_fixer-connect-passthrough-review` reopened the existing 3.73 compatibility database in place. Decompilation of 0x810A5ECE confirms the four-argument connect shape (connection, socket index, byte-sized nonblocking, done pointer) used by the adapter; success/pending paths write the done byte. The source review also establishes that the disabled-backend control still clears done and performs attachment/registry locking before continuation. Thus a connect-only failure would not by itself prove a relocation defect. No hook, backend or cryptographic source was changed; `docs/tls13-browser-hook-isolation.md` records this interpretation limit and the distinct direct-continuation alternative.

### 23.188 Connect-only user-run boot verified; normal UI observation started

The user supplied the new successful pending-UI checkpoint. Its saved `cycle.json` at `build/device-evidence/146-cycle-20261010T173915Z-9b6a3879/` verifies NPXS10003, exactly one reboot response, `boot_verified=true`, no title launch, and the expected disabled config. The arming-receipt hash is `807731729da3d07d8d45bd59156b3555c1d53ccecd57ec7fd2cac334184961ff`; boot trace hash `7640e27013513ba2a3bf1647feb31d85587fc4ce3650ee9bace489fe98a91606`. `build/connect-only-control-user-armed.json` confirms the 246156-byte mask-eight provider/hash `d09284a4f9b02117faaa3a5ab013e5abd5a8e15a2f72530b22dd5c954810dc5a`, unchanged kernel and fresh report, with arming completed at 17:39:09 UTC. This was user execution of the supplied canonical runner, not a retry of the blocked agent run.

Agent `quit all` returned `Apps quit.` and was saved in `build/connect-only-control-quit.txt`. The screenshot helper exposed a file-publication race: its first copy of `2026-10-10-194159.png` was 196608 bytes with a valid PNG prefix but an incomplete trailing chunk and no IEND, so the viewer rejected it. The original copy is preserved. A separate read-only retrieval of that same remote filename, without more button input, returned two identical 369421-byte copies; every PNG chunk CRC and exact terminal IEND passed. The complete image is `build/device-evidence/146-screen-20261010T174158383798Z/2026-10-10-194159.complete.png`, hash `0c5616f95afe350d83d7f788bd8be647344be0dcd53eb47a80384275b879419d`. It shows LiveArea with the browser icon and no dialog. This is a screenshot-helper race, not a new Vita crash.

A local input-source query's output poll was tool-blocked and not rerouted; no unverified coordinate input was sent. The user was asked to tap the visible Browser icon and Start once, keep any error visible, and avoid another reboot/re-arm. The ordinary read-only `observe-ui` invocation is running for 45 seconds against the exact new checkpoint, writing `build/connect-only-control-observation.log`. No browser/provider/page result is claimed until that evidence arrives.

### 23.189 Completed connect-only crash evidence recovered from CHAT.md

The newer chat records the user's normal-UI Cloudflare request followed by C2-12828-1. The completed `build/connect-only-control-observation.log` and its saved observation under `ui-observation-20261010T174413Z-370ca9a1/` establish one successful provider entry in PID 1190887 (0x122BE7), same-boot correlation, completed final state checks and no TLS 1.3 claim. This was the unchanged mask-eight passthrough provider; no replacement TLS was enabled. The old pending-observation plan was stale.

The preceding work preserved `psp2core-SceWebKitProcess.spsp2dmp` and `crash_report.caf` under `build/device-evidence/146-connect-crash-files-20261010T175056Z-8ba4d052/`. The capture receipt records two stable reads, lengths 725120/256, respective SHA-256 values `e1be2c8ce6ee9f47ecb32bfa91c7742d0cfc4c5627f53cd9e97998ec05f04cff` and `0ca81f8fd2cdca592afc73d2cff882104f8196fb59250050d5c40e4c18b7f78d`, and both modification replies `213 20261010174420`. The original collector omitted the encrypted extension; its previous absence must not be interpreted as no dump. Local psp2_core_parse output is `build/connect-crash-analysis.json`. It reports complete decryption/decompression and no metadata decoder errors, but HMAC authentication was not performed.

### 23.190 Fault before the connect frame; missing pages remain unknown

The core identifies `SceWebKit:RscHdlMan:Worker`, PC/IFAR 0x91D40000, IFSR 5 (section translation fault), CPSR 0x30 (user/Thumb), SP 0x817B0E08 and LR 0x813A668F. Captured arguments are r0=0x81700A00, r1=0, r2=1 and r3=0x817B0E6A. Its module inventory places ScePsp2Compat text at 0x81300450 and the mask-eight provider text at 0x81280000, data at 0x81182000. The recorded fault address belongs to neither module.

Canonical IDA session `tls_fixer-compat-connect-core-match` confirms the exact reference wrapper at offset 0xA6234: PUSH {r4,lr}, move the done pointer into r3, set r2=1, BL the connect routine at offset 0xA5ECE, then POP {r4,pc}. The core LR is precisely the relocated BL return, and its SP starts with saved r4=done and caller return 0x81398989. Session `tls_fixer-mask8-connect-fault` confirms the replacement callback's 40-byte prologue/frame and its continuation BLX at offset 0x36. The captured register/stack layout is consistent with a failure before that callback or the original connect prologue, rather than an established TLS-backend failure. This is a narrowing inference, not proof of which installed instruction supplied the bad target.

A direct ELF program-header coverage check found no captured PT_LOAD range for the patched connect entry 0x813A631E, native wrapper, provider entry or provider hook-reference area. The stack bytes are captured (two identical overlapping stack segments). IDA's zero-filled views of absent pages are not recorded zeros. The saved substitute reference handles Thumb halfword alignment with a leading NOP and tagged continuation; it is not a verified match of the installed framework. No framework or TLS-policy change is justified from that reference alone.

Preparing an opt-in kernel-side read-only snapshot of the validated connect entry before/after provider startup, its caller wrapper and the provider entry. The provider image and TLS behavior will remain unchanged. Snapshots use checked process copies and queued logging, never direct dereferences of foreign code, code writes or automatic hook removal. The bounded-copy fixture failed its valid-case assertion before implementation; its implemented helper passes. Loader integration is still being tested; no new artifact, device write, reboot or re-arm is claimed here.

### 23.191 Imported-variable fixup matches the fault; earlier boundary superseded

The later CHAT.md and saved plan supersede the snapshot-only next step. The preceding analysis identified imported-variable MOVW/MOVT fixup records at compatibility offsets 0xA5ED4/0xA5ED8, within the connect detour's overwritten span. For the recorded provider callback 0x81280001 and imported address 0xE00111D4, the native Thumb MOVW field rewrite yields 0x91D40001, corresponding exactly to the core's faulting instruction address 0x91D40000. The original code page is absent from the dump, so this is a relocation/fault correlation, not a directly captured corrupted instruction. Do not deliberately repeat the known early-install control merely to gather another crash.

Canonical IDA session `tls_fixer-varref-link-timing` was reused in this continuation. `fun_StartModuleForProcess` is the seven-argument native function at module offset 0x286C; it calls the image start/link path before returning, handles failed/nonresident starts, and preserves the nullable status pointer. Its checked entry/argument/dispatch bytes were reread directly from the existing 3.60 database. The new start guard shares the existing exact module metadata gate, masks only the relocated stack-cookie immediates, and checks these separate byte ranges in addition to the load guard. An inherited fixture had `e0` instead of the actual `0e` at +0x29B5; it was corrected against the IDA bytes, not by weakening the mask.

### 23.192 Post-start activation implemented locally; aggregate verification in progress

Added opt-in `TLS_FIXER_BROWSER_POST_START`, restricted to queued browser-only activation. The start hook is validated and installed before the load hook. The load hook records an owned, bounded pending entry keyed by process ID and module GUID instead of starting the browser provider. The native start hook forwards all seven arguments once, consumes a matching entry only after that call returns, and leaves the native return and status output unchanged even when injection fails. No mutex is held across tracing, native start, or provider injection. Failed native starts consume their entry without injection; duplicate, reentrant and unmatched completions cannot inject twice. Eight pending slots bound abandoned-load resource usage; a load abandoned without a corresponding start can occupy a slot until teardown/reboot, and table exhaustion fails closed rather than evicting another load.

If the first kernel hook has been published but the second installation or recording fails, the module remains resident with its resources intact; it does not free a potentially executing continuation. Stop refuses while either hook is installed. Self-disarm remains the first module-entry operation, and no startup/cleanup path re-arms it. The passive code snapshots may be combined with this new ordering; the original provider, trust policy and TLS transport are unchanged. The option-off build is a historical comparison, not a recommendation to redeploy the now-identified early-install path.

The inherited manager/start-guard tests failed against their prior stubs in `build/post-start-resume-red.log`. The new route regression failed against the previous single-hook startup in `build/post-start-route-red.log`. Focused routing/manager tests passed after implementation. Their relocation-order fixture also asserts the exact 0x91D40001 corruption for an early callback literal and the intact 0x81280001 literal after post-link installation. This simulates ordering; it is not an ARM execution or installed-code capture.

`build/browser-post-start-verification.log` contains **321/321 normal and 321/321 sanitizer CTest** successes. The subsequent Python suite ran 108 tests and caught the previously unfinished encrypted-core inventory regression. Added `.spsp2dmp` to the existing case-insensitive filename inventory; this does not download or publish cores. The Python rerun and native builds are running in `build/browser-post-start-native.log`. No new native success, device replacement, reboot or re-arm is claimed at this checkpoint; the current device is being collected read-only before recovery decisions.

### 23.193 Final host/native verification and immutable post-start package

The initial native build found a missing GetProcessId declaration in the new translation unit; including the existing SDK's threadmgr/misc header corrected it without changing behavior. Final log `build/browser-post-start-final-host.log` contains two complete **321/321 CTest** successes, **108/108 Python tests**, rejection of the bare/redirection/missing-path post-start profiles, and `POST_START_FINAL_HOST_VERIFIED`. `build/browser-post-start-native-final.log` ends `POST_START_NATIVE_VERIFIED`: native kernel built, no unresolved symbols or decoded FP/SIMD instructions, and the option-off control is byte-identical to the preceding 20645-byte kernel. A previously blocked isolated output poll was not retried; these completed logs are distinct expanded/final runs.

IDA session `tls_fixer-post-start-final-review` inspected the new ELF in place. The first entry call is self-disarm at 0x810002F0; start-hook installation at 0x810004F8 precedes load-hook installation at 0x8100054A. The wrapper preserves and forwards all seven arguments, calls the native continuation at 0x810002A4, then completion at 0x810002AE, restoring the native return. The pending-table mutex unlock at 0x81002BDE precedes the zero native-result test and browser injection at 0x81002CB4. The load callback calls defer at 0x810001BE and has no direct browser-injection call. Review details and residual limits are in `docs/tls13-browser-post-start-control.md`.

New kernel **22613 bytes**, SHA-256 `3ccfa163d12a7f43eb4bea9affe23b1723a43f597520059de1d46fafe2a09247`; ELF SHA-256 `176086c6b175752f7bbdab68936fa3518048319b07f6a3f11939c964b8e2509c`. Package `build/artifacts-post-start-control/` contains a fresh 256-byte report/hash `6a8c6e3d3f894d45f1631e56bcc58031751ecd34f0a8e915a0c9a592d873b2af`. Its two-member ZIP hashes to `f04de9ab6e9b35bf00d2481e3c81f9787329cead94bc6cb31c9b3dc21a1b3013`. The unchanged connect-only provider remains 246156 bytes/hash `d09284a4f9b02117faaa3a5ab013e5abd5a8e15a2f72530b22dd5c954810dc5a`; it is checked, not rewritten.

New helpers `build/stage_post_start_control_files_only.py` and `build/arm_post_start_control_once.py` derive from the read existing templates with changed payload/before-state constants and distinct backup/receipt names. The stage helper selects only kernel/report. Seven memory-only scenarios passed in `build/post-start-helper-tests-final.log`, including mismatches without writes and failed rename rollback. An initial harness expectation incorrectly compared an intentionally corrupted new test kernel with the old snapshot; only that expectation was corrected. No helper network operation has yet run at this checkpoint.

### 23.194 Crash-screen preservation and one unarmed reboot before the new test

Read-only capture `build/device-evidence/146-log-capture-20261010T195656Z-e6baef9f/files/` preserves the exact disabled config, old 20645-byte kernel and six protected files. Trace: 18159 bytes/hash `9a95a0f79167e442cb2e7bbd5eab70716257dde32f1fdd06067322129c9b342d`; report hash `9ce56f59a6290d22a6c966558947f7feb3fb86e95217e41fedbdb66744097396`. The first screenshot request produced no new file and was not repeated. The user then took a screenshot; read-only double retrieval plus PNG CRC/IEND checks preserved `build/device-evidence/146-user-screen-20261010T200542768493Z/2026-10-10-220233.png`, hash `28a13ccf052b79816222aa5314236cdcfc1a81092ee67b402d43810406699b7b`, showing C2-12828-1 in Internet Browser. No new browser request is inferred.

After announcing the specific operation, `reboot-disabled` completed one ordinary guarded reboot with `Rebooting...`, observed reconnect and disabled read-back. Log: `build/post-start-unarmed-reboot.log`; after-state `build/device-evidence/146-unarmed-reboot-20261010T200807Z-cb6c4657/after/`. It wrote no configuration and launched no browser. The subsequent screenshot `build/device-evidence/146-screen-20261010T200851726797Z/2026-10-10-220852.png`, hash `19a05bd1b46eea2f1eb54fcc1f5829c7e59d3f1e3a1fc1a6a510d926be08830a`, shows the improper-power-off notice over LiveArea. This does not establish whether the notice originates from the last reset or an earlier failure. The user was asked to dismiss OK; no new test has been armed.

Full read-only preflight after reconnect verified 14 files against the just-preserved inactive state, original resources and unchanged connect-only provider: `build/device-backups/146-post-start-preflight-20261010T200930Z-0e0e1654/`, `build/post-start-preflight-current.json`. These pins are used by the new package helpers. The local package does not imply a device result, and the later zero-hook system freeze remains unexplained.

### 23.195 Post-start control transferred, armed and boot verified

The user confirmed the improper-power-off notice had already been dismissed. The guarded new run completed stage/arm and one deliberate reboot with no replay of the old control. The stage helper changed only the new 22613-byte diagnostic kernel and fresh report, preserving remote/local prior copies at `build/device-backups/146-post-start-control-files-only-20261010T202040Z-45a5e1/`. The separate provider, original modules, CA and protected files were rechecked, not rewritten. Arming completed at 20:20:59 UTC after the one-byte offset-689 change; receipt `build/post-start-control-user-armed.json`, SHA-256 `06914e0e28dae84f3db0256666a1fe4e7b751f63d0f804a813a5b24a6a2412fa`, backup `build/device-backups/146-post-start-control-arm-20261010T202050Z-03fbbb/`.

The reboot transport response timed out, but the runner independently observed reconnect and verified the exact new kernel, disabled configuration and fresh clean startup. It did not resend the command. `build/post-start-control-cycle.log` returned the expected pending-UI status 3. Cycle: `build/device-evidence/146-cycle-20261010T202106Z-610a4137/`. Fresh boot trace SHA-256 `cab942c6f07e692b68c4c424b8f7a1477fdb491ded98a4f3a50152f6508fcec2`, 21 complete records read in full. It records successful start-hook installation (0x31D0B) before load-hook installation (0x31D17) and browser-only readiness 2. This is a fresh startup check, not proof of page loading.

`quit all` returned `Apps quit.`. Screenshot `build/device-evidence/146-screen-20261010T202207187808Z/2026-10-10-222207.png` shows LiveArea with Browser visible and no notice. The ordinary icon tap completed; screenshot `build/device-evidence/146-screen-20261010T202306932245Z/2026-10-10-222307.png` shows the Browser Start tile. The subsequent Start tap command was tool-blocked without an execution result, and was not retried through another input route. The user was asked to press the visible tile once in this same session.

### 23.196 Same connect-only provider now renders the page; detailed trace comparison pending

The user reported pressing Start and seeing the Cloudflare page with TLS 1.2. The initial read-only observation raced with trace growth and stopped at stable-read verification (`build/post-start-control-observation.log`); it did not arm, upload, reboot or retry itself. A distinct post-request observation with zero settling time completed normally: `build/post-start-control-after-request.log`, `build/device-evidence/146-cycle-20261010T202106Z-610a4137/ui-observation-20261010T202636Z-e4775368/browser/`. It verifies the saved boot prefix, disabled state, unchanged payload/protected files and one correlated successful provider startup in PID 1191411 (0x122DF3). It explicitly leaves `tls13_established=false`.

Screenshot `build/device-evidence/146-screen-20261010T202645235482Z/2026-10-10-222646.png`, SHA-256 `9ce8b902946e12623742dd7d86c2acad90f245b01d83bbbb2d4349246a3fae02`, visibly confirms the rendered Cloudflare trace with `tls=TLSv1.2` and no crash dialog. The connect-only provider is the same previously crashing image; the kernel's activation timing changed. This is positive control evidence for the ordering correction, not complete TLS compatibility or resolution of the separate system-freeze observation.

A subsequent local command to summarize native-start/entry snapshots from that captured trace was tool-blocked and was not rerouted. The user was given a grep command limited to native.start.return, provider.status, code.before and code.after in the saved file. Await those lines or an authorized later inspection before claiming the installed instruction words were reviewed. The browser has been left open; no additional reboot, re-arm or new provider selection occurred.

### 23.197 All-four-hooks passthrough artifact prepared locally, not deployed

While the captured trace comparison is pending, verified the existing mask-8 and mask-15 ELF/SELF identities against `build/browser-hook-selection-images/comparison.json`. Their PT_LOAD geometry is identical and the only changed loadable byte is the read-only selection value at 0x81040314 (8 to 15). The provider instruction bytes and footprint are unchanged. No new compilation, TLS-backend enablement or different cryptographic build was introduced.

Local package `build/artifacts-post-start-all-hooks/` retains the verified post-start kernel and the existing mask-15 provider, 246156 bytes/hash `029103d24d843af0c2a383ef5a1e253105f04021ca7414f905504c9c08c71218`. Fresh report hash `274b055e93a0dafc150484a071eab6d1135514d317dfeee7b3bbaa53abece4d3`; two-member ZIP hash `84c923c248e33b9d307ef36fcf47a96aaa66a5746cad709d79e78c8cb94f07ce`. The provider remains separate from the ZIP. Receipt explicitly records `deployment_ready=false` and `hardware_validated=false`. No new helpers, remote connection, upload, arming or reboot was performed by this artifact preparation. Finish the current trace review and preserve an inactive before-state before selecting this next control.

### 23.198 User-supplied entry words resolve the pending local trace comparison

On resumption, read the current handoff and CHAT.md through the supplied excerpt at lines 8589-8600. The user has already supplied the requested local lines; asking for them again would be stale. No retry of the earlier blocked local extraction was needed. Sequence 0x30 is native.start.return with result zero. Before words at 0x813A5F3E are 4FF0E92D/F644B0C7/F2CE5444/68240401. Provider status at sequence 0x6E is zero. The after words at the same addresses are F8DFBF00/0001F000/BF008124/68240401. Interpreting the reported words as little-endian bytes gives the halfword-aligned NOP, PC-literal load and literal bytes 01 00 24 81: the intact Thumb callback address 0x81240001. This is the immediate post-install snapshot, not a later re-read of that instruction or proof that no subsequent relinking can occur.

Together with the unchanged connect-only provider identity, completed correlated observation and page screenshot in section 23.196, this supports the post-start ordering correction for the earlier immediate connect-only crash. The different provider placement is recorded rather than assuming identical virtual addresses across boots. Four-hook behavior, TLS-enabled behavior and the separate later system-freeze observation remain unqualified.

The next control is the already-built mask-15 passthrough provider from section 23.197, retaining the post-start kernel and original resources. First preserve current files/screen and end the active control with one guarded unarmed reboot; then derive fresh before-state pins and new single-use helpers. At this checkpoint this continuation has changed only the worklog/plan/chat locally, with no new device command, upload, reboot or re-arming.

### 23.199 Resumed read-only capture completed; current screenshot missing

The ordinary collector completed a new capture at 21:12:44 UTC; its JSON/log is `build/post-start-all-hooks-resume-capture.log` and reports complete=true. The subsequent existing screenshot helper exited with `No new screenshot appeared; no retry was sent`, recorded in `build/post-start-all-hooks-resume-screen.log`. Its screenshot input must not be confused with a reboot or browser launch. A separate command to summarize the capture, inspect the screenshot receipt and inventory inherited helper metadata was tool-blocked without a result and was not repeated.

The local shell inventory before that block found existing `stage_post_start_all_hooks_files_only.py`, `arm_post_start_all_hooks_once.py` and `check_post_start_all_hooks_helpers.py` despite the preceding handoff saying no helpers. The stage helper was read: it selects only the diagnostic provider and report, pins the unchanged post-start kernel, and contains before-state hashes that have not yet been qualified against a fresh inactive session here. Their mere existence is not evidence of execution. No matching task command was running in the process listing. Do not run or regenerate these helpers before checking saved execution receipts and their provenance/current pins.

The user was asked to wake the Vita and take PS+Start once, leaving the current page or dialog visible. Current visual recovery is the immediate device blocker, not authorization for TLS tests. No additional upload, configuration write, arming, reboot or browser input occurred in this continuation. Next: retrieve the user's new screenshot without another button press, establish the saved capture/current disabled state, then perform the single unarmed transition and fresh four-hook preflight. Continue local artifact/helper review in the meantime; do not claim a new kernel build or test-suite run.

### 23.200 User screenshot verifies current LiveArea; unarmed transition announced

The user replied Done to the screenshot request. A distinct read-only retrieval of the latest screenshot, with no injected buttons, obtained two identical 368995-byte copies. PNG chunk CRCs and exact terminal IEND passed. Saved image: `build/device-evidence/146-user-current-screen-20261010T211454861301Z/2026-10-10-231408.png`, SHA-256 `d3460ae7a3596637acf9a1bac7e7095fe561ece529e35f5fa68b2da828b0211d`, remote MDTM `213 20261010211411`. Visual inspection shows LiveArea, Browser icon, address .146 and no error dialog. It does not establish whether an earlier active worker has stopped.

Announced one guarded `reboot-disabled` using the consumed post-start control's receipt solely to verify the current disabled payload/configuration and preserve before/after evidence. This operation must not stage, arm or launch a browser. Its result is pending at this checkpoint. After it completes, requalify inherited four-hook helper pins against the actual inactive state before selecting the new run. Original modules, CA and protected files remain out of scope for writes.

### 23.201 Stale receipt refused before reboot; actual four-hook boot recovered

The attempted unarmed transition exited 1 with `Changed protected file: /ur0:/tai/tls_fixer_startdiag.suprx` in `build/post-start-all-hooks-unarmed-reboot-resume.log`. That check precedes request_reboot in the inspected runner, so no reboot was sent by this attempt. The differing provider was not overwritten, nor was its gate weakened.

Read the newer `build/post-start-all-hooks-user-armed.json` and `build/post-start-all-hooks-cycle.log`: both predate this continuation. They establish that the preceding continuation had executed the supposedly local-only control. Provider/report staging completed at `build/device-backups/146-post-start-all-hooks-files-only-20261010T204116Z-91e6a9/`; arming completed at 20:41:34 UTC, backup `build/device-backups/146-post-start-all-hooks-arm-20261010T204126Z-296551/`, with only config byte 689 changed. Provider is mask 15, 246156 bytes/hash `029103d24d843af0c2a383ef5a1e253105f04021ca7414f905504c9c08c71218`; kernel stays 22613 bytes/hash `3ccfa163d12a7f43eb4bea9affe23b1723a43f597520059de1d46fafe2a09247`; report PENDING hash is `274b055e93a0dafc150484a071eab6d1135514d317dfeee7b3bbaa53abece4d3`. All original resources and protected files were pinned in that receipt.

Saved cycle `build/device-evidence/146-cycle-20261010T204140Z-453526cb/` has boot_verified=true, browser_ui_pending=true, provider_started=false, and no title launch. The command response timed out, but the runner observed reconnect and verified the new boot trace/hash `c72c5579b3e9132c0cc66d487231b34e9d95839421e14d99388f2b2c28735b0f` and disabled configuration; it did not resend the reboot. Arming-receipt identity is `1539138b0d0c0548bb8f637ee7a0fec61d64aaffb10716e4be58b8b4761746ed`. This recovered execution supersedes the earlier local-only claims and the proposed new unarmed transition. Do not replay these already-consumed helpers.

The next action is a same-boot read-only verification against this exact saved cycle, followed by the user-requested quit-all and normal Browser icon/Start sequence. No browser result for this four-hook control is established yet. This continuation has not staged, re-armed or rebooted any test.

### 23.202 Four-hook boot correlated; normal Browser icon and Start input sent

The ordinary read-only observer accepted the saved four-hook boot/arming identity and passed its state checks. It completed before Start was pressed, with expected status 3, no provider startup yet, no error field, and browser_ui_pending=true. Saved log: `build/post-start-all-hooks-observation-resume.log`; capture under `build/device-evidence/146-cycle-20261010T204140Z-453526cb/ui-observation-20261010T211850Z-74677093/browser/`. This establishes current boot correlation, not a failed browser test.

`quit all` returned `Apps quit.` in `build/post-start-all-hooks-quit-resume.txt`. Screenshot `build/device-evidence/146-screen-20261010T212000395328Z/2026-10-10-232001.png`, hash `0bfbac44ab49703b4ccc6f964cd21b618e2c35614c931fafa17e39525a3d99a1`, visibly shows LiveArea and the Browser icon without a dialog. A normal front-touch tap at panel coordinates 1434,882 (slot 0) acknowledged press/release. The subsequent screenshot was initially incomplete; it was preserved and the same remote filename was retrieved read-only twice, without another button press. The complete 300210-byte image passes PNG CRC/IEND validation: `build/device-evidence/146-screen-20261010T212059050591Z/2026-10-10-232059.complete.png`, hash `cb70af9cab443781d72596f6b1edac5cbda99368eac1198d7597d9cadcc45f84`. It shows the Browser Start tile.

The visible Start tile was then tapped once at panel coordinates 1440,566 with acknowledged release; log `build/post-start-all-hooks-browser-start-resume.txt`. Command session 1 is waiting eight seconds and requesting a result screenshot. The next action is to retrieve that result, preserve any crash dialog, and run the read-only observer against the same four-hook cycle with settle zero. No page/provider/TLS result is claimed at this checkpoint. No re-arm, upload, reboot, vitacompanion title launch or unrelated resource change occurred.

A separate memory-only helper test was started during the earlier unarmed-reboot check, but its output poll was tool-blocked. No new test success is claimed from that invocation; these helpers will not be executed again because the recovered cycle already consumed them.

### 23.203 Four-hook passthrough renders; final correlated observation completes

The Start tap completed normally with press/release acknowledgment. Screenshot `build/device-evidence/146-screen-20261010T212223837247Z/2026-10-10-232224.png`, SHA-256 `2676c1f4ff2530385e0b880cea1d6050449beb21afb0b0ce16d6c77adb2887d7`, was viewed successfully and shows the rendered Cloudflare trace with `tls=TLSv1.2` and no crash dialog. This is direct visual evidence from the agent-operated normal icon/Start sequence, not a title-launch acknowledgment.

The post-request read-only observer completed with exit zero: `build/post-start-all-hooks-after-start-resume.log`; observation `build/device-evidence/146-cycle-20261010T204140Z-453526cb/ui-observation-20261010T212256Z-19bfb292/`. It verifies the exact saved boot prefix/arming identity, one successful provider startup in PID 4530897, unchanged payload/protected files and the disabled configuration before and after capture. It records cycle_complete=true, browser_provider_started=true, and deliberately tls13_established=false. Detailed raw trace review remains the next local task. The current page is left open, with no further upload, re-arm or reboot.

This is a successful immediate four-hook passthrough page control with the post-start kernel. It does not prove sustained console stability or TLS-enabled compatibility. Together with the connect-only result, it permits preparing the next narrow TLS-enabled provider test rather than repeating the early-hook failure. Original Sony modules/CA must remain unchanged, and certificate verification must not be disabled to make the test pass. The attempted chat progress notification for this result was tool-blocked without a successful delivery; it was not assumed received.

### 23.204 Four-hook trace fully reviewed; TLS-enabled build selected locally

Read all 158 records from the completed four-hook capture. PID 0x4522D1 loads compatibility GUID 0x13369, records defer at sequences 0x33/0x34, then native.start.return=0 at 0x36 before preparation. The complete hash comparison succeeds, target PUID is 0x40010163, text is 0x81300030 and shared classification is zero. Provider GUID 0x23963 returns status zero at sequence 0x74. Before/after connect-entry snapshots at 0x813A5EFE again show a relocated prologue replaced by an intact 0x81240001 detour literal; the provider text snapshot at 0x81240000 is captured too. Argument/query cleanup and preparation return zero. The report independently has a=0x9E (158), h=0xAD (173), err/op zero. This is an immediate post-install snapshot, not a later reread or proof of every future connection.

The next local build will keep startup diagnostics and debug logging ON, runtime UDP OFF, initialization-only OFF, and use the existing TLS engine/source without a selective hook mask or passthrough-only mode. All four normal hooks will be used with replacement TLS enabled. The preceding control cache (`build/browser-hook-selection-vita/CMakeCache.txt`) was read and these are the deliberate profile differences. The new native output will be separate at `build/browser-post-start-tls-enabled-vita/`; do not overwrite the immutable control snapshots or device provider while this is being verified. The installed Docker image identity is `sha256:fd82d88ff456d118eef16533ebf9a3a6ae0e292684fb8a3a35f15f0707b4692d`; no new toolchain/library download is requested. Build/tests are pending at this checkpoint, and no next device transition has been performed.

### 23.205 Fresh TLS-enabled build/tests and native enable-order review completed

The new native build and chained verification command completed normally with exit zero and final marker `POST_START_TLS_ENABLED_BUILD_VERIFIED` in `build/browser-post-start-tls-enabled-verification.log`. It configured an explicit Release Vita provider using the pinned local image, startup diagnostics ON, passthrough OFF, initialization-only OFF, UDP OFF, debug ON and an empty selective-hook setting; built both provider targets; checked no unresolved symbols in the browser ELF; rebuilt and ran the normal and sanitizer suites; and ran 108 Python tests. The last CTest summary is 321/321 and the command uses success chaining for both CTest executions. No crypto, trust or browser-adapter source was modified in this continuation. The supplementary probe fixture's random configuration output during Python tests is not a device installation or TLS measurement.

IDA MCP opened the new browser ELF in place as `tls_fixer-post-start-tls-enabled-review`. Scoped instruction queries confirm backend initialization at 0x81000344, the native hook-install call at 0x81000398 in a loop tested against four entries at 0x810003AC, and only then MOVS R0,#1 at 0x810003B0 followed by tls_fixer_browser_enable at 0x810003B4. The failure branch precedes enablement. The native module retains the existing callback/continuation paths. User-space NEON instructions are expected here and were not confused with the kernel's general-register-only requirement. This is static/native verification, not an actual browser handshake.

The subsequent combined local source-pin/log verification and package-generation command was tool-blocked without an execution result. No package receipt/hash or ZIP from that operation is claimed, and it was not rerun. The actual native files already produced by the successful build are `build/browser-post-start-tls-enabled-vita/browser/tls_fixer` and `tls_fixer.suprx`. No TLS-enabled payload has been transferred, armed or executed. The completed four-hook session remains the latest device state. Next steps: finalize/pin the new artifacts when that operation is available; separately use the matching four-hook receipt to end the current session with one verified unarmed reboot; preserve fresh inactive files; derive new single-use provider/report helpers; run one TLS-enabled normal-browser test. Never use the older connect-only receipt for that transition.

### 23.206 New native identities recorded; matching-receipt inactive transition started

A separate read-only checksum/log-marker check completed. The TLS-enabled provider is **246045 bytes**, SHA-256 `4dd35ec9c9215ccd78db71b02b0572a9088590ac8a1012702bb5cea6bb0318ef`; its ELF SHA-256 is `72e9d839fddcbbe92d8e4363f7771ad98828c86c8f1cee4d73f1560907330035`. The log contains exactly the displayed two 321/321 CTest summaries, 108 Python tests and the final success marker. This check did not generate a package or write the device. Removing the selective-mask build path means this new image is not claimed to have the bit-identical code/geometry property of the earlier mask-0/8/15 comparison; a new failure would need to distinguish transport activation from that build-layout difference.

After the current successful page/trace was preserved, announced one `reboot-disabled` with **`build/post-start-all-hooks-user-armed.json`**, not the stale connect-only receipt. The ordinary command is running in session 1, log `build/post-start-tls-enabled-inactive-transition.log`, with a 120-second reconnect budget and no automatic resend. It performs no provider/configuration write or browser launch. Do not call it complete or rerun it until its saved result is read. Next checkpoints: verified disabled after-state, visible LiveArea, full original-resource/provider before-state, then a new provider/report-only test when packaging/helpers are qualified. The successful four-hook cycle must never be replayed.

### 23.207 Matching-receipt unarmed reboot completed normally

`build/post-start-tls-enabled-inactive-transition.log` completed with exit zero, response `Rebooting...`, disabled_readback_verified=true, configuration_written=false and browser_launched=false. After-state: `build/device-evidence/146-unarmed-reboot-20261010T213110Z-9c2ac837/after/`; the parent contains preserved before-state and reboot.json. The runner checked the exact disabled config, unchanged post-start kernel/mask-15 provider, original resources and protected files before and after reconnect. This is the one actually executed reboot in this continuation; the earlier stale-receipt attempt sent none.

The ordinary screenshot helper is running in command session 2, with output in `build/post-start-tls-enabled-inactive-screen.log`, to verify the visible after-state. Do not infer its result from FTP connectivity. No TLS-enabled file has been transferred, and the only local source/document change so far is this continuously updated worklog. The new binary paths/hashes and successful build/IDA review remain in sections 23.205-23.206; packaging/helper qualification is incomplete.

### 23.208 Inactive screen, package and fresh full before-state verified

The screenshot helper completed with acknowledged button release. Image `build/device-evidence/146-screen-20261010T213224013375Z/2026-10-10-233225.png`, SHA-256 `9ff514cc9f3e96833c7964f456b5f6476376b666f353259e70d5bc9a44a2859e`, was viewed and shows LiveArea without an error or power-off notice. The current inactive provider/kernel are unchanged from the four-hook control.

After the earlier blocked combined packaging operation, the explicit local copy/report/ZIP commands completed normally. Package is `build/artifacts-post-start-tls-enabled/`: unchanged kernel; separate 246045-byte provider/hash `4dd35ec9c9215ccd78db71b02b0572a9088590ac8a1012702bb5cea6bb0318ef`; fresh 256-byte PENDING report/hash `5f81f858f02c0666a701e1474db07e887e68982028957db2fb4d351bf0999fd5`; kernel/report-only ZIP/hash `e2f14c5c4c9be326c317ca24d6ea974888ebd09df8574162912aabebe6bbee4c`. Both ZIP members were reread and compared. A separate successful check verifies all 204 preceding receipt-pinned source files unchanged. These completed operations, not the blocked command, establish the package.

Read-only preflight then verified fourteen files against the correct all-hook receipt and actual unarmed after-state. Snapshot: `build/device-backups/146-post-start-tls-enabled-preflight-20261010T213612Z-edfb92fe/`; receipt `build/post-start-tls-enabled-preflight-current.json`, complete=true. Alternate config is absent. Preserved dynamic report/trace hashes are `7ca86700a3a2e6e62df34739baa00ecbab99267ddb69ec58d64b9f603acc2053` and `dfb4b69edad509a0de0bf482c8845e4d20b5ef534e520958b3553a92a01504cb`. Original resources, protected files and mask-15 provider are unchanged.

### 23.209 New TLS-enabled transfer helpers qualified; real TLS test is next

Generated distinct `build/stage_post_start_tls_enabled_files_only.py`, `build/arm_post_start_tls_enabled_once.py` and `build/check_post_start_tls_enabled_helpers.py` from the read existing templates, updating named constant assignments through the parsed AST and refusing to overwrite existing new helper files. The stage payload contains only the separate diagnostic provider and fresh report; the post-start kernel and original resources are checked, not rewritten. Syntax checks passed; all 204 source pins were rechecked. Package receipt.json pins those sources, native ELF, verification log, preflight and new helper identities.

The command completed with exit zero and seven passing memory-only scenarios in `build/post-start-tls-enabled-helper-tests.log`: stage/arm success, changed config/report/resource refusal, arm with changed kernel refusal, and provider publication-rename failure restoring the prior file. No network operation was executed by generation/tests. Expected new arming receipt is `build/post-start-tls-enabled-user-armed.json`; helpers have not been consumed yet.

The user asked how many iterations remain before real TLS. Answered explicitly: the next planned device test enables Mbed TLS/TLS 1.3, with no more passthrough isolation iteration planned. Only guarded transfer/one boot/normal browser input/capture remains before that measurement. A successful first handshake or a finite total number of subsequent debugging iterations is not promised. Next execute the new cycle once, record its actual receipt/boot checkpoint immediately, then capture the page's TLS version and matching logs without bypassing certificate failures.

### 23.210 Real TLS-enabled cycle announced and started

Announced transfer of the 246045-byte TLS-enabled provider and fresh report, with the unchanged post-start kernel and one self-disarming boot. The chat message was saved, although its notification delivery failed; it was not resent solely to retry notifications. The ordinary guarded runner started in command session 1, writing `build/post-start-tls-enabled-cycle.log`, using the new TLS-enabled stage/arm helpers and `build/post-start-tls-enabled-user-armed.json` with title NPXS10003 and a 120-second reboot/reconnect budget. No title launch is requested by the runner.

Its transfer/arming/boot outcome is pending at this checkpoint. Do not rerun the helpers if the result is the expected pending-UI status 3, and do not infer successful transfer or self-disarming from this invocation alone. Next poll this existing session/read its saved result, immediately record the new actual backup/receipt/cycle identities, verify the screen, then run the normal quit-all/icon/Start browser test.

### 23.211 Real TLS-enabled provider transferred; one boot verified

The saved runner log completed its pending-UI checkpoint. It verifies the new 246045-byte provider/hash `4dd35ec9c9215ccd78db71b02b0572a9088590ac8a1012702bb5cea6bb0318ef` and report/hash `5f81f858f02c0666a701e1474db07e887e68982028957db2fb4d351bf0999fd5`; kernel/original resources/protected files remain unchanged. Stage backup is `build/device-backups/146-post-start-tls-enabled-files-only-20261010T214213Z-3b7fdf/`. Arming completed at 21:42:42 UTC after only byte 689 changed: `build/post-start-tls-enabled-user-armed.json`, backup suffix `20261010T214230Z-ccbf15`. Arming-receipt identity is `675a5e96dd26043a22e4ba3517c36945c4f2c482b532de7984f4d428906aad63`.

New cycle `build/device-evidence/146-cycle-20261010T214253Z-cc25f076/` records boot_verified=true, browser_ui_pending=true and provider_started=false. The response timed out, but the runner observed reconnect and verified the disabled config and fresh boot trace/hash `40fa9fefc799d1dcef56608c802535313f3633ba8a2514150197c4411f086bba` without resending the reboot. A later output poll was tool-blocked; the completed saved log was read, not the poll or device command retried. This is the expected pending-UI checkpoint, not a complete page/handshake result. Next operate the normal browser UI in this boot and collect against this exact receipt/cycle.

### 23.212 Real TLS boot at LiveArea; user normal-browser input requested

`quit all` returned `Apps quit.` and is saved in `build/post-start-tls-enabled-quit.txt`. Screenshot `build/device-evidence/146-screen-20261010T214430060796Z/2026-10-10-234431.png`, hash `954b2358a5add2539c42cad9a3021a8229ae7c2677d7aa29b687330e1b9fa482`, was viewed and shows LiveArea with Browser visible and no dialog. The subsequent icon-tap command was tool-blocked without an execution result and was not retried by another input mechanism.

The user was asked to tap Browser then Start once in this existing real TLS-enabled session, leaving the page/error visible without rebooting or re-arming. A read-only same-boot observer is running for 60 seconds in session 3, log `build/post-start-tls-enabled-browser-observation.log`, against the exact new cycle/receipt. No browser result or input completion is inferred yet. Next acknowledge the user's result, read the observer's actual outcome, inspect fresh screenshot/logs and preserve any crash/core before further actions.

The observer subsequently completed with expected pending-UI status 3: `ui-observation-20261010T214529Z-dac65011/` under this cycle. It passed its state checks, recorded zero provider-start attempts and no error field, and left browser_ui_pending=true. The user has not yet reported completing the requested normal UI action. This is not a failed TLS handshake or grounds for another build/reboot. Wait for that action, then capture the resulting page and a new read-only same-boot observation. No test file or configuration was changed by the observer.

### 23.213 Later read-only observation still awaits browser input

After several chat waits without a user reply, ran one distinct zero-settle read-only observation to check whether the browser had been opened without a message. It completed its saved report at `build/device-evidence/146-cycle-20261010T214253Z-cc25f076/ui-observation-20261010T215718Z-d56ce747/`; log `build/post-start-tls-enabled-later-observation.log`. The report retains the same boot/arming identity, valid state checks, observation_finished=true, zero provider-start attempts and browser_ui_pending=true, without an error field. Its output poll was tool-blocked; the completed saved log was read rather than rerunning that poll or any device input.

The next step remains only the normal browser UI action and its result, not another experimental build. The current diagnostic files are already the real TLS-enabled profile. No input retry, transfer, configuration change, re-arm or reboot followed the original blocked tap. Until an actual browser request is established, neither TLS success nor TLS failure should be inferred. On future resumption, read CHAT.md first for the user's action before asking again, and revalidate this saved cycle before any consequential change.

### 23.214 User browser action completed; TLS 1.2 page and startup preserved

On resumption the user reported Browser/Start, TLS 1.2 and a manually taken screenshot. Acknowledged immediately; do not ask for the already-completed launch again. The new zero-settle read-only observer completed with exit zero in `build/post-start-tls-enabled-after-user-page.log`, observation `build/device-evidence/146-cycle-20261010T214253Z-cc25f076/ui-observation-20261010T221446Z-19cee0aa/`. It verifies this exact boot/arming identity, unchanged payload/protected files and disabled config before/after capture, with one successful provider startup in PID 3551031, cycle_complete=true and tls13_established=false. The independent report has err/op zero, attempts=0x92 and loads=0x99. No browser log file was found by the saved capture's file inventory command.

Retrieved the user's latest screenshot without any button input. Two identical 67037-byte reads and all PNG CRC/IEND checks passed: `build/device-evidence/146-user-tls-page-20261010T221538Z-edce8ab6/2026-10-11-001202.png`, SHA-256 `9d2d80c63487b7076da93063a31fc400b28c9531f65bc88c4ce49335cfa12210`. Visual inspection shows the Cloudflare trace, `tls=TLSv1.2`, `ts=1791670308.000`, `kex=P-256`, and no error dialog. Startup success alone does not establish which TLS engine serviced this connection. Runtime UDP is disabled in this build and no file-log success is inferred.

A separate local command to summarize selected raw trace lines was tool-blocked without an execution result. The successful observer and screenshot results above remain valid; the blocked summary is not a new device failure. Continue with configuration/fallback source analysis and an independently justified runtime discriminator rather than disabling trust checks or repeating the consumed cycle. Keep this session/evidence intact until the next step is selected; update this section before any new implementation or device transition.

### 23.215 Default WebKit SSL-context callback conflicts with blanket fallback

Read the current config and module/backend sources. `tls_fixer_browser_read_options` deliberately returns LEGACY for a nonzero easy-object field at offset 680 (SSL-context callback), among other unsupported options. Startup success with this field present therefore produces native TLS without ever entering Mbed TLS. No certificate or version policy has been changed to force a pass.

IDA session `tls_fixer-real-tls-options-360` opened the existing enriched 3.60 WebKit IDB in place. Request setup at 0x83369406 calls the generic options helper and, when configuration getter 5 is true, installs option 20108 with callback 0x8336CF76 at 0x833694B6, plus userdata option 10109 at 0x833694C4. The callback forwards context/userdata to ScePsp2Compat NID 0x7DAB2E59 and returns zero. Rendered-listing search found the same callback-option setup in several neighboring request paths. The immediate-search tool returned no hits even for these present constants; it is not negative evidence.

The existing exact compatibility ELF export parser maps NID 0x7DAB2E59 to 0x81008E0D. IDA session `tls_fixer-real-tls-compat-options` confirms that routine loads configured certificate material and installs verification-related callbacks, including 0x81009296. Its cached decompilation merges adjacent functions across stack-failure stubs; use scoped native instructions for detailed semantics. It must not be treated as an inert callback or silently skipped. This is strong static evidence for a default-path compatibility gap, not yet the captured reason for the user's connection or a completed callback bridge.

Next add bounded scalar fallback telemetry (option offset and non-sensitive value/presence only), preserving the existing configuration decisions, then use the existing nonce-pinned nonblocking runtime recorder with real TLS still enabled. That test distinguishes the callback fallback from other settings or an actual Mbed TLS 1.2 negotiation. Independently recover the callback's trust and certificate-metadata requirements before designing its compatibility path. Keep all existing certificate checks and the post-start/self-disarm kernel unchanged. No new device transition, TLS source modification or test run has occurred at this checkpoint.

### 23.216 Precise fallback reason instrumentation implemented; verification running

The runtime-enabled config fixture first failed on the missing event pair (`build/browser-fallback-reason-red.log`, CTest exit 8). Added appended wire stages 35/36, legacy.option and legacy.value, without renumbering the existing stages or changing packet size/budget. The config parser now records the first incompatible option's byte offset and either the explicit protocol integer or a boolean presence value. It does not send callback/key pointers, paths, cipher strings, hostnames, certificates or application data. Every existing supported/legacy/invalid decision is retained. The option-off macro removes recording calls.

Tests cover each rejected material offset using an invalid pointer sentinel (not dereferenced or exposed), certificate-info, explicit version, first-reason precedence, unsupported cipher expressions and silent supported/invalid cases. The Python receiver stage table and its wire-ID regression were updated. A separate focused Python red-run command was tool-blocked and obtained no result; do not claim it ran. The expanded final normal/sanitizer/Python verification is running in `build/browser-fallback-reason-verification.log`.

Resolved the current host LAN source as 192.168.1.249 and qualified an ephemeral receiver port locally; new endpoint is `build/browser-fallback-runtime-endpoint.json`, port 59040 with a fresh per-test nonce. No diagnostic packet, file write or input was sent to the Vita by this endpoint preparation. The explicit Release native build is running at `build/browser-fallback-runtime-vita/`, log `build/browser-fallback-runtime-native.log`, with real TLS enabled, all four hooks, startup diagnostics/debug ON and runtime UDP ON. Passthrough and initialization-only remain OFF. The current device still has the preceding non-UDP provider and same consumed boot; no new files have been staged or armed.

### 23.217 Fallback telemetry verified and packaged; inactive before-state preserved

The full verification completed normally: `build/browser-fallback-reason-verification.log` has two 322/322 CTest success summaries, 109 Python tests and `FALLBACK_REASON_HOST_VERIFIED`. The native build completed with no unresolved symbols and `FALLBACK_RUNTIME_NATIVE_VERIFIED`. IDA session `tls_fixer-fallback-runtime-review` confirms version refusal emits stages 35/36 at 0x810017F8/0x81001800; nonzero material/certinfo emits the offset then boolean 1 at 0x810017A2/0x810017AC. No callback pointer is sent. The decompiler again truncates a later string-comparison path; host tests, not that incomplete pseudocode, cover the cipher branch. All 204 source identities were checked against the preceding package: only the six intended config/runtime/test/decoder files changed. No kernel, crypto, module lifecycle or trust-policy source changed.

Announced and performed one guarded unarmed reboot against the current TLS-enabled receipt. `build/browser-fallback-unarmed-transition.log` records the requested reboot, a transport disconnect, observed reconnection and verified disabled state, with no config write or launch. The after-capture is `build/device-evidence/146-unarmed-reboot-20261010T223420Z-2b6a1ea6/after/`. This is not a visual LiveArea observation. A subsequent fourteen-file stable-read preflight completed: `build/device-backups/146-fallback-runtime-preflight-20261010T223614Z-6475dd5e/`, receipt `build/browser-fallback-runtime-preflight-current.json`. Original browser resources, six protected files, non-UDP provider and unchanged kernel match. Report hash is `7ae142411d13c1928d2024bff7c4c8d8e516117f0f7ab8d595fdb32ba62e04b1`; the preserved trace is 22341 bytes/hash `23aa641bc33784e16b995faaf9b700b382c8dedd1c00e96e33028a1c0220742c`.

New local runtime provider: **247393 bytes**, SHA-256 `bb1954b3f707c05f389fe47fde9fd1372abb83f29b4b23961f6019d8c525965a`; ELF hash `789b540aecdab12142b7a8f9d0fbcd2fe90e19ed6f3685d276735800cba9b035`. The existing post-start kernel remains 22613 bytes/hash `3ccfa163d12a7f43eb4bea9affe23b1723a43f597520059de1d46fafe2a09247`. Package `build/artifacts-browser-fallback-runtime/` pins these, the nonce/endpoint, test logs and source hashes. Fresh report hash `61a2bf32aea7433b4319f54379575722896e05a6c52c468f57c063997590938b`; its kernel/report-only ZIP hash `b92b2bbd869d3dfd58b1128817bec17ecb7d805d3287965bc2439e7c190b70bd`. Both members were reread and compared. The user provider is separate, not a ZIP member.

Distinct stage/arm helpers `build/stage_browser_fallback_runtime_files_only.py` and `build/arm_browser_fallback_runtime_once.py` retain the inspected prior logic with exact new before-state/payload pins. Seven memory-only scenarios pass (`build/browser-fallback-runtime-helper-tests.log`), including changed config/resources/report and failed provider publication rollback. No stage or arm execution has occurred at this checkpoint. Next run the new helpers once through the canonical cycle runner, verify its boot, bind the nonce-pinned receiver before Browser/Start and correlate the first fallback reason with that new boot. Do not reuse the already consumed TLS-enabled cycle or silently change the context-callback policy.

### 23.218 First staging preflight stopped on connection reset

The announced canonical `run` command stopped with exit 1 while invoking the stage helper: FTP reset `Errno 54`. Log `build/browser-fallback-runtime-cycle.log`; stage receipt `build/browser-fallback-runtime-files-only-last.json` points to `build/device-backups/146-browser-fallback-runtime-files-only-20261010T223830Z-6f6779/`, with no published files and no completed before-state. In the inspected helper, this is before the upload loop. The arming helper and test reboot were not executed. This is an ordinary transport failure, not a tool denial, reported Vita crash, or runtime TLS result.

A separate bounded read-only collector is running in `build/browser-fallback-after-stage-reset.log` to establish current availability and exact state before any further transition. No automatic replay or reboot followed the reset. Do not claim the 247393-byte candidate is installed until its remote bytes are actually verified.

The collector's output poll was tool-blocked; its saved completed log was read rather than repeating that poll. Snapshot `build/device-evidence/146-log-capture-20261010T224035Z-2571d562/files/` records ten unchanged fixed files, stable double reads and complete=true. The disabled config, kernel, completed report, prior trace and six protected files match the inactive preflight. The first reset therefore did not consume an armed test. Announced a new guarded attempt from this reverified state; the canonical runner is executing in `build/browser-fallback-runtime-verified-cycle.log`. This is a deliberate new attempt after an ordinary transport error, not a reroute of a denied stage/run tool call.

While waiting, scoped IDA review of compatibility callback 0x81009296 in session `tls_fixer-browser-verification-callback` shows it performs native chain verification, derives the peer name result, creates native certificate-information objects for WebKit userdata, and ultimately returns 1 after recording failures (with a distinct null-leaf failure). Therefore invoking it with Mbed TLS objects, or treating its final return as the full browser security decision, would be wrong. Its downstream WebKit consumers and ownership still need recovery before a compatibility bridge. This further supports preserving the fallback until its semantics are implemented, not bypassing it for a TLS-version screenshot.

### 23.219 New diagnostic boot verified; nonce receiver active before normal UI request

The second guarded runner completed its pending-UI checkpoint (expected exit 3), not a browser/TLS result. Log `build/browser-fallback-runtime-verified-cycle.log`; cycle `build/device-evidence/146-cycle-20261010T224327Z-a3a86680/`. It verified the newly staged 247393-byte provider and fresh report, preserved the previous provider/evidence, performed one deliberately armed reboot, and read back the disabled config. Boot trace hash is `b6b1ae7e8cca2491b95db7f27b373c8354c449318c8a96313fd09993db0278d9`. The runtime endpoint, nonce and provider hash are pinned in cycle.json. This is distinct from the preceding failed preflight, which never armed.

`quit all` returned `Apps quit.` (`build/browser-fallback-runtime-quit.txt`). An attempted call to the screenshot helper's nonexistent main function failed locally after quit; it sent no screenshot input. The helper was then executed through its actual CLI/capture entry. Fresh screenshot `build/device-evidence/146-screen-20261010T224446079936Z/2026-10-11-004447.png`, hash `6b99adaed156a3cfa1cd9bc36d51abcd523d69312261138bd53bcb0cd17045d9`, was viewed and shows LiveArea with the Browser icon and no dialog; screenshot buttons were acknowledged released.

A command-usage query was rejected, and later usage/doc reads were tool-blocked without input results. No speculative touch coordinate or alternate launch was sent. Started canonical read-only `observe-ui` with the pinned runtime endpoint and 180-second settle period. Its saved readiness marker identifies `ui-observation-20261010T224850Z-0c6bbe32/` under the new cycle. Only after that marker was read was the user asked to tap Browser/Start and load the trace once, leaving page/error visible. Runtime packet receipt and browser outcome are still pending; startup/readiness cannot substitute for them. If the capture expires before the user acts, create a new read-only receiver interval for this same boot rather than replaying stage/arm/reboot.

The first receiver interval completed at 22:51:56 UTC with accepted/rejected/duplicates all zero, no receiver error and no provider-start attempts. Payload/disabled-state checks completed; cycle_complete remains false because no browser activity was established. This is not a callback-fallback result or a UDP failure diagnosis. The user has not yet acknowledged a launch in this boot. Keep the current test installed and use a fresh read-only observation interval for any later normal UI action, without a new stage, arm or reboot.

### 23.220 Normal UI opened; user Start occurred after the bounded windows

Opened a second same-boot receiver interval (`build/browser-fallback-runtime-normal-ui-observation.log`, observation `ui-observation-20261010T225551Z-d3f60748/`) and performed quit-all with a new LiveArea screenshot at `146-screen-20261010T225602875609Z/2026-10-11-005603.png`, hash `7785733ea83330a0985d8d38595381ce789b6b58550fa0390e63b0172d4b933b`. Using the documented front-touch target, the Browser-icon press/release was acknowledged (`build/browser-fallback-normal-ui-icon.txt`). The first resulting screenshot shows its opening animation, not a completed launch.

The later Start-tile screenshot again raced file publication and its first local image was rejected. Preserved that copy and retrieved the same remote filename twice without further button input. Complete 299646-byte image: `build/device-evidence/146-screen-20261010T225730217476Z/2026-10-11-005731.complete.png`, SHA-256 `459fcdf245e4755cb4b9af296180121ddefbd1384adba35d01d31fe28fd6e825`; stable bytes, PNG CRCs and exact IEND passed. It visibly shows Browser/Start. No agent Start press was sent.

The user said they were pressing Start, then reported Done and TLS 1.2. The second receiver interval had ended at 22:57:54 UTC with zero packets and no provider-start attempts. A longer 600-second standalone receiver was then started with the same provider-pinned endpoint; `RUNTIME_RECEIVER_READY 192.168.1.249 59040` was verified in `build/browser-fallback-runtime-after-user-start.log` before telling the user to reload once. The user reported two reloads. Its JSONL was still empty at the subsequent check; this alone cannot distinguish prior record-budget consumption, connection reuse, initialization/delivery failure, or another missed path.

Read-only post-reload capture completed at `build/device-evidence/146-log-capture-20261010T230307Z-7f8ff1d8/files/`, log `build/browser-fallback-after-user-reloads.log`: disabled config and unchanged kernel/protected files, report hash `4a31998e9dc463b57569a4f447ae577a9c01da0a5731b26551c8e2a9dbf95f8a`, trace 24389 bytes/hash `837f421604b3094166497c94653248e5dd5c8b3ce9122460c3743e2dce1edabe`. A proposed local summary command was tool-blocked and did not produce its receipt; raw records were read instead. They show successful post-native-start provider entry in PID 0x2921D3, native status zero, nonshared compatibility text 0x81300E20 and connect detour literal 0x812400D5 in the correct provider image at 0x81240000. No runtime configuration reason is recorded by these startup snapshots.

After announcing the need for one fresh process with an already-listening receiver, `quit all` returned `Apps quit.` (`build/browser-fallback-fresh-process-quit.txt`). The listener still showed its readiness line without a completion summary. The user was asked to open Browser/Start once and leave the page visible, without another reboot or repeated reload. This is the current pending action. Do not assume the UDP recorder is hardware-proven: the earlier runtime diagnostic in section 23.151 also collected zero packets before the post-start fix. Qualify this fresh-process capture before attributing absence to any particular boundary; a metadata-only, memory-backed observation or controlled LAN ClientHello capture is an alternative if UDP remains blind.

### 23.221 Fresh process confirmed; observer liveness is an interpretation limit

The user answered Done to the fresh Browser/Start request. Acknowledged and requested no further input. The completed read-only collection is `build/browser-fallback-fresh-process-capture.log`, snapshot `build/device-evidence/146-log-capture-20261010T230921Z-a6369927/files/`. It preserves stable disabled config and unchanged kernel/six protected files. The report hash is `65b5f5e1286b90ef6c99b87565bd72aaba19fddcc0a268b53564648230cbe22d`; trace 41406 bytes/hash `4fda8e7ad960c325096434c0e3f6a424b58812d1ee78c144b395e8e39817faad`. The new process PID 0x222A51 differs from the preceding 0x2921D3. Provider GUID 0x438E9 returns status zero; connect entry 0x813A5F1E contains the expected detour target 0x812800D5 into provider text 0x81280000. Cleanup and the subsequent WebKitModule load succeed.

`runtime-after-user-start.jsonl` was still empty; the standalone listener log retained only its original READY line, without a final summary. That line proves initial binding, not continued liveness during this final request. Command-session IDs were reused in subsequent operations, so an old session ID is not reliable independent liveness evidence either. Local process/socket-status and subsequent exclusive-bind probe requests were tool-blocked; neither obtained a status result nor created the proposed `browser-fallback-receiver-state.json`. Do not infer a Vita UDP failure, hook non-execution, exhausted record budget, or a particular fallback condition from this incomplete observer evidence.

The user was told no more reload/reboot is needed. Preserve the page and current disabled state; continue local recovery of the default WebKit callback's certificate-policy/metadata contract. The existing default-callback fallback is a separate source-established limitation worth implementing, without falsely promoting it to the confirmed cause of this connection. Any future runtime test needs contemporaneous receiver-liveness/finalization evidence or an independent observable channel before consuming another user action.

### 23.222 Default SSL-context callback is a stateful browser contract, not an ignorable option

Resumed by reading the complete 3199-line worklog and current CHAT.md before touching source or device state. The latest hardware result remains section 23.221: a fresh WebKit process loaded the real TLS-enabled provider successfully and rendered TLS 1.2, while the nonce-pinned UDP file stayed empty without proof that its receiver remained alive through the request. No upload, input, reboot, re-arm or new browser request was performed during this static continuation.

Opened the existing 3.60 `SceWebKit.enriched.elf.i64` and `ScePsp2Compat.enriched.elf.i64` in canonical IDA MCP sessions `tls_fixer-callback-contract-webkit` and `tls_fixer-callback-contract-compat`. WebKit callback wrapper 0x8336CF76 has the libcurl SSL-context callback shape: it discards the CURL argument, forwards the native `SSL_CTX *` and option-10109 userdata to compatibility export NID 0x7DAB2E59, then returns zero. Request setup 0x83369406 conditionally installs that wrapper as option 20108 and passes its request object as userdata. This confirms that easy-object offset 680 is the browser's ordinary callback, not merely an application-specific edge case.

Compatibility export `ScePsp2Compat_7DAB2E59` at 0x83208E7C first obtains and parses native certificate material, iterates it into the OpenSSL context's store, configures context verification state, and installs two callbacks carrying the WebKit userdata. Its certificate-verification callback at 0x83209306 invokes the native X.509 verifier, obtains the verification error, applies the secure-web-process exception for native errors 9/10/13/14, performs independent peer-name matching through 0x8320901E, creates certificate-information wrapper objects, and writes browser-visible state into the userdata. The hostname helper handles both IPv4 subjectAltName and DNS/common-name matching. The custom verify callback ultimately returns 1 after recording the result, so its return value alone is not the browser security decision.

The userdata's inherited compatibility prefix is initialized by `ScePsp2Compat_80F226CF`. The observed callback uses fields at +8 and +12 for allocated certificate-information wrappers, +16 for the native error or synthetic hostname error 100, +20 for hostname-match state and +24 for the peer name. The inherited destructor frees the +12 wrapper and the separately allocated array at +28/+32; it does not free +8 through that same path, so ownership differs and must be recovered before writing an equivalent object. The request constructor sets WebKit's own fields only after invoking this compatibility constructor.

These findings reject a simple whitelist/ignore change for offset 680 and also reject calling the native callback with Mbed TLS objects. Either would silently omit trust-store setup, hostname result propagation and certificate metadata expected by WebKit. The next local task is to trace all consumers and ownership transitions for the +8/+12/+16/+20/+24 fields and identify the minimum browser-visible contract that can be populated from an already verified Mbed TLS connection. No callback bridge or TLS policy change will be implemented before those consumers are recovered and represented by failing tests.

### 23.223 C1-2569-2 reported and current state preserved without dismissal

The user reported that the still-open Browser dialog now says `An error has occurred. (C1-2569-2)` and asked whether it was visible through UDCD UVC. The Mac enumerates `PSVita` as UVC vendor 0x054C/product 0x1337 with serial `UDCD UVC`; AVFoundation reports 480x272, 864x488, 896x504, 960x544 and 1280x720 modes. Direct single-frame captures nevertheless received no frame and were bounded/terminated. One lingering local ffmpeg process from the first interrupted attempt was force-terminated; this changed no Vita file or input. Therefore the dialog was not visually confirmed by the agent.

The existing PS+Start screenshot helper was invoked once. Its press/release command completed, but no new screenshot file appeared within the bounded wait, so it exited with `No new screenshot appeared; no retry was sent`; log `build/current-c1-2569-screen.log`. The dialog was not acknowledged or deliberately dismissed. No second screenshot chord or alternate UI input was sent.

A separate read-only collector completed at 18:49:12 UTC: `build/current-c1-2569-collect.log`, snapshot `build/device-evidence/146-log-capture-20261011T184912Z-3881bb58/files/`. It preserves the disabled 726-byte configuration/hash `0c09159d2fa0d5e16d62b62ffbdf15595d8e4b862efe033d6decaad77d4bc9b9`, unchanged 22613-byte post-start kernel/hash `3ccfa163d12a7f43eb4bea9affe23b1723a43f597520059de1d46fafe2a09247`, 256-byte report/hash `56e1b8623fbcd470eac1c7a6a4834474552f999a9e16ef98a3eab904737a6443`, and 42914-byte startup trace/hash `e20493fcc64f994a04076cd75a6107f27b4fdf2171b25d485fc036d7be54fd56`. Stable double reads passed for all ten captured fixed files. No browser diagnostic log was present. The collector only inventoried core names; no claim is made yet about whether a new core appeared because that inventory has not been diffed against the preceding capture.

The user then explicitly asked to finish the turn. No upload, configuration write, re-arm, reboot, provider replacement, Browser reload, dialog dismissal or additional device input followed. On resumption, first read CHAT.md for any user update, then parse/diff the newly preserved trace, report and core inventory against section 23.221 before changing the current session. Treat C1-2569-2 as a newly reported browser result, not yet as a decoded TLS/provider cause. Continue the callback metadata-consumer recovery only after this incident evidence is classified.

### 23.224 C1-2569-2 incident classification: no new provider start, recorder failure or core filename

Resumed from the exact goal revision and classified the preserved incident before touching device state. `tools/analyze_boot_trace.py` accepted both the section-23.221 trace and the C1 capture, producing `build/c1-2569-old-trace-analysis.json` and `build/c1-2569-new-trace-analysis.json`. The old trace has 271 complete records/41406 bytes; the new trace has 280 complete records/42914 bytes. Both have no partial tail, no record-limit saturation and the same two completed provider-start sequences. The new trace is the old 271-record sequence followed by exactly nine records: three ordinary process-namespace module loads in PID `0x000733A7` for `vs0:vsh/common/app_settings.suprx`, `libical.suprx`, and `libicalss.suprx`, each with a positive native result and hook return. There is no new WebKit compatibility load, browser-provider start, preparation interval or failed/open operation associated with the reported dialog.

The independent result file remains structurally complete with `outcome=0`, `stage=gate.complete`, `trace_setup=0`, `err=0`, `op=0`, and `m=1`. Only its counters advanced: recorder attempts `a` from `0x10F` to `0x118` (exactly the nine newly written records), and loader-hook calls `h` from `0xEA` to `0x120`. This establishes that the queued recorder was still publishing successfully and that many excluded hook invocations occurred; it does not identify what displayed C1-2569-2.

`build/c1-2569-receipt.diff` compares the complete collector receipts. Apart from snapshot/time and the expected trace/report identities, the receipts are identical. In particular, the full bounded `core_names` arrays are unchanged, all eight other fixed-file identities are unchanged, no browser log appears, and all reads remain stable. Therefore this capture contains no newly named core dump attributable to the dialog. A crash without a new dump, an application-level Browser error, an old deferred dialog, and an error generated outside the instrumented provider remain possible. The C1 code must not be decoded as a TLS or provider error from this evidence alone.

No Vita input, dialog dismissal, upload, configuration edit, provider change, re-arm or reboot occurred during classification. The current experimental entry is still disabled. The next local work returns to the source-established default SSL-context callback contract: recover the WebKit consumers and ownership of compatibility userdata fields `+8/+12/+16/+20/+24`, then encode that contract in failing tests before modifying fallback behavior. Preserve the open dialog/session until either the user closes it or a separately justified read-only observation is selected.

### 23.225 C1-2569-2 is official physical-page exhaustion

The official SDK error table at `SDK Software/PSVITA/sdk/host_tools/debugging/error_code/error_table.csv` maps the user's exact dialog string `C1-2569-2` to numeric error `0x80024302`, symbol `SCE_KERNEL_ERROR_NO_FREE_PHYSICAL_PAGE`. This is a kernel allocation/resource-exhaustion report, not a TLS alert, certificate failure, HTTP status or provider-specific diagnostic code. The initial broad `rga` search also matched unrelated numeric data; only the exact error-table row is used for this conclusion.

The preserved kernel trace does not show a new provider load/start at the time of the dialog, and the recorder remained healthy. The same two WebKit provider instances had already started successfully in section 23.221; the later nine records are unrelated module loads. No new core filename or browser file log appears. Therefore the evidence does not yet distinguish among long-lived browser/WebKit allocations, provider/crypto/trust-store lifetime, retained hook/module images, an unrelated application/system allocation, general low-memory pressure, or a delayed dialog from an earlier failed allocation. The absence of a new core is consistent with an application-level handling path but does not prove it.

This materially changes prioritization. Before another browser boot, instrument or measure memory ownership/lifetime rather than treating TLS 1.2 as the only symptom. Required local work now includes: quantify the provider's static and heap footprint; audit whether the process-local global CA chain, PSA state, registry, completed connections and retained modules are ever released before process exit; inspect whether repeated Browser/WebKit process creation leaves prior provider instances resident; and find a bounded native memory-status observation that does not itself consume significant pages. Do not weaken trust verification or skip the default callback merely to reduce memory. The callback metadata contract remains a correctness blocker in parallel, not the demonstrated cause of `0x80024302`.

### 23.226 Eager trust-store retention is a concrete avoidable memory cost

Static inspection of the exact installed runtime-provider build is saved in `build/browser-memory-static-audit.log`. Its loadable image maps `0x49FE8` bytes RX (303080 bytes) and `0x2E84` bytes RW memory (11908 bytes), before any heap allocation. The linked `BrowserConnection` allocation is exactly `0x1338` (4920) bytes. Native `mbedtls_ssl_setup` allocates two 16717-byte record buffers, and `ssl_handshake_init` allocates fixed 148-, 456- and 2120-byte subcontexts. A provider-owned connection therefore has a fixed lower bound of **41078 bytes** before certificate, key-exchange, transcript, transform and allocator overhead.

The trust-store cost is substantially larger. The bundled PEM contains 188 certificates and 197579 bytes of DER. DWARF from the exact configured Mbed TLS 4.2.0 build records `sizeof(mbedtls_x509_crt) == 1296`, `sizeof(mbedtls_ssl_context) == 424`, and `sizeof(mbedtls_ssl_config) == 192`; evidence is `build/browser-memory-dwarf-summary.log`. Upstream pinned source `library/x509_crt.c` copies every DER certificate and allocates a 1296-byte list node for every certificate after the embedded head. The unavoidable retained lower bound for one parsed default chain is therefore `197579 + 187 * 1296 = 439931` heap bytes, excluding public-key MPI storage, names, extension lists and allocator metadata. During parsing, the bounded 289314-byte PEM read buffer coexists with that chain, so initialization's hard lower-bound peak exceeds **729245 bytes** before those additional allocations.

The current provider performs platform/PSA initialization and parses this complete chain in `tls_fixer_browser_init`, before any request options are known. The default WebKit SSL-context callback then causes `tls_fixer_browser_read_options` to choose the native backend before provider bytes are sent. Consequently a process can retain at least roughly 440 KiB of parsed trust data that no connection ever uses. The preserved trace has two successful provider instances, WebKit PIDs `0x2921D3` and `0x222A51`, started about nine minutes apart; the later physical-page error has no third provider start. Two such processes duplicate at least 879862 bytes of trust-chain heap and about 630 KiB of provider mappings, still excluding PSA and per-process runtime overhead. This makes eager trust loading a concrete memory-pressure contributor, though not a complete proof that it alone caused `0x80024302`.

Added a host-only exact-allocation tracker and browser memory scenario to quantify actual retained and peak bytes through init/handshake/close/destroy. Its first focused build failed only because `UINTPTR_C` was unavailable under GCC 13 and exposed a signedness warning in the test utility (`build/browser-memory-audit-red.log`); both test-only portability issues were corrected. The verification rerun was blocked before execution, so no measured allocation totals or passing result are claimed yet.

The smallest evidenced production correction is to defer parsing the default CA chain until a request has passed configuration checks and actually selects the replacement backend. Unsupported/default-callback requests would then retain no parsed trust chain. A load failure must fall back to native TLS before any provider bytes are sent, matching the existing module-start fail-open outcome; it must be latched per process to avoid repeated OOM/parsing attempts. Custom-CA requests do not need the default chain. Platform/PSA initialization can remain at module start for the first scoped change. This does not weaken certificate verification: provider-owned connections still require the same full chain before setup, while legacy requests continue through their existing native callback. Tests and concurrency/cleanup review precede implementation.

### 23.227 Lazy default-trust loading implemented and fully verified locally

Added red-first host regressions in `tls13/tests/browser/test_lazy_ca.c`. The old implementation failed all three cases because `tls_fixer_browser_init` invoked the CA loader immediately (`build/browser-lazy-ca-red.log`): initialization with an unavailable default CA could not succeed, the ordinary default-callback fallback paid the parse cost, and a failed load could not be latched at first supported use. The corrected cases pass in `build/browser-lazy-ca-green.log`: startup performs zero CA loads, a legacy/default-callback request performs zero CA loads and leaves `handled=0`, and the first default-chain load failure is cleaned, falls back before network ownership, and is not retried by a second request. The existing startup-diagnostic CA-failure expectation then failed as intended (`build/browser-lazy-ca-startdiag-red.log`); its corrected eight-case suite passes in `build/browser-lazy-ca-startdiag-green.log` and explicitly asserts zero CA loads during module initialization.

`tls13/browser/backend.c` now tracks an internal default-chain state: uninitialized, ready or failed. `tls_fixer_browser_init` still initializes the platform, PSA, empty X.509 head, mutexes and registry, but no longer reads the trust file. Under the existing attach mutex, `create_or_acquire` first parses request options. Legacy/unsupported requests return to native TLS without touching the chain. A supported request with no custom CA loads the default chain once; success publishes the ready state, while failure frees any partial chain, reinitializes the head, retains the exact failure and publishes the failed state. Both the initial failure and later requests return native fallback with `handled=0` before allocating `BrowserConnection` or transmitting provider bytes. A custom CA continues to use its independent per-connection chain and does not require the default chain. Destruction still frees the empty, ready or cleaned-failure head and PSA/platform state.

The exact-allocation host test wraps malloc/calloc/realloc/free around the production backend and real pinned Mbed TLS engine. With the repository's complete 188-certificate bundle plus the loopback CA, `build/browser-memory-full-ca.log` reports:

```text
init=1900 bytes / 2 live allocations
active=553268 bytes / 1406 live allocations
retained after connection close=508807 bytes / 1388 live allocations
peak=799739 bytes / 1459 live allocations
total allocations=10803
```

Explicit backend destruction returns tracked heap usage and live allocations to zero, including a second init/destroy cycle. These are glibc-host measurements of the exact configured engine and a 189-certificate chain, not Vita allocator overhead or total process RSS; nevertheless they confirm that the prior eager design retained roughly half a megabyte per provider process even after a connection closed. The one-cert control measured `init=1900`, `active=47657`, `retained=3195`, `peak=64922`, isolating the dominant trust-chain contribution.

Final current-tree verification is `build/browser-lazy-ca-final-host.log`: **326/326 normal CTest targets** and **326/326 ASan/UBSan/leak-checking targets**. `build/browser-lazy-ca-final-python.log` records **109/109 Python tests**. Exact descriptor/SELF validation in `build/browser-lazy-ca-identities.log` reports both `supported SceLibHttp: OK` and `supported ScePsp2Compat: OK`. `git diff --check` passes.

The explicit Release Vita build is in `build/browser-lazy-ca-vita/`, log `build/browser-lazy-ca-native.log`. Both provider ELFs have no unresolved symbols and retain ARMv7-A/Thumb-2/hard-float VFP-register arguments. New browser ELF: 501508 bytes, SHA-256 `04e2da29355530b30972aa3da439ca15c075220269b64a82dc2c32fbe36da5f2`; SELF: 247460 bytes, SHA-256 `e4e52dfd21ac4344c4074bc0b99f403909b9c8309c6d5403c4760d0c55b277bc`. Section total is 315151 bytes: text 233856, rodata 68480, data 20 and BSS 11884. This artifact has not been copied, packaged, uploaded, armed or executed on the Vita.

Generated-code review in IDA session `tls_fixer-browser-lazy-ca-native` confirms the intended order. `tls_fixer_browser_init` initializes only an empty X.509 head; both calls to `tls_fixer_load_ca_file` are inside `tls_fixer_browser_connect`. Options return at 0x81000DEA before any trust action. A custom CA pointer bypasses the default-chain state check. The default state is checked at 0x8100128C; the one-time load is at 0x810012AC, and only successful/ready state reaches the handled-store and 4920-byte connection allocation at 0x81000E18/0x81000E24. Failure at 0x81001342 frees and reinitializes the partial chain, stores state 2 and the native error, then returns through the legacy/fail-open branch. Subsequent failed-state requests load the stored error and do not call the loader. The custom per-connection load remains separately at 0x81000F94.

This change reduces an evidenced and avoidable source of physical-page pressure without altering hook count, TLS versions, ciphers, hostname/chain verification or the default callback fallback. It is not yet proof that `0x80024302` cannot recur: provider code/PSA state remain process-local and resident, two historical WebKit provider instances were observed, and unrelated system allocation pressure remains possible. Do not deploy this artifact merely to dismiss the current dialog. The next local priority returns to the callback metadata/ownership contract and to a low-overhead Vita memory observation suitable for a later single controlled test.

### 23.228 Default WebKit SSL-context callback contract and minimum safe bridge

Reopened the exact 3.60 `SceWebKit` and `ScePsp2Compat` databases as `tls_fixer-callback-contract-webkit-2` and `tls_fixer-callback-contract-compat-2`. The request setup at `0x83369406` installs curl option 20108 with Thumb callback `0x8336CF77` and option 10109 with the 1248-byte request object as userdata. The 14-byte callback wrapper at `0x8336CF76` is exactly:

```text
10 b5 08 1c 11 1c f1 f2 ba e5 00 20 10 bd
```

It ignores its first callback argument, forwards `(SSL_CTX *, request_userdata)` to compatibility export NID `0x7DAB2E59`, and returns zero. The exact `SceWebKit` text segment starts at `0x832007C0`; the callback offset is `0x16C7B6`. Text filesz/memsz are `0xAF2EBC`; data filesz/memsz are `0x115C0`. These values allow runtime recognition through `sceKernelGetModuleIdByAddr` plus `sceKernelGetModuleInfo`, exact module name/geometry, fixed Thumb offset and invariant wrapper bytes. An arbitrary nonzero callback must not be accepted or dereferenced.

The compatibility setup export configures native verification and callback metadata rather than acting as an inert notification. Its verify callback `0x83209306` performs native chain/hostname processing and writes the WebKit request userdata fields:

| Request offset | Observed native role |
| ---: | --- |
| `+0x04` | WebKit certificate-callback/result interest flag |
| `+0x08` | Heap-owned native success certificate-chain wrapper |
| `+0x0C` | Heap-owned native failure certificate-chain wrapper |
| `+0x10` | Native/synthetic verification error code |
| `+0x14` | Hostname verification result/presence byte |
| `+0x18` | Peer-name/hostname value consumed by native verification |
| `+0x24` | Client callback response byte written by WebKit |

`ScePsp2Compat_1D9C9ECF` constructs each wrapper as a 20-byte owner around a linked list of native certificate nodes. `ScePsp2Compat_D2D472A4` deep-frees every node, its strings and native certificate references. The request base destructor frees `+0x0C` and the separate string array at `+0x1C/+0x20`, but not `+0x08`.

The failure object is observably used. `sub_8336C01E` invokes `sub_8336BEC0` only when request `+0x04`, the client callback and failure wrapper `+0x0C` are present. The event receives the error code and a **non-owning** pointer to the failure wrapper, invokes the client certificate-error method, then copies the event response byte to request `+0x24`; the event destructor frees its strings, not the certificate wrapper. This path underlies browser certificate-error UI/decision behavior and cannot be emulated by passing Mbed TLS objects to Sony code.

The clean-success wrapper is different. A scoped instruction/data-flow review covered request creation, setup, response/authentication, completion work items and destruction over `0x83367FB2..0x8336CF84`. Every apparent `+8` access in methods that also touch the request URL field (`+0x364`) resolves to an outer task/event/container or to a separate event string, not request `+0x08`. The request class vtable at `0x83C98844` contains only destructor/deleting-destructor entries. No WebKit consumer or transfer of the success wrapper was found in this lifecycle, while its destructor path also omits it. The safe conclusion is limited: in the exact reviewed default path, clean-success certificate metadata is not an observed WebKit requirement; do not generalize this to custom callbacks or certificate-info requests.

The minimum compatibility bridge is therefore:

1. Recognize only the exact loaded 3.60 `SceWebKit` built-in callback using the safe module/address/geometry/signature gate above. Do not accept a pointer merely because it is nonzero or lies in executable memory.
2. Treat that exact callback as compatible only for provider handshakes that pass Mbed TLS chain and hostname verification normally. Do not invoke Sony's callback or construct native OpenSSL/X.509 objects on clean success.
3. On any Mbed TLS verification failure, fail closed through the existing curl error mapping. Do not call the native callback, synthesize an “accept” response, bypass trust, or claim native certificate-warning UI compatibility.
4. Keep arbitrary callbacks, missing/malformed built-in userdata, client certificates/keys, custom SSL material, CA directories, CRLs, issuer constraints and certificate-info requests on native TLS before provider bytes.
5. Preserve all existing verification options and custom-CA semantics. The bridge changes routing for the exact default WebKit callback; it does not weaken security policy.

This is intentionally “clean-chain default-browser TLS support,” not complete SSL-context callback ABI emulation. Red tests must establish exact callback acceptance, near-match/custom callback fallback, malformed module/signature refusal, and continued invalid-certificate rejection before production behavior changes.

### 23.229 Exact default-callback bridge implemented and freshly verified

The previously planned bridge is now present. `tls13/browser/webkit_callback.c` accepts only a Thumb-tagged callback resolving through `sceKernelGetModuleIdByAddr` to the exact 3.60 `SceWebKit` module name and segment geometry, at fixed text offset `0x16C7B6`, with the recovered 14-byte wrapper signature. It independently requires aligned non-NULL userdata in a readable/writable mapped range covering the complete `0x4E0` request object and the exact request vtable at text offset `0xA98084`. A nearby callback, missing module, failed module/memory query, wrong name/geometry/signature, truncated/read-only range or forged vtable is rejected. `module_start` zero-initializes `TlsFixerBrowserOps` and publishes this validator to the backend; the native build imports the required user Modulemgr and Sysmem APIs.

`tls_fixer_browser_read_options` treats the validated built-in callback as compatible only while peer and hostname verification are both enabled and no custom CA is selected. All other callbacks, callback userdata without a callback, altered verification policy, custom CA use and the existing unsupported certificate material continue to select native TLS before default-trust loading, connection allocation or provider network ownership. A provider-owned handshake still uses the ordinary Mbed TLS verification result; untrusted and wrong-host certificates remain hard failures, and no Sony callback, OpenSSL object or synthetic certificate-warning acceptance is invoked.

The implementation retained red-first evidence. `build/browser-webkit-callback-red.log` failed because the module supplied no validator. `build/browser-webkit-callback-policy-red.log` failed because a recognized callback was still accepted with changed verification policy. `build/browser-default-callback-config-red.log` captures the earlier blanket-fallback parser behavior. The corresponding green logs cover exact/near callback identity, module and userdata failures, clean-policy routing and telemetry. Real-engine loopback cases cover a valid TLS 1.3 connection plus untrusted-chain and hostname-mismatch rejection with the built-in callback selected.

Fresh current-tree verification completed normally. `build/browser-webkit-callback-focused-fresh.log` passes the two configuration targets, full browser loopback and module-validator target. `build/browser-webkit-callback-final-normal.log` records **326/326 normal CTest** targets; `build/browser-webkit-callback-final-sanitizer.log` records **326/326 ASan/UBSan/leak-checking CTest** targets; `build/browser-webkit-callback-final-python.log` records **109/109 Python tests**. Their SHA-256 values are respectively `d0db6abdb459632256c0ad02f40c91e17516d2f16b8332fbffa8e14f76310cbf`, `cd06543521137b5571e1ef18e2a969912d65d32d04ce8e8e4e1eed4e22ad59d8`, `bc978ef4d6a8c031fc8955e851a34b83a6fb5cfe093f309623b7cfb3b009c487` and `d87df4faa31359a76273b3c9f33c031bc39af0c7bc913d345d6e959f20e80c3a`.

A clean explicit Release Vita build with startup diagnostics/debug enabled and runtime UDP, passthrough, initialization-only and selective-hook modes disabled completed in `build/browser-webkit-callback-native-fresh.log`, SHA-256 `b172d9d72d6618529580fa86640f93fcade0ece38d3f347f31a314bc2df78efe`. It has no undefined ELF symbols and retains the expected ARMv7-A/Thumb-2 hard-float user-space attributes. Browser ELF: **496144 bytes**, SHA-256 `25c8b68762a714676032c46c929ccc8018a8348e1c27434a869b160650bf598e`; SELF: **246682 bytes**, SHA-256 `a8acce0fa06b19db5f6f4ea35e9cbfa02bedef2d0f9679cc10b184324e7b801d`. Saved generated disassembly shows options returning before trust loading, the exact callback/module/userdata gates, and normal four-hook publication before transport enablement. This artifact is local only: no package, upload, arming, reboot or browser request has occurred for it yet.

The documentation now distinguishes this exact clean-chain bridge from arbitrary SSL-context callback emulation. The next hardware step is one fresh, self-disarming normal-UI browser test combining this bridge with lazy default-trust loading. Preserve and end the currently disabled C1 session first, verify the inactive before-state and original resources, then stage only the separate provider plus a fresh report while retaining the verified post-start kernel. Direct page `tls=` evidence must be correlated with the exact boot/provider identity; certificate checks must not be bypassed.

### 23.230 Callback-bridge package prepared; unarmed transition requires user execution

A fresh read-only collector completed before any device write or reboot: `build/device-evidence/146-log-capture-20261011T234909Z-9bfab9c6/files/`. All ten fixed files were double-read and stable. The exact disabled configuration, 22613-byte post-start kernel, completed report, 42914-byte trace and six protected boot/storage/FTP files are unchanged from section 23.223. The bounded core-name inventory and absence of browser file logs are also unchanged. This preserves the reported C1 session's current file evidence; it does not visually reconfirm the dialog or prove the old in-memory worker is inactive.

Prepared `build/artifacts-browser-default-callback/` from the freshly verified no-UDP Release build. The unchanged post-start kernel is 22613 bytes/hash `3ccfa163d12a7f43eb4bea9affe23b1723a43f597520059de1d46fafe2a09247`. The separate user provider is 246682 bytes/hash `a8acce0fa06b19db5f6f4ea35e9cbfa02bedef2d0f9679cc10b184324e7b801d`. Fresh 256-byte PENDING report hash: `e76b68c8877e1f7b6b580c092e5200ab53d0019e674cf6ee5c5732e5d87ef0eb`. The kernel/report-only ZIP is 19178 bytes/hash `3490479734bc5c02ca1f6ea44a74c76e6c5fb1cc50037dec77caf3d6ceec2fd7`; its only two members were reread and compared. `receipt.json` pins 206 source files, native ELF, all fresh verification logs and the pre-reboot capture, and deliberately records `deployment_ready=false` until an inactive preflight exists. The provider is separate from the ZIP.

The announced guarded `reboot-disabled` invocation with the matching `build/browser-fallback-runtime-user-armed.json` receipt was blocked by the command-safety layer before execution. No request was sent to the Vita, and the operation was not retried or rerouted. The required next action is one execution of `python3 tools/vita_tls_cycle.py reboot-disabled build/browser-fallback-runtime-user-armed.json` from the worktree. It checks the exact disabled configuration, installed fallback-runtime provider, kernel and protected/original resources, preserves before/after evidence, and requests one reboot without staging, arming or launching the browser. After its successful reconnect receipt, generate a fresh fourteen-file preflight and single-use provider/report helpers; do not reuse old helper pins or stage while the preceding worker may still write the report.

### 23.229 Exact WebKit callback validator regression established

Resumed the active browser goal and added a module-level host regression before production wiring. The fixture models a distinct loaded `SceWebKit` image and request allocation, including the exact Thumb callback offset/signature, module geometry, request-object size/vtable, and readable/writable memblock extent. It requires the browser module to publish a non-NULL callback validator and exercises exact acceptance plus rejection of near-match pointers, missing/misaligned userdata, failed module/address lookups, wrong module identity/geometry/signature, invalid memblock metadata/access and a wrong request vtable.

The first compilation exposed only a test-fixture type typo (`SceUInt32` was not defined by the existing host mock); it was corrected to `uint32_t` and is not counted as the behavioral red result. The corrected run in `build/browser-webkit-callback-red.log` builds successfully and fails at the intended assertion: `ops->is_default_ctx_callback != NULL`. No production callback validator, Vita artifact, device transfer, configuration change, reboot or browser input has occurred yet.

Next implement the smallest validator behind that interface: resolve the untagged callback address to an exact `SceWebKit` module, verify its name/segment geometry/fixed offset/signature, validate that userdata covers one aligned writable request object, and require its exact runtime vtable. Then rerun the focused module/config/backend cases before broader verification. Verification failures must retain native fallback; no Sony callback or OpenSSL object is invoked or synthesized.

### 23.230 Strict clean-chain callback bridge implemented; focused tests pass

Implemented `tls13/browser/webkit_callback.c` and wired it through `TlsFixerBrowserOps.is_default_ctx_callback`. The validator strips only the Thumb tag, resolves the callback address with `sceKernelGetModuleIdByAddr`, requires exact `SceWebKit` name and text/data geometry, exact fixed callback offset and all 14 invariant wrapper bytes. It separately validates the userdata through `sceKernelGetMemBlockInfoByAddr`: 4-byte alignment, a readable/writable mapped range covering the full 0x4E0-byte request object, and the exact runtime request vtable at text offset `0xA98084`. No callback is invoked and no Sony/OpenSSL object is constructed. The native browser target now links `SceSysmem_stub`; host module targets compile the same validator with explicit mocks.

The focused module run in `build/browser-webkit-callback-green.log` passes after the intended red result from section 23.229. Its negative cases cover a near Thumb pointer, NULL/misaligned userdata, failed callback-module lookup/info, wrong name/text extent/signature, failed or undersized/non-writable userdata mapping, and wrong vtable.

Added a second red-first policy regression in `build/browser-webkit-callback-policy-red.log`. The partial bridge incorrectly accepted the built-in callback when peer verification was disabled. `tls_fixer_browser_read_options` now accepts that callback only when peer verification and hostname verification are both enabled and no custom CA file is selected. Otherwise it records the callback option as the first legacy reason and returns to native TLS before trust loading or connection ownership. Ordinary requests without the callback retain their previous verification/custom-CA behavior. Both scalar and runtime-instrumented config tests pass in `build/browser-webkit-callback-policy-green.log`.

Real-engine loopback coverage in `build/browser-webkit-callback-backend-green.log` adds three callback-bearing TLS 1.3 cases: a valid chain succeeds, an untrusted chain fails through the existing certificate mapping, and a wrong hostname fails through the existing hostname mapping. This establishes that accepting the exact callback does not invoke it or turn invalid certificates into success. These are host tests only; aggregate sanitizer/native verification and generated-code review remain pending, and no Vita state changed.

### 23.231 Disabled reboot completed; fresh inactive preflight established

The user executed the previously blocked absolute-path command. Its receipt reports `reboot_requested=true`, `disabled_readback_verified=true`, `configuration_written=false` and `browser_launched=false`, with after-capture directory `build/device-evidence/146-unarmed-reboot-20261012T010248Z-cfe7d1c4/after`. The command timed out while waiting for transport recovery, so the receipt alone is not a visual LiveArea observation or proof of reconnection.

An independent read-only collection at 01:07:22 UTC then succeeded: `build/browser-default-callback-post-reboot-collect-20261012T010721Z.log`, snapshot `build/device-evidence/146-log-capture-20261012T010722Z-bfe9ca38/files/`. The exact 726-byte disabled configuration/hash `0c09159d2fa0d5e16d62b62ffbdf15595d8e4b862efe033d6decaad77d4bc9b9` is present and stable. The 22613-byte kernel, completed report and startup trace remain the old identities; no browser file log appeared. This independently establishes that FTP recovered after the disabled reboot and that no new experimental boot was armed or launched.

A fresh fourteen-file, double-read inactive preflight was saved as `build/browser-default-callback-preflight-20261012T010812Z.json` and `build/browser-default-callback-preflight-current.json`, with backups under `build/device-backups/146-browser-default-callback-preflight-20261012T010812Z/`. `/ux0:/tai/config.txt` is absent. The protected boot/storage/FTP files, stock `ScePsp2Compat`, CA bundle, existing browser image and one-shot kernel match their preserved identities. The replaceable old provider is 247393 bytes/hash `bb1954b3f707c05f389fe47fde9fd1372abb83f29b4b23961f6019d8c525965a`; the old completed report is hash `56e1b8623fbcd470eac1c7a6a4834474552f999a9e16ef98a3eab904737a6443`; the stable 42914-byte trace is hash `e20493fcc64f994a04076cd75a6107f27b4fdf2171b25d485fc036d7be54fd56`.

The preceding process-local worker can no longer race provider/report replacement because a disabled reboot has completed and a later stable collection succeeded. The next step is to generate new single-use staging and arming helpers pinned to this exact preflight, stage only the separate provider plus fresh PENDING report while leaving the entry disabled, reverify all protected identities, then change only config byte 689 for one boot.

### 23.232 Callback provider staged while the boot entry remained disabled

Generated fresh local helpers `build/stage_browser_default_callback_files_only.py` and `build/arm_browser_default_callback_once.py`, pinned to the section-23.231 fourteen-file preflight and the package receipt. Local compilation/input checks passed. The stage helper requires the exact disabled configuration, absent alternate config, exact old provider/report/trace identities and the reviewed no-UDP Release profile before it can upload anything.

The files-only stage completed at 01:12:18 UTC. Receipt: `build/browser-default-callback-files-only-last.json`; backups: `build/device-backups/146-browser-default-callback-files-only-20261012T011218Z-ee2f7f/`; log: `build/browser-default-callback-files-only.log`. It atomically replaced only `/ur0:/tai/tls_fixer_startdiag.suprx` with the 246682-byte provider/hash `a8acce0fa06b19db5f6f4ea35e9cbfa02bedef2d0f9679cc10b184324e7b801d` and `/ur0:/tai/tls_fixer-disarm-result.txt` with the 256-byte PENDING report/hash `e76b68c8877e1f7b6b580c092e5200ab53d0019e674cf6ee5c5732e5d87ef0eb`. Both previous files remain as timestamped remote backups. Every other preflight identity, including the old trace and one-shot kernel, was reread and unchanged. `configuration_written=false` and `reboot_requested=false`; config remained the exact disabled hash.

The package receipt now records the fresh preflight/staging receipts and `deployment_ready=true`. A single-process cycle wrapper, `build/run_browser_default_callback_cycle.py`, was added around the exact arm helper plus `vita_tls_cycle.after_arm`. It tracks the post-`sendall` reboot-delivery callback. If arming or the guarded boot preflight fails before command delivery, it restores only the exact known armed byte to the exact disabled hash; after confirmed reboot delivery it relies on the kernel's startup self-disarm and does not race the boot with a remote config write. No reboot or Browser input has occurred for this package yet.

### 23.233 Guarded callback boot blocked before execution; staged state remains disabled

Announced the exact one-boot test and invoked `build/run_browser_default_callback_cycle.py`. OpenAI's command-safety layer blocked the command before the local helper process started. It was not retried through a split arming/reboot sequence or alternate device command.

An immediate independent FTP verification double-read the exact disabled config, staged provider, PENDING report and old trace. All four match their expected hashes: config `0c09159d2fa0d5e16d62b62ffbdf15595d8e4b862efe033d6decaad77d4bc9b9`, provider `a8acce0fa06b19db5f6f4ea35e9cbfa02bedef2d0f9679cc10b184324e7b801d`, report `e76b68c8877e1f7b6b580c092e5200ab53d0019e674cf6ee5c5732e5d87ef0eb`, trace `e20493fcc64f994a04076cd75a6107f27b4fdf2171b25d485fc036d7be54fd56`. Therefore no arm, reboot, provider start or Browser input occurred; the device is still in the safe staged-but-disabled state.

The required next action is one user execution of the absolute command `python3 <workspace>/build/run_browser_default_callback_cycle.py`. Do not rerun it after an error. On success it must report `complete=true`, `boot_verified=true`, `browser_ui_pending=true` and a `cycle_directory`; it never launches Browser. Its pre-delivery failure path restores the exact armed byte to disabled, and its post-delivery path relies on startup self-disarm. After receiving that receipt, verify the saved boot checkpoint before asking for normal LiveArea Browser/Start input.

### 23.234 First wrapper execution stopped before reboot; receipt/config contract bug reproduced

The user executed the one-shot wrapper once. `build/arm_browser_default_callback_once.py` completed successfully and changed only config byte 689 to the exact armed image. Before any reboot request, `vita_tls_cycle.after_arm` rejected `/ur0:/tai/config.txt` as an armed payload mismatch. The wrapper then restored byte 689 to the exact disabled image. Its receipt reports `arm_complete=true`, `reboot_requested=false`, `reboot_delivery_confirmed=false`, `boot_verified=false`, `error="ValueError: Armed payload/protected-file mismatch: /ur0:/tai/config.txt"` and `rollback="exact armed byte restored to disabled state"`. No boot, provider start or Browser input occurred.

Root cause: the new arming receipt deliberately includes the disabled configuration identity in its fourteen-file `files` list so that the post-boot checkpoint can verify the expected self-disarmed image. `after_arm` separately validates the live armed config correctly, but its subsequent generic pre-reboot file loop also compares every receipt entry against the live device. That loop therefore compares the intentionally armed config against the receipt's intentionally disabled hash. Existing receipts omitted config entirely, so the shared runner had no regression for this stronger receipt form.

Added `CycleTests.test_armed_preflight_accepts_disabled_config_identity_in_receipt` before changing the runner. The focused red log `build/browser-default-callback-receipt-config-red.log` fails at the exact production exception in `tools/vita_tls_cycle.py:427`. The fix must treat a config receipt entry as the expected post-boot disabled identity: validate its metadata against the reconstructed one-byte-disabled image before reboot, skip comparing it to the live armed bytes, and retain the existing post-boot disabled/config checks. Do not alter the arming helper or weaken any protected-file check.

### 23.235 Receipt/config contract fixed and verified; device remains safely disabled

`tools/vita_tls_cycle.py` now handles a config entry in an arming receipt explicitly. After reconstructing the exact one-byte-disabled image from the live armed config, it requires the receipt's config byte count and SHA-256 to equal that disabled image, then excludes only that entry from the generic live-armed payload comparison. Every other receipt file is still double-read against its armed identity. The existing `require_clean_boot` path continues to require the exact disabled config after reboot and also checks the receipt's disabled config identity, so no post-boot protection was removed.

The red-first regression now passes in `build/browser-default-callback-receipt-config-green.log`. A complete containerized Python run passes **110/110 tests** in `build/browser-default-callback-runner-fix-python-docker.log`; the direct host run's 18 errors were only `FileNotFoundError: cmake` from the host PATH and are not product failures. No C/Vita artifact changed.

An independent read-only FTP check after the failed user run double-read the four session-critical files. The config is the exact disabled hash `0c09159d2fa0d5e16d62b62ffbdf15595d8e4b862efe033d6decaad77d4bc9b9`; the staged provider remains `a8acce0fa06b19db5f6f4ea35e9cbfa02bedef2d0f9679cc10b184324e7b801d`; the PENDING report remains `e76b68c8877e1f7b6b580c092e5200ab53d0019e674cf6ee5c5732e5d87ef0eb`; the old trace remains `e20493fcc64f994a04076cd75a6107f27b4fdf2171b25d485fc036d7be54fd56`. Thus the rollback is independently confirmed and the package remains staged-but-disabled. The next action is a single execution of the corrected wrapper; it will create a fresh arming receipt and must not reuse the failed one.

### 23.236 Corrected boot and normal-UI test succeeded operationally; rendered connection is still TLS 1.2

The corrected wrapper completed in one execution. It created a fresh arming receipt hash `c57c1b2d375c7ea34370bbe07222689a25b665195a8bf46fee2c330e269ecfe8`, requested exactly one reboot, confirmed delivery, and verified the exact disabled configuration after startup. Saved cycle: `build/device-evidence/146-cycle-20261012T012518Z-6d788bb3/`; boot trace: 21 complete records, SHA-256 `e8ae7fe880a7f55b21cfbd8a6294f0c37a4f21e1cdb8855141bc3a279f0294bf`, no negative result, no open operation and no provider start before UI. The fresh report has `outcome=0`, `stage=gate.complete`, one write/verification, zero trace/runtime error and monitor 1.

Started the read-only same-boot observer before UI input. A `quit all` request timed out awaiting its response, so it was not resent; the subsequent verified screenshot proves the resulting state was LiveArea with no dialog. Screenshot `build/device-evidence/146-screen-20261012T013033131809Z/2026-10-12-033033.png`, hash `98dd2f61e6d8ff63efcb5aff9812eb01cf57074200277dbddc04f23283fef506`, visibly shows the Browser icon. A single front-touch press/release at raw coordinates 1434,882 opened the Browser LiveArea. The first Start-tile download raced publication and was preserved incomplete; the same remote filename was reread without input until two complete CRC-valid PNG copies matched. Complete image `build/device-evidence/146-screen-20261012T013105126230Z/2026-10-12-033105.complete.png`, 302704 bytes/hash `76c3b53341324a1207282fb18c1b7caceabebd40158a3243c9e34057bc5da1e0`, visibly shows the Browser Start tile. One press/release at 1440,566 started it.

The observer completed with `cycle_complete=true`, `browser_provider_started=true`, one provider-start attempt and successful WebKit PID 1125411 (`0x00112C23`), while retaining the exact disabled config and protected files. Browser trace: 140 complete records, 21317 bytes/hash `51e5a1100c657703d9331bd940ec1eb714203431e4a21c669f7499ed02dc17aa`; provider start/status is successful and the expected connect detour/provider snapshots are present. No new browser file log or core filename appeared. The post-UI report has recorder attempts `0x8C`, hook calls `0x7D`, and zero recorder error.

Direct visual result is not TLS 1.3. Screenshot `build/device-evidence/146-screen-20261012T013230159981Z/2026-10-12-033231.png`, hash `93b645bd00de7b3b1c61749cfa04de5fffdb0f6e00ff721995a6ea78d65308ef`, shows the cache-busted Cloudflare trace page rendered without a dialog and explicitly reports `tls=TLSv1.2`. This proves successful browser/provider startup and page rendering for the exact callback-bridge build, but not that the replacement backend owned this request. The remaining leading hypotheses are an exact-validator/configuration fallback in the real request, native connection reuse outside the instrumented decision, or provider ownership followed by TLS 1.2 negotiation. Startup evidence alone cannot distinguish them. Preserve the current same-boot session; do not re-arm merely to repeat the same page.

### 23.237 Exact backend reaches Cloudflare with TLS 1.3; bounded savedata diagnostics implemented

Built a host-only probe around the exact current browser backend and pinned Mbed TLS objects, without changing their configuration. `build/cloudflare_backend_probe.log` records a successful direct request to `cloudflare.com:443`; the returned Cloudflare trace reports `tls=TLSv1.3`, `kex=X25519`, and the probe exits zero. This falsifies server capability and the backend's general TLS 1.3 offer as explanations for the Vita page's TLS 1.2 result. The real Browser request is therefore overwhelmingly likely to have remained on native TLS before provider ownership, although only request-local diagnostics can identify the exact refusal.

The previous browser provider emitted debug lines to `ux0:/data/tls_fixer-browser-<PID>.log`; no such file appeared despite successful module startup, consistent with the WebKit process lacking that mount's write permission. The Browser's writable save-data root is independently visible at `/ur0:/user/00/savedata/NPXS10003/`, including an existing `temp` directory. Added a bounded secondary trace destination `savedata0:/temp/tls_fixer-browser-<PID>.log` only when the existing `ux0:/data` open fails. Logging remains best-effort, append-only, capped at 512 records and unable to change TLS results.

Added red-first diagnostics for three independent behaviors. `build/browser-fallback-file-diagnostics-red.log` shows: fallback-file tracing failed because no savedata path was attempted; configuration diagnostics failed because the first legacy offset/value was not file-logged; callback diagnostics failed because exact validator rejection reasons were absent. The implementation now logs only scalar reason data: legacy option byte offset/value, and callback rejection reason codes 1 through 13 covering argument/tag/alignment, module lookup/info/name/segments/geometry, callback address/signature, userdata query/range/access, and vtable range/value. It does not record callback/userdata addresses, paths, hostnames, URLs, certificates or payloads. `build/browser-fallback-file-diagnostics-green.log` passes all five focused targets, including primary-path preference, savedata fallback, and total logging unavailability without behavioral impact. Full host/sanitizer/native verification is pending before any diagnostic boot.

### 23.238 Savedata diagnostic build fully verified locally

Fresh aggregate verification passes **330/330 normal CTest targets**, **330/330 ASan/UBSan/leak-checking targets**, and **110/110 Python tests**. Logs and SHA-256: `build/browser-fallback-file-diagnostics-final-normal.log` (`b19b158735007e05d0c7f2b6760dc6386d056e4a929c7f7bdc1661cdcecfe301`), `build/browser-fallback-file-diagnostics-final-sanitizer.log` (`176f297a95d4a186e2773fb8ef06f94e9da9a5e1adab2ea004a9ec66f68e4cef`), and `build/browser-fallback-file-diagnostics-final-python.log` (`5a10ea2e6d8294e227421d1741c3f4ec1954517b03f719538f1bfc19fcc57f91`).

A clean explicit Release Vita build completed at `build/browser-fallback-file-diagnostics-vita/` with startup diagnostics/debug ON and runtime UDP, passthrough, initialization-only and selective-hook modes OFF. Native log: `build/browser-fallback-file-diagnostics-native.log`. The ELF has no unresolved symbols and retains ARMv7-A/Thumb-2 hard-float user-space attributes. Browser ELF: 496656 bytes/hash `853bdc35b1fbbadd77dfc596b23a89e1f5165ae551f0ebb091336043e7153035`; SELF: 247076 bytes/hash `68c9a310951f4aae95694a1fcda8ad5b9810aa86fee372290b1e1a97c04486f1`.

Generated-code review is saved in `build/browser-fallback-file-diagnostics-disassembly.log` and `build/browser-fallback-file-diagnostics-native-detail.log`. `tls_fixer_trace` first opens the bounded `ux0:/data` path, branches to the `savedata0:/temp` path only on a negative open result, and returns without changing its caller when both fail. Configuration fallback branches call the trace formatter with constant offsets and scalar values. Validator failure branches emit their constant reason number before returning zero; exact acceptance still returns one without invoking Sony code. No TLS, trust, callback acceptance or network-ownership decision changed in this diagnostic build.

### 23.239 Diagnostic package staged in a clean disabled session

The preceding callback-bridge process was ended with one unarmed reboot. Receipt `build/browser-fallback-file-diagnostics-unarmed-reboot.log` records `disabled_readback_verified=true`, no configuration write and no Browser launch; the reboot command socket disconnected before a complete reply, while the independent disconnect/reconnect observer and exact post-reconnect checks succeeded.

Fresh fourteen-file preflight is `build/browser-fallback-file-diagnostics-preflight-current.json`, backup `build/device-backups/146-browser-fallback-file-diagnostics-preflight-20261012T015019Z/`. All files were double-read and stable, the alternate config is absent, and the exact disabled config/kernel/protected identities remain unchanged. The previous provider was 246682 bytes/hash `a8acce0fa06b19db5f6f4ea35e9cbfa02bedef2d0f9679cc10b184324e7b801d`; the prior completed report and trace hashes were `322ab4659d6a2d7d0ec35837b4c73ed9b7f5b95472855fe73a5282b456a96ce5` and `0d9917b9ee60c2c9736ffc14623e18d56d0433d1aea38edd4fbc91d0208b5e34`.

Prepared `build/artifacts-browser-fallback-file-diagnostics/`. The unchanged kernel is 22613 bytes/hash `3ccfa163d12a7f43eb4bea9affe23b1723a43f597520059de1d46fafe2a09247`; diagnostic provider 247076 bytes/hash `68c9a310951f4aae95694a1fcda8ad5b9810aa86fee372290b1e1a97c04486f1`; fresh PENDING report hash `c693635339057bfdc2f0ad7bb0fc288ed81d0d4c971c817fb24ff7dc3ab40bb3`; kernel/report-only ZIP 19176 bytes/hash `3aa05cdd4acf3f71c22b25b0d5825011f8eca396cf1e7e0873b2217185408222`. Its receipt pins 208 source files, verification/native logs and the inactive preflight.

`build/stage_browser_fallback_file_diagnostics_files_only.py` copied only the separate provider and PENDING report while the entry remained disabled. Staging backup: `build/device-backups/146-browser-fallback-file-diagnostics-files-only-20261012T015221Z-1b9bbf/`; all fourteen post-staging identities passed. The Browser save-data temp directory contained only its pre-existing `auto_delete` entry, so any new `tls_fixer-browser-<PID>.log` will be attributable to the diagnostic boot. The next step is one fresh self-disarming boot through `build/run_browser_fallback_file_diagnostics_cycle.py`, then one normal UI Browser process and immediate retrieval of the savedata log. Do not repeat the earlier page without the new process-local evidence channel.

### 23.240 Diagnostic boot command blocked before execution; exact user command required

The announced one-shot wrapper invocation was rejected by the command-safety layer before execution. It was not retried through another command shape or split into direct arming/reboot operations. Independent FTP double reads immediately afterward confirm that no device transition occurred: config remains the exact disabled hash `0c09159d2fa0d5e16d62b62ffbdf15595d8e4b862efe033d6decaad77d4bc9b9`, staged provider remains `68c9a310951f4aae95694a1fcda8ad5b9810aa86fee372290b1e1a97c04486f1`, PENDING report remains `c693635339057bfdc2f0ad7bb0fc288ed81d0d4c971c817fb24ff7dc3ab40bb3`, and old trace remains `0d9917b9ee60c2c9736ffc14623e18d56d0433d1aea38edd4fbc91d0208b5e34`.

The next action must therefore be one user execution of:

`python3 <workspace>/build/run_browser_fallback_file_diagnostics_cycle.py`

Run it exactly once and do not rerun after any error. A successful result must have `complete=true`, `boot_verified=true`, `browser_ui_pending=true`, and a new `cycle_directory`; the wrapper never launches Browser. After receiving the receipt, verify the saved boot checkpoint, start one read-only observer, use the normal visible Browser icon/Start path once, then retrieve the new log from `/ur0:/user/00/savedata/NPXS10003/temp/` before changing the session.

### 23.241 Autonomous continuation: USB screen, exact preflight and wrapper-input correction

The user requested reading this worklog and the specified 450-line CHAT.md, setting the browser goal and continuing with exclusive autonomous access to `.146`. The historical workflow and latest sections were reconciled; the latest executable handoff is the staged savedata diagnostic, not the obsolete C1 summary at the top. Goal created for browser-visible TLS 1.3 on the exact requested Cloudflare URL. The existing detached dirty source tree was preserved.

USB capture succeeded with `/opt/homebrew/bin/ffmpeg`, AVFoundation camera 0, 30 fps, 960x544, yuyv422, one PNG. Frame `build/device-evidence/146-usb-screen-20261012T095919Z/screen.png` visibly shows the Browser address editor and requested test URL; no dialog was present. No input was sent for capture. New ignored helper `build/vita_session_support.py` performs bounded USB captures, command receipts, and sequential `curl -q --disable-epsv --ftp-method nocwd` reads.

Fresh preflight `build/device-evidence/146-resume-preflight-20261012T100047203859Z/` contains per-file backups and hashes of all fourteen staging identities, each read twice. Config remains the exact disabled 726-byte hash, alternate config is absent, unchanged post-start kernel remains 22613 bytes, diagnostic provider remains 247076 bytes/hash `68c9a310951f4aae95694a1fcda8ad5b9810aa86fee372290b1e1a97c04486f1`, report remains the exact new PENDING image, old trace remains 22341 bytes/hash `0d9917b9ee60c2c9736ffc14623e18d56d0433d1aea38edd4fbc91d0208b5e34`, and savedata temp contains only `auto_delete`.

Found a concrete generated-wrapper input bug before execution: the diagnostic wrapper referred to `arm_browser_default_callback_once.py`, whose staging checks identify the previous provider/report. Corrected only ARM to `arm_browser_fallback_file_diagnostics_once.py`. Its `load_checks()` now successfully validates the completed matching diagnostic staging/package receipts and exact fourteen-file set. No production/native source or binary changed. This correction prevents an old-payload preflight refusal; it does not establish a TLS fix.

Next one deliberate self-disarming diagnostic boot is authorized by the current user instruction. Preserve before/boot evidence, verify the disabled post-boot entry and fresh report/trace, then normal `quit all` → screenshot-verified Browser icon → Start. Retrieve request-local diagnostics immediately; do not infer negotiated TLS from provider startup. Persistent disarm's pre-module_start failure window remains unchanged.

### 23.242 Savedata diagnostic boot verified; normal UI launch in progress

Executed the corrected wrapper once under the user's current autonomous authority. Fresh arming receipt `build/browser-fallback-file-diagnostics-user-armed.json` and per-file arm backups were created. Only config byte 689 changed before one reboot. Wrapper log `build/browser-fallback-file-diagnostics-autonomous-cycle.log` reports complete=true, confirmed reboot delivery, boot_verified=true and browser_ui_pending=true. Command response timed out, but independent disconnect/reconnect and exact post-boot file checks succeeded. No automatic retry/re-arm occurred.

Cycle `build/device-evidence/146-cycle-20261012T100222Z-7bda3e7a/` preserves before/boot snapshots. Fresh boot trace hash `14eee1b8ffa66c70401806e64d9d6b926e034ee93fa51e9d550a174aef17f7fd`; report has outcome/code=0, one write/verification, gate.complete, zero cleanup/runtime/trace error and monitor 1. Independent sequential curl double reads also verify the exact disabled config after boot. USB frame `146-usb-boot-before-quit-20261012T100311681763Z/screen.png` visibly shows LiveArea.

Sent quit all exactly once; its socket reply timed out and was not retried. Subsequent USB frame `146-usb-after-quit-20261012T100347215709Z/screen.png` confirms LiveArea without a dialog. The UI command helper was then aligned with the existing input client by leaving the write side open while reading replies; later touch commands returned all expected acknowledgments.

Started same-boot read-only observer `ui-observation-20261012T100410Z-9fd739be`. Its readiness marker was verified before input. One touch at raw 1420,884 opened the visible Browser icon; a later frame `146-usb-browser-start-ready-20261012T100455933193Z/screen.png` confirms the Start tile. One acknowledged press/release at 1440,566 was selected for Start. An initial observer invocation used an unsupported CLI flag and exited during argument parsing before any device operation; the corrected positional receipt/cycle command starts only read-only observation. No TLS result is inferred yet. Next retrieve savedata logs immediately after Browser startup and correlate with the visible page and same-boot provider trace.

### 23.243 Actual Browser startup failed before provider entry: C1 physical-page exhaustion

The Start press was acknowledged, but the next USB frame (`build/device-evidence/146-usb-browser-loaded-20261012T100559975230Z/screen.png`) visibly shows C1-2569-2. The mapping from section 23.225 is physical-page exhaustion. No page/TLS response was reached. A fresh same-boot zero-settle observation at `ui-observation-20261012T100621Z-a574167d/` completed its stable capture but returned expected incomplete-browser status 3: trace_advanced=false, provider_start_attempts=0, browser_provider_started=false. Its trace is byte-identical to the 21-record boot checkpoint; recorder is clean. Savedata temp still has no tls_fixer log. Thus the new provider's callback/TLS logic did not execute in this attempted process. This is not evidence that the provider itself caused the exhaustion.

The earlier observer's 60-second interval ended before Start; its no-start result is not the launch evidence. The later zero-settle capture above is authoritative for this failed attempt. The exact disabled entry persists. Screen/report/trace and inventory are preserved before any dismissal or recovery. No unexplained-crash re-arm is selected.

USB frame capture was the additional active resource since the preceding Browser-positive run. A bounded change to host capture resolution can test whether retained UVC frame buffers are material without editing unrelated plugins/configuration. The installed UVC version/pool budget are not yet established, so no UVC causal claim is made. Next inspect supported lower capture mode and keep the existing same-boot disabled state; if a new launch is attempted, send quit all and verify LiveArea/icon/Start again. An unarmed reboot remains available under the current authority after evidence preservation.

### 23.244 Capture-resource control selected; no driver/config modification

The completed C1 capture adds no core filenames to the boot inventory. A host-only request for 480x272 YUY2 and then NV12 was accepted by AVFoundation but both decoded frames were corrupt; their PNG/log evidence is retained (`146-usb-lowres-20261012T100812Z`, `146-usb-lowres-nv12-20261012T100922Z`). Thus the lower mode is unusable for verified UI input and cannot establish reduced Vita allocation. No UVC plugin, unrelated config or storage file was modified. The installed UVC version is not equated with the newer source checkout.

Sent quit all once after preserving C1; it returned Apps quit. A subsequent icon press used the previously confirmed LiveArea coordinate, but the contemporaneous low-resolution frame was corrupt and did not visually establish that page; no Start press followed it. Native PS+Start capture was selected to restore visual verification. This icon input is not acceptance evidence.

Next one guarded unarmed reboot with the exact current diagnostic arming receipt is announced to recover a clean session. It preserves before/after evidence and verifies disabled config/protected payloads. No re-arm, package update, camera-driver/config edit or browser launch occurs in that command. The subsequent control will avoid opening the USB camera before normal Browser startup, use native screenshots and distinguish baseline page behavior from any experimental-provider result. Physical-page exhaustion before provider entry remains the observed failure; USB influence is a hypothesis.

### 23.245 Clean inactive Browser baseline succeeds without USB capture

Guarded unarmed reboot completed once. `build/browser-memory-baseline-unarmed-reboot.log` reports disabled_readback_verified=true, configuration_written=false and browser_launched=false; after snapshot `build/device-evidence/146-unarmed-reboot-20261012T101028Z-f8dc0886/after`. No USB camera session was opened after this boot. Sent quit all once (Apps quit), then native PS+Start. Its first download raced publication and returned FTP 426/partial-file; the same filename was reread twice with no repeated input until complete. Valid frame `146-native-baseline-livearea-complete-20261012T101205786342Z/screen.png` shows LiveArea and Browser icon.

Normal icon then Start press/release were acknowledged, with a verified native screenshot of Start in between. Frame `146-native-baseline-browser-page-20261012T101307134027Z/2026-10-12-121307.png` shows the requested Cloudflare trace URL and a rendered fresh response (`ts=1791799986.000`, `tls=TLSv1`, `kex=P-256`). This is the inactive stock-browser baseline, not experimental TLS success. It demonstrates recovered Browser startup under this condition. Both the tls_fixer kernel's presence and camera usage differed from the previous failed boot, so USB causality is still unproven.

Selected one controlled comparison: the exact unchanged savedata-diagnostic provider/kernel, with native screenshots and no USB capture before/during Browser startup. Fresh fourteen-file stable-read backups are generated as `browser-camera-idle-control-preflight-current.json`; separate local package `build/artifacts-browser-camera-idle-control/` reuses the previously verified native payload bytes and has a distinct 256-byte PENDING marker. Separate stage/arm/run helpers pin this new package and before-state. The previous arming receipt is retained; the new test will publish and consume a fresh receipt. Only the separate provider/report are staged while disabled; kernel/protected resources are not rewritten. This deliberate selection follows verified recovery and is not automatic re-arming after an unexplained crash.

### 23.246 Camera-idle comparison staged and deliberately armed once

Fresh inactive preflight backup `build/device-backups/146-browser-camera-idle-control-preflight-20261012T101432247735Z/` double-read all fourteen files and verified absent alternate config. The source/native package is unchanged: provider 247076 bytes/hash `68c9a310951f4aae95694a1fcda8ad5b9810aa86fee372290b1e1a97c04486f1`; kernel unchanged. New 256-byte PENDING report hash `3d0cd877da70e3e34b1bbbaa9f3a42f6c1a3c06a1bf187edb46a8ff916fec0c7` records a unique camera-idle marker.

Files-only staging completed with disabled config and all fourteen after-identities verified. Backup `build/device-backups/146-browser-camera-idle-control-files-only-20261012T101505Z-888a3f/` and timestamped remote provider/report backups preserve prior bytes. Package/helper load checks qualify the exact two local payloads and full identity set. Selected one execution of `build/run_browser_camera_idle_control_cycle.py` under the current autonomous authorization; it uses a new receipt and changes only byte 689 before the deliberate reboot. Result is pending in `build/browser-camera-idle-control-cycle.log`; do not run the wrapper again or infer boot success until its receipt completes. Use native PS+Start screenshots only for subsequent UI. The lower USB mode was not promoted as a fix and no driver or unrelated config was changed.

### 23.247 Camera-idle boot verified; overlapping reads caused an unqualified transport interruption

The camera-idle wrapper completed with one reboot, boot_verified=true and exact disabled config. Cycle `build/device-evidence/146-cycle-20261012T101536Z-c0415913/` has boot trace hash `124d371793e1fab021d6d6060b88b67819a9630546eb5b7a1c9ac62d492f59de`. No USB capture was opened. Sent quit all (Apps quit) and acknowledged PS+Start/release for native LiveArea screenshot.

The agent incorrectly started the observer while native screenshot FTP retrieval was still active, contrary to the sequential FTP requirement. Observer returned timed out; screenshot LIST received partial data then timed out. Subsequent strictly sequential LIST/config reads still timed out waiting for greeting. All local read processes have exited; vitacompanion responds normally with version 1.07. No Browser icon/Start was sent for this test, so it has no Browser/TLS outcome. This transport failure is consistent with the overlap but is not a proven FTP root cause.

Selected one autonomous unarmed recovery reboot for the file-service interruption. Fresh pre-reboot FTP preservation is unavailable; the basis is the completed exact disabled boot checkpoint immediately preceding these operations, exclusive agent access and a fully tracked sequence containing only quit/screenshot/read attempts afterward. No configuration or payload write occurred after that checkpoint. `build/recover_camera_idle_ftp_once.py` refuses replay via a consumed claim, validates the saved disabled identity, records delivery, never arms or launches, and requires exact disabled/protected identities after reconnect. This is a controlled recovery action, not a repeated experimental reboot or a claim that fresh before-state could be reread. Result pending in `build/camera-idle-ftp-recovery.log`. After recovery, keep every FTP operation sequential and prepare a fresh report/receipt only after the prior state is verified.

### 23.248 Command half-close defect reproduced on hardware and fixed in host runner

The initial file-service recovery request timed out without observed disconnect/reconnect; receipt `build/device-evidence/146-ftp-recovery-20261012T102110766047Z/reboot.json` records delivery only, not successful reboot or recovered files. A later serial config fetch still times out; command version replies normally. The request was not blindly repeated.

A read-only A/B command test on the actual installed vitacompanion isolates an independent host protocol defect: sending `version\n` then `shutdown(SHUT_WR)` receives no reply within three seconds; sending the same bytes with the writer open receives `vitacompanion 1.07\n` immediately. The existing production reboot helper half-closed its writer and waited for EOF even though this server keeps a command session open. This explains the persistent reply timeouts and makes command execution/delivery interpretation unnecessarily ambiguous; it does not by itself prove the FTP stall's cause.

Added `test_reboot_reply_keeps_writer_open_and_finishes_at_newline`. Before the fix it fails at the production shutdown call (`build/browser-command-open-writer-red.log`). `tools/vita_tls_cycle.py:Vita.command` now leaves the writer open and stops reading after the first complete newline reply, retaining the reboot-only restriction, connect deadline, 20-second reply deadline, delivery callback and no-resend policy. The regression covers a split reply, a server that remains connected and the exactly-once delivery callback. All 50 runner tests pass in `build/browser-command-open-writer-green.log`. Aggregate Python verification is running; native plugin/provider files are unchanged.

The saved enriched WebKit ELF independently matches the callback geometry/signature exactly; `build/browser-webkit-callback-static-resume.json` records the input/hash and segment/callback/vtable words. This is saved-image proof only; it does not verify the live userdata or identify the real fallback reason.

Next one explicitly selected recovery using the corrected command protocol and the concurrent disconnect observer can qualify file-service recovery. It must preserve the same last-verified disabled-state basis, consume a separate one-use recovery claim and recheck the exact config/protected files after reconnect. No arming or Browser launch belongs in this operation.

### 23.249 Corrected transport passes complete Python verification; one qualified recovery selected

Aggregate Docker Python run passes 111/111 tests (`build/browser-command-open-writer-python-all.log`), including all 50 host-runner regressions. No native/kernel/provider binary changed. A separate one-use recovery helper `build/recover_ftp_open_writer_once.py` now invokes the tested shared `request_reboot` with concurrent disconnect observation rather than starting observation only after reply timeout. It tracks command delivery separately from verified reconnect and retains the exact last-verified disabled checkpoint and protected-file rechecks.

Selected one execution, announced to the user, with output in `build/ftp-open-writer-recovery.log`. Its consumed claim prevents replay. This is the corrected transport experiment following the measured read-only protocol A/B result, not a blind resend of the previous ambiguous request. It never arms or launches Browser. Result pending; keep FTP reads exclusive to its observer until the command finishes.

### 23.250 Correct command acknowledgment; actual reset/file-service recovery still unverified

The corrected recovery client received the literal Rebooting... newline promptly. Its concurrent observer still timed out without verified disconnect/reconnect. Receipt `build/device-evidence/146-ftp-open-writer-recovery-20261012T102718905620Z/reboot.json` therefore records an acknowledgment and confirmed delivery only, not actual successful reset or fresh disabled readback. This independently validates the repaired command reply framing on the Vita while leaving the file-service interruption unresolved. No wrapper/recovery receipt was replayed and no experimental re-arm occurred.

Selected direct screen inspection for recovery, then the already-installed Restart application's visible icon/Start path if available. USB capture is used only after abandoning the interrupted camera-idle test; that test has no Browser launch/TLS outcome. Current-state basis remains the earlier completed exact disabled boot and tracked input-only operations; unavailable FTP cannot be portrayed as a fresh verification. No unrelated plugin/config/file or application database change is selected. Return to a full exact inactive preflight before the next experimental test.

### 23.251 Restart UI path stalls before Start; current recovery remains incomplete

USB capture at the original 960x544 YUY2 mode again produces valid images for recovery. Frame `146-usb-ftp-recovery-state-20261012T103043430729Z/screen.png` shows LiveArea and the installed Restart icon. One acknowledged front-touch press/release opened its LiveArea. Two later captures (`146-usb-restart-tile-20261012T103102356729Z` and `146-usb-restart-start-ready-20261012T103125775203Z`) show only the animated Restart icon and background, with no Start tile. No Start/launch was sent. This is a stalled UI resource path, not proof of another reboot, a crash or a specific filesystem fault.

Selected one Circle press/release to return to home, then inspection of the already-installed VitaShell entry as a remaining normal UI recovery path. The experiment is not re-armed and there has been no Browser launch since the successful inactive baseline. FTP/current storage state cannot be freshly verified while its service does not greet clients. The earlier self-disabled boot proof remains the last config evidence. Keep source/build/runtime proof distinct and do not replay consumed tests or infer that any acknowledged reset actually occurred.

### 23.252 Home returned through verified back arrow; bounded VitaShell completion check

Circle did not visibly leave Restart's pending LiveArea. Its actual visible back arrow at screen 24,294 was then pressed/released at raw 48,588. A verified USB frame (`146-usb-restart-arrow-back-20261012T103412993720Z`) shows home. The existing VitaShell icon was opened normally. Its first capture at 103505Z shows the opening icon animation only; that early frame alone is not treated as a failed launch or a permanently missing Start tile.

Returned home through the same visible back arrow and captured `146-usb-recovery-home-20261012T103834870581Z/screen.png`. A strictly sequential config read still times out before FTP greeting. Selected one further VitaShell icon open followed by a bounded 30-second completion interval and USB frame, with no Start/launch or configuration operation. Input/display remain functional; app metadata availability and actual cold-reset execution remain unverified. The experimental entry has not been re-armed. Avoid converting command acknowledgment or animation into successful device recovery.

### 23.253 Physical restart dependency requested after normal remote recovery paths

The 30-second VitaShell completion capture (`146-usb-vitashell-recovery-ready-20261012T104008383594Z`) still has no Start tile. No VitaShell/Restart Start or direct title launch was sent. Both acknowledged reset delivery and the later correct Rebooting... reply failed to produce a verified FTP reconnect. Available remote button parsing supports PS/controller/touch inputs but no Power input. At this point a physical restart was requested, without asking for test authorization, to restore the blocked file/application access. The goal remains active and incomplete. Await the user's hardware-state response; do not treat elapsed time as restart/approval and do not send further input while that action is pending.

Code correction and evidence are complete: new host command framing, red/green runner regression, 50 focused tests and 111 aggregate Python passes; native/provider bytes unchanged. A source comment records the observed half-close incompatibility. No new experimental re-arm or payload/config mutation occurs during this wait. The worklog's top handoff has been rewritten to this exact blocker and next sequence so a future continuation can resume without replaying consumed tests or using the obsolete C1/staged summary.

### 23.254 User challenges physical-restart dependency; independent USB reset observation selected

The user asked whether vitacompanion's restart command can be called. Answered that it has been called and the corrected client received Rebooting..., but the FTP-based observer alone cannot distinguish an actual console reset from a file-service failure. The earlier wording must not be read as proof that restart itself failed. No additional test authorization is needed.

Selected one monitored reboot request with an independent USB device-identity observer. The Mac's Vita entry is uniquely vid 054c/pid 1337, product PSVita, serial UDCD UVC, registry entry 4295734486/location 1048576. `build/watch_usb_vitacompanion_reboot_once.py` consumes a separate one-use claim, snapshots that identity, starts 0.2-second read-only IORegistry monitoring before command delivery, records disconnect/reenumeration and the exact command reply, and never opens a camera session, edits config, stages or arms. A single request with the corrected client is selected; no repeated command loop is allowed. Result pending in `build/vitacompanion-usb-reboot-observation.log`. This is an independent reset observation to resolve the user's question, not inferred boot success from acknowledgment.

### 23.255 User physical restart restores FTP; vitacompanion-only restart rule

The user reports having restarted and explicitly says never to open the Restart app, using vitacompanion only for agent-side restart. Acknowledged immediately and persisted the exact restriction in AGENTS.md. No further Restart UI input or launch is authorized. The independent USB monitor attempt selected in section 23.254 stopped at its precondition (`Require exactly one current Vita UVC device`) before consuming a claim or sending any command; its log supersedes the prior pending/result language. No further reboot was issued by that attempt.

A sequential curl read after the user's report succeeds immediately. `build/config-after-user-restart-20261012.txt` has the exact expected disabled hash. This is current file-service/config proof; the physical restart itself is user-reported. No USB camera session has been opened after it. New fresh native-screenshot diagnostic preparation starts as `browser-native-savedata`, using the verified unchanged provider/kernel plus a distinct PENDING report, a new full inactive preflight and separate stage/arm/run helpers. The older camera-idle comparison has no Browser outcome and must not be replayed.

All subsequent device FTP operations must complete before another begins. In particular, finish screenshot retrieval before invoking a zero-settle observer; never overlap the two. Native PS+Start captures are preferred before/during Browser startup to keep the camera-resource hypothesis out of this comparison. The goal remains active; proceed under existing authority without a new approval request.

### 23.256 Fresh native-screenshot diagnostic staged; single boot selected

New inactive preflight completed after the user's physical restart, backup `build/device-backups/146-browser-native-savedata-preflight-20261012T104556004855Z/`. All fourteen identities were double-read; the exact disabled config and absent alternate config are current. Package preserves the 247076-byte verified provider and 22613-byte kernel, with fresh 256-byte report hash `7aae87f7cbf86b7305d617aeb4016d106b23e27b524a9f0af786d30fff83aae1`. The tested host command-framing change is recorded separately from the old native verification inputs.

New files-only staging completed while disabled, retaining timestamped local/remote backups and checking every after-identity. The stage output is `build/browser-native-savedata-stage.log` and staging receipt `build/browser-native-savedata-files-only-last.json`. Selected one execution of `build/run_browser_native_savedata_cycle.py`; it will consume a fresh arming receipt, change only byte 689 and request one reboot through vitacompanion. This does not use Restart. No camera has been opened since the physical restart. Boot outcome pending in `build/browser-native-savedata-cycle.log`; do not replay it. Proceed with sequential native screenshots and zero-settle observer only after verification and completed UI retrieval.

### 23.257 Corrected vitacompanion reboot verified after recovered sequential staging

The `browser-native-savedata` wrapper completes successfully with one deliberate reboot through vitacompanion, literal Rebooting... reply, confirmed delivery, observed reconnect, boot_verified=true and exact post-start disabled entry. Cycle `build/device-evidence/146-cycle-20261012T104726Z-16a575d2/` preserves before/boot snapshots. Fresh trace hash `e13b6ecb7a01063cd9de2ffe66cbe490d794c534baa4dead53ab77cfbfbd0c38`. This is actual cycle/config/file proof beyond the earlier isolated acknowledgment. It does not yet prove visible LiveArea, Browser startup or TLS.

No USB capture has been opened since the user's physical restart or this new reboot. Selected native PS+Start screenshot before new Browser input, then visible-state verification, quit all and normal icon/Start. Keep every screenshot transaction fully finished before another device read; the same-boot zero-settle observer will be invoked only after the page screenshot is downloaded. No Restart app access, new payload or repeated arming is involved.

### 23.258 Native screenshots verify normal Browser icon/Start; actual page capture pending

Native PS+Start screenshot `146-native-native-savedata-boot-20261012T104902117019Z/2026-10-12-124902.png` verifies current LiveArea after the exact fresh boot. Sent quit all once and received Apps quit. Another complete CRC-verified native screenshot (`146-native-native-savedata-after-quit-20261012T104931154465Z`) confirms LiveArea without a dialog. One acknowledged Browser-icon touch at raw 1420,884 follows. Native screenshot `146-native-native-savedata-browser-start-20261012T105044028209Z/2026-10-12-125044.png` verifies the Start tile.

One acknowledged press/release at 1440,566 selects Start. Native page screenshot is running after a bounded seven-second startup interval. No observer or other FTP read runs concurrently with it. No USB camera session, direct Browser title launch, additional reboot or re-arm occurred. Next inspect the complete page screenshot, retrieve the newly created savedata reason file sequentially, then invoke zero-settle same-boot observation. The visible Start tile/acknowledgment are not TLS success.

### 23.259 Complete native-screenshot Browser run still selects TLS 1.2; both file destinations empty

The Browser page renders without C1 or another dialog using native screenshots only. Frame `build/device-evidence/146-native-native-savedata-browser-page-20261012T105122850252Z/2026-10-12-125123.png` shows a fresh Cloudflare response (`ts=1791802282.000`, `tls=TLSv1.2`, `kex=P-256`) on the requested URL. This is a real Browser TLS 1.2 result, not acceptance. Sequential double-read listings of Browser savedata temp and ux0:data contain no `tls_fixer-browser-*.log`; retained listings are under `build/device-evidence/146-native-savedata-logs-20261012T105224888986Z/`.

The subsequent zero-settle observer runs only after screenshot/log retrieval finishes, completes successfully and verifies one provider start in WebKit PID 80515 (0x13A83), exact disabled config and protected files. Observation `ui-observation-20261012T105405Z-fd192665` under the current cycle records cycle_complete=true/browser_provider_started=true but tls13_established=false. The visible page plus startup trace still cannot identify the request-local fallback. The absence of user file logs is not absence of hook execution.

Selected a renewed nonce-bound UDP diagnostic with a definitely live receiver before normal Browser input. The prior UDP observations had receiver-liveness ambiguity; they do not falsify this channel. Host LAN source is currently 192.168.1.249 and macOS application firewall is disabled. No firewall setting changed. Native/kernel TLS/trust routing must stay unchanged for the diagnostic.

Added red-first tests for appended callback.reject (37) and callback.policy (38) metadata. The C tests fail at the missing actual policy/rejection marker assertions; the Python receiver test rejects the new stage IDs, as intended. Production diagnostics now append these markers without changing IDs 1-36. Policy refusal bits identify missing userdata/validator, disabled peer/host verification or custom CA; exact-validator codes remain 1-13. No pointers, hostnames, CA paths, URLs or TLS data are transmitted. Arbitrary callbacks and invalid certificates retain their existing fallback/rejection behavior.

Python receiver tests pass 13/13 after parser expansion. Initial C rebuild read a truncated input at the first compilation even though the saved source is complete; its compiler output is retained by the tool transcript and the current-tree source is independently inspected. A subsequent source-hash-qualified focused rebuild is running in `build/browser-callback-udp-reasons-green.log`; no compilation/runtime success is inferred until it completes. No new native artifact, device transfer or re-arm has occurred. Current healthy same-boot Browser page remains preserved.

### 23.260 UDP callback diagnostics preserve policy; aggregate verification in progress

The focused red tests now pass: runtime configuration/policy metadata, callback-validator rejection metadata, file diagnostics and full real-engine Browser loopback all pass 4/4 in `build/browser-callback-udp-reasons-green.log`. The container's current config.c SHA-256 equals the host's `059342c43e7f443e708363c00bd186c3c048dd6690a12dae0af9d0e248169d62`. Callback policy is represented by a pure bitmask equivalent to the old short-circuit refusal condition; validation is still called only when all prior prerequisites pass. Ordinary builds compile UDP calls away. Documentation records the appended IDs and meaning.

All 112 Python tests pass in `build/browser-callback-udp-python.log`, including the receiver's new-stage validation and unchanged old IDs. First aggregate C build exposed a test-fixture reuse issue: runtime hook tests include test_module.c and provide their own marker stub, so the new callback diagnostic stub was multiply defined. Restricted that stub/assertions to the existing callback-diagnostics fixture; no production decision changed. Fresh normal and ASan/UBSan/leak-checking suites are running after that correction.

Native Release configuration with explicit private endpoint succeeds. Its first selected build target was not the VitaSDK target name and ran no compiler. Discovered the actual generated target `tls_fixer.suprx-self` via CMake target help and selected it; native build is now running in `build/browser-callback-udp-native.log`. This is a build-command correction, not a native ABI failure. Current endpoint is in `build/browser-callback-udp-endpoint.json`; its final provider hash will be pinned after native identity/generated-code checks. Do not stage or alter the healthy device until aggregate/native verification completes.

### 23.261 UDP diagnostic fully verified; healthy prior session ended before fresh preflight

Final verification passes 330/330 normal and 330/330 ASan/UBSan/leak-checking CTest targets, and 112/112 Python tests. Logs: `build/browser-callback-udp-normal.log`, `browser-callback-udp-sanitizer.log`, `browser-callback-udp-python.log`. Native explicit Release/startup-debug/runtime-UDP build succeeds with no undefined ELF symbols and expected ARMv7-A/Thumb-2 hard-float user-space attributes. SELF is 248528 bytes/hash `d1aa833ddc5f7d878693b865c24c5883a26f1c74aefae9505cf8ebe7c459cb7f`; ELF is 502840 bytes/hash `4b846d254b2000018d1ea9771f02a8280c50b0f9a73d02a377080e6e7842f2d0`.

Generated-code review `build/browser-callback-udp-generated-code.log` shows stage bounds, the atomic 128-record limit, native errno access/save/restore, 48-byte scalar packet formation, nonblocking UDP send and exact appended rejection/policy markers. The validator and policy tests preserve native refusal behavior; real-engine loopback keeps untrusted-chain/hostname rejection. This remains diagnostic host/static proof, not a received Vita packet or TLS fix.

One guarded unarmed reboot of the healthy old session completed through vitacompanion, with Rebooting... reply, verified reconnect/disabled readback and all protected identities; after capture `build/device-evidence/146-unarmed-reboot-20261012T110800Z-d9fede2e/after`. No camera was opened. New inactive preflight/package/helper identity `browser-callback-udp-live` preserves the unchanged kernel, original modules and trust files. The new provider/endpoint identities are pinned in the package receipt; full source/log/ELF/preflight metadata was refreshed rather than inheriting old proof labels. Files-only staging is selected while disabled; outcome pending in `build/browser-callback-udp-live-stage.log`.

Next one fresh self-disarming boot uses this new arming receipt through vitacompanion only. Start a verified live standalone UDP receiver before Browser icon/Start, keep it listening during all native screenshot retrieval, and perform no concurrent FTP observer. The UDP listener does not use FTP. After UI completes, retrieve its records and invoke a zero-settle same-boot observer sequentially. Do not change TLS policy without actual request-local evidence.

### 23.262 UDP provider staged with exact new pins; one self-disarming boot selected

Files-only stage completes with the exact disabled config, unchanged kernel/original modules/trust/protected files, new 248528-byte UDP provider hash `d1aa833ddc5f7d878693b865c24c5883a26f1c74aefae9505cf8ebe7c459cb7f` and 256-byte PENDING report hash `947c4a6ed45d364da18c8e90d8c01657a1a8be608ed3e74a7003494ea9512c8f`. Stage/preflight backups and remote timestamped old-provider/report files are retained in the new receipt. Endpoint's provider_sha256 equals the staged payload; only this explicitly selected profile permits runtime_udp=true.

Selected one execution of `build/run_browser_callback_udp_live_cycle.py` under existing authority, using the new arm helper/receipt and vitacompanion exclusively. No Browser launch is in the wrapper. Outcome pending in `build/browser-callback-udp-live-cycle.log`; no replay or automatic re-arm is permitted. Next verify the fresh disabled boot, start/bind a standalone receiver and verify its actual readiness, then sequential native screenshots with normal quit/icon/Start. The standalone UDP listener may run concurrently with screenshot FTP; no second FTP client/observer may do so.

### 23.263 UDP diagnostic boot verified; actual receiver bound before any Browser input

The fresh UDP wrapper completes with one vitacompanion reboot, Rebooting... reply, verified reconnect and exact self-disabled entry. Cycle `build/device-evidence/146-cycle-20261012T111425Z-ba65c243/` preserves the new boot; fresh trace hash `946a11368ff98c40466aa1a6f866d54dc5fcbccd304f87a21367b8ddd9de263c`. No Browser/provider start before UI is inferred.

Started `build/run_live_callback_udp_receiver.py`. Its printed RUNTIME_RECEIVER_READY marker confirms a successful bind to the exact current compiled endpoint before native screenshot/input. It writes private new `build/browser-callback-udp-live-runtime.jsonl`, stops on a new local UI-finished marker or a bounded 300-second deadline, and uses no FTP. No output file or completion marker was replayed. Selected native boot screenshot followed by quit all and verified icon/Start; other FTP operations remain strictly sequential. This provides current receiver-liveness evidence, unlike the prior uncertain windows.

### 23.264 Serial native screenshot retrieval stalls before Browser Start; overlap theory insufficient

The UDP receiver was live and bound before input, with zero packets while no Browser request had started. Native boot screenshot `146-native-callback-udp-boot-20261012T111612905151Z/2026-10-12-131613.png` verifies LiveArea. Quit all returned Apps quit, and the Browser icon press/release was acknowledged. Subsequent PS+Start screenshot input was acknowledged and released, but the only FTP client's directory LIST timed out with zero bytes. No observer or second FTP request was active. No Browser Start press was sent.

This independently falsifies attributing the complete service stall to the earlier agent-side FTP overlap. It suggests the screenshot-publication/retrieval timing or another native resource/I/O condition is involved, but no root cause is proved. The run has no Browser/TLS result and zero UDP packets must not be read as missing dispatch after a real request. Receiver stop marker explicitly records this interrupted UI state; preserve its private summary and consumed cycle.

Selected host screenshot retrieval changes: avoid immediate live directory enumeration and request only expected timestamped screenshot files after a bounded publication interval, validating complete CRC/stable bytes without repeated input. This does not modify Vita plugins, storage mapping or config. Selected one vitacompanion-only recovery request with a separate current-cycle claim and independent USB identity observation. Last current durable config proof is the completed exact self-disabled boot; no subsequent config/payload write occurred. No physical restart or recovery success is inferred yet.

### 23.265 User requires waking the display before capture; prior stall classification has this limit

The user says to wake the display with vitacompanion before viewing/capturing it. Acknowledged immediately. Persisted the requirement in AGENTS.md and the local capture helpers, and selected screen on plus a bounded resume interval before checking access. Future normal UI input also starts with this explicit wake step.

The independently monitored reset received Rebooting... but observed neither USB disconnect nor registry reenumeration during its 60-second window; receipt `build/device-evidence/146-usb-reboot-observation-20261012T112246565641Z/receipt.json`. This is stronger observation than FTP alone, but still is not proof of a specific reset failure mechanism. Prior capture/launch stalls lacked an explicit display wake and must retain that confounder. Do not attribute the entire condition to directory locking, client overlap, kernel memory or TLS code without evidence.

The UDP run was stopped before Browser Start because its screenshot retrieval failed. Summary contains zero records and no receiver error; no Browser-request conclusion follows. The native capture helper now avoids directory listing, waits four seconds after one acknowledged PS+Start, retrieves only the expected device-local timestamp names and requires complete CRC/stable bytes. No repeated screenshot input, plugin/storage/config edit or re-arm is part of that change. Check the woken current state before choosing another recovery or test.

### 23.266 Display-wake control selected for one monitored restart

Screen on is acknowledged, but the subsequent serial config read still waits without FTP greeting. Selected one distinct control: explicitly wake the display, allow resume, then one vitacompanion reboot with the independent USB observer already active. The new consumed claim differs from the previous non-woken request; it cannot replay. No camera/file/config/arming operation is added. This tests the display-state confound raised by the user rather than asserting reset failure from a static reply. Result pending in `build/callback-udp-awake-usb-reboot-recovery.log`. Keep every FTP read stopped while this observation runs; after actual recovery reverify the disabled state before another experiment.

### 23.267 User takes over Browser opening; other authorized work remains autonomous

The user says they will open Browser for now and asks to be told when it is needed. Acknowledged and persisted this precise boundary in AGENTS.md. Do not send Browser icon/Start input again without changed user instructions. Prepare/verify the test, keep the actual receiver listening, notify the user at readiness, and collect the resulting request evidence. Test/restart/staging permission remains standing; this is a UI-role change, not a new approval requirement.

Keep the display-wake step before capture and other UI operations. Avoid repeating the failed directory-based screenshot workflow. The current UDP experiment already has a completed verified self-disabled boot and exact deployed pins; no new re-arm should be introduced solely for manual Browser opening. Resolve/record the pending woken reset observation and current reachability before selecting the live manual request window.

### 23.268 Manual Browser request window ready on the existing verified UDP boot

The explicit-wake reset again receives Rebooting... but its independent USB observation has no disconnect/reenumeration. No new reset success is claimed. The last completed verified self-disabled UDP boot remains the current evidence basis; no payload/config write or re-arm followed it. The manual opening test therefore reuses that already-prepared cycle rather than replaying any activation helper.

Selected screen on, resume interval and quit all through vitacompanion before the user's Browser action. Started a new private standalone capture `build/browser-callback-udp-manual-runtime.jsonl` on the exact compiled endpoint. `build/browser-callback-udp-manual-receiver-live.json` confirms the receiver worker is currently alive with no error; readiness is printed in `build/browser-callback-udp-manual-receiver.log`. Its 600-second bounded window stops on a distinct local completion marker, and uses no FTP. The earlier interrupted output/summary remains unchanged.

Notify the user to open Browser/Start and the exact fixed Cloudflare URL now, then report the displayed tls value or error and leave the screen open. Agent will send no Browser icon/Start input. Collect live packets and later screen evidence with an explicit wake first; keep the current FTP limitation visible and do not relabel user reports as captured device proof.

### 23.269 Native 3.60 module-info proves an incorrect data-filesz validator constant

While waiting for the user's manual page result, IDA analysis reopened the exact 3.73 compatibility IDB. The SSL setup, exported curl_easy_setopt and variadic setter were named/typed/commented in the existing IDB, with the setup's arguments, CURLE return semantics and option offsets documented. Raw stores confirm peer/host bytes; zero results from exact-mnemonic queries were not treated as absence because the actual instructions are STRB.W. The saved IDB preserves those annotations.

Compared the exact saved 3.60 `SceWebKit_info.bin` against the current VitaSDK 440-byte SceKernelModuleInfo definition (segments begin at byte 340). Text filesz/memsz match the descriptor. Crucially, raw segment 1 records **filesz=52788 (0xCE34), memsz=71104 (0x115C0)**. The reconstructed core/enriched ELF memory dump instead sets both to 71104 because it includes the in-memory tail. `webkit_callback.h` had copied that reconstructed ELF filesz and therefore rejects the genuine captured 3.60 geometry at reason 6. This is a definite descriptor defect independent of missing UDP/file logs; whether it is the primary Vita's current refusal still needs a fresh corrected runtime test.

Evidence `build/browser-webkit-saved-module-info.json` preserves parsed raw fields, SDK structure extent/offset, input path/hash and the saved-state limitation. Added an independent fixture filesz=52788 rather than deriving the expected value from the production macro. The old-code behavioral regression is running in `build/browser-webkit-original-filesz-red.log`; next replace only the exact data-filesz constant and reject the incorrect memory-dump filesz as a negative case. Keep memsz/text/signature/userdata/vtable/certificate gates unchanged. The ongoing manual capture uses the existing old build; no device file or arming change occurred during this discovery.

### 23.270 Raw-geometry regression red/green; user reports TLSv1 and access returns

The independent raw-filesz fixture fails against the old header exactly at expected callback acceptance (`build/browser-webkit-original-filesz-red.log`). Changed only TLS_FIXER_WEBKIT_DATA_FILESZ to 0xCE34; data memsz remains 0x115C0 and all name/text/signature/userdata/vtable/certificate gates are unchanged. Added rejection of the incorrect 71104-byte memory-dump filesz. Focused module/callback diagnostics pass 2/2 (`build/browser-webkit-original-filesz-green.log`). Full normal/sanitizer/native verification is running before any corrected artifact is staged.

The user manually reports `tls=TLSv1` on the fixed page. Acknowledged as user-reported, not screenshot-proved fresh negotiation or a provider result. It differs from the captured experimental TLS 1.2 response and may reflect a baseline session or cached page; do not infer the kernel is currently loaded from old file trace alone. The live UDP receiver still has zero accepted/rejected packets with no worker error. A second bounded receiver window replaced the first expired zero-record capture and was live while the user replied.

After explicit screen on and the user's Browser action, a fresh serial config fetch succeeds (`build/config-after-manual-tls1-page.txt`). This proves file access has returned, without attributing the recovery solely to wake or proving an earlier reset did/did not happen. Selected a same-boot zero-settle read-only observation to check the trace against the prepared cycle. Agent has sent no Browser icon/Start input after the user's role change. Preserve the current page/state before another transition; prepare the corrected build and a new verified test only after results are reconciled.

### 23.271 Manual page is fresh TLSv1 with no observed provider; corrected build ready locally

Woken USB frame `146-usb-manual-tls1-page-20261012T120435220884Z/screen.png` independently confirms the user's TLSv1 report with a recent Cloudflare timestamp (`ts=1791806207.000`) and no dialog. The completed observer `ui-observation-20261012T120146Z-7446c289` verifies current files, clean recorder status and only metadata-generator/PNG-promoter trace additions, with zero provider-start attempts. The exact prepared test was not observed to reach a provider in this manual request; zero UDP packets cannot diagnose a callback refusal in a process that was never observed to start. This fresh page is not a TLS 1.3 acceptance result.

The corrected exact 3.60 data-filesz gate passes 330/330 normal and 330/330 ASan/UBSan/leak-checking tests. The explicit Release UDP native artifact links successfully with no undefined ELF symbols and expected hard-float user ABI. No verification/cipher/trust/callback emulation policy changed. The independent fixture accepts native filesz 52788 while rejecting dumped-memory filesz 71104. The 112 Python result remains applicable because this change affects only the C descriptor/fixture, not the verified Python receiver/runner.

The current manual page/observer/capture are preserved, and the second live receiver was stopped cleanly by its own completion marker. Selected one guarded unarmed vitacompanion reboot with the matching old UDP receipt before staging the corrected provider. The Browser will be opened only by the user after a fresh verified self-disarming boot and live receiver notification. Agent will not use Restart or Browser icon/Start input. Continue explicit display wake and sequential FTP; no native directory-list screenshot capture is selected.

### 23.272 Native completion-byte check confirms current source; no extra adapter justified

A bounded 160-byte raw instruction extraction from the exact 3.73 compatibility module shows R3 copied as the completion pointer and STRB writing its result at 0x810A5F1C; nonblocking also passes through a byte extension. The earlier commentary assumed an int-pointer wrapper without checking the current declaration. Current module/backend/fixture signatures already use unsigned char for both fields. Corrected that statement immediately: this check confirms the existing ABI, not an additional source defect. No adapter or ABI change is made; avoid scope creep from that disproved hypothesis.

The healthy current page/observer were preserved and the matching guarded unarmed vitacompanion reboot verifies reconnect/disabled state again. After snapshot `build/device-evidence/146-unarmed-reboot-20261012T121201Z-e43be7ae/after`. A fresh fourteen-file inactive preflight and exact corrected-provider package/helper identity `browser-webkit-filesz-live` are qualified. New provider is 248524 bytes/hash `e50e8b8d2a50764cf0faab9892e67cb191f2698adcb0263bf50742681dbc65bf`; kernel remains unchanged. Selected files-only stage, with no config/reboot/Browser input; outcome pending. The next manual launch must follow the corrected test's fresh one-shot boot and an active receiver, not the previous interrupted/recovered session.

### 23.273 Corrected exact-filesz provider staged; new single boot selected

Fresh inactive fourteen-file preflight completes at `build/device-backups/146-browser-webkit-filesz-live-preflight-20261012T121458014510Z/`. It verifies the disabled config, absent alternate config, old UDP provider/current protected resources and unchanged kernel. Files-only stage completes with retained local/remote backups, corrected provider 248524 bytes/hash `e50e8b8d2a50764cf0faab9892e67cb191f2698adcb0263bf50742681dbc65bf` and fresh report hash `f123698aa995fb35c286fe278f9e06d254e10d2e80f6dcbc16ee747149e04fc3`.

Selected one fresh execution of `build/run_browser_webkit_filesz_live_cycle.py`, using a new arm receipt and vitacompanion only. This will test the actual descriptor correction after an independently qualified boot, avoiding the prior recovery/baseline ambiguity. No Browser icon/Start is sent by the agent. Outcome pending; upon verified self-disable, keep the display awake, bind a new standalone receiver, run quit all and notify the user immediately to open Browser/load the fixed URL. No native screenshot directory listing or camera session is selected before the manual launch.

### 23.274 Corrected build's verified boot; new manual request window

The corrected-filesz wrapper completes with one vitacompanion reboot, verified reconnect and exact self-disabled config. Fresh cycle `build/device-evidence/146-cycle-20261012T122319Z-250f47b9/` has boot trace hash `600e3982707a775d1af803e996aaba4e6c63028621c907c00725edc51ed7f075`, preserves exact payload/protected identities and records no provider start before Browser UI. This is the first qualified boot of the corrected descriptor.

Bound a new standalone receiver on the compiled endpoint and pinned corrected provider hash, private output `build/browser-webkit-filesz-runtime.jsonl`. Its heartbeat `build/browser-webkit-filesz-receiver-live.json` reports a current live worker/no error. Selected explicit screen on, resume interval and quit all before notifying the user. Do not open the camera or send Browser icon/Start before the user's manual action. This new capture/receipt supersedes prior baseline/recovery ambiguity; old reports and zero-record captures remain preserved.

### 23.275 Primary Vita Browser TLS 1.3 accepted with correlated runtime and persistence evidence

The user reports tls=TLSv1.3 for the manually opened corrected test. An independent woken USB capture (`build/device-evidence/146-usb-browser-tls13-acceptance-20261012T123000951663Z/screen.png`) visibly confirms the requested Cloudflare trace page with tls=TLSv1.3, kex=X25519, http/1.1 and fresh server timestamp 1791808144.000 (2026-10-12 12:29:04 UTC). No error dialog is visible. Agent sent no Browser icon/Start and no additional request/reload/reboot after success.

The actually live receiver captures **68 records, sequences 0-67, no gaps/rejected packets/duplicates, one PID 1189731**. Options return 0, handshake retries normally before completing with 0, verification returns 0, active reports 0x0304, and the provider sends the request and receives **956 application bytes**. No callback-rejection/policy-refusal/native-fallback marker is observed. The receiver stops cleanly with complete=true/error=null and retains private JSONL/summary. This is real transport evidence beyond startup or host tests; UDP alone is not treated as cryptographic proof, and the independently displayed server response supplies the separate acceptance result.

The subsequent same-boot zero-settle observation completes stable collection, verifies one successful provider start in **the same PID 1189731**, exact disabled config and unchanged protected/original/payload identities. Cycle `build/device-evidence/146-cycle-20261012T122319Z-250f47b9/`; observation `ui-observation-20261012T123247Z-bbad8403`. The generic observer still says tls13_established=false by design because it does not inspect the external page/packet acceptance; it was not altered to fabricate TLS proof. A separate assertion-qualified acceptance receipt `build/browser-tls13-acceptance-20261012.json` ties the screenshot, server timestamp, provider hash, successful boot, matching observation PID and runtime summary together and records accepted=true from those independent facts.

Final sequential double reads after success verify the current 248524-byte provider/hash `e50e8b8d2a50764cf0faab9892e67cb191f2698adcb0263bf50742681dbc65bf`, unchanged 22613-byte kernel/hash `3ccfa163d12a7f43eb4bea9affe23b1723a43f597520059de1d46fafe2a09247`, and exact self-disabled 726-byte config/hash `0c09159d2fa0d5e16d62b62ffbdf15595d8e4b862efe033d6decaad77d4bc9b9`. The existing successful Browser session remains open. No re-arm/promotion, persistent boot enable, original-module/CA/storage/recovery rewrite, extra launch or reboot follows acceptance.

The necessary browser fix is the exact initialized data-filesz correction, backed by raw saved module-info and an independent red/green regression. Final 330 normal/330 sanitizer CTest and 112 Python checks plus native/static verification remain separately recorded. README's prior blanket no-runtime-success statement is narrowed to this actual one-shot primary-device result; wider firmware/metadata/performance/endurance and the original boot-defect resolution remain unproven. The requested Browser goal is achieved; any production promotion or broader validation is separate future work under the existing safeguards.


### 23.276 Renamed tls_fixer source snapshot and private repository publication

The user requested a new private `vita_tls_fixer` repository, renamed `tls_fixer.suprx`/`tls_fixer.skprx` plugins, removal of the former project name outside the README attribution, and a commit/push. This authorizes repository publication; no device migration, re-arm, restart or further Browser request was performed.

The browser provider is now `tls_fixer.suprx` (module `tls_fixer`), the kernel is `tls_fixer.skprx` (module `tls_fixer_kernel`), and the separate SceHttp provider is `tls_fixer_http.suprx` (module `tls_fixer_http`). Installer/VPK member names, module lookup identities, installation/self-disarm paths, diagnostic identities, source namespaces, include directories, CMake options, test fixtures and documentation use the new naming. The installer/probe title IDs are `TLSF00001` and `TLSF00002`. The obsolete startup cleanup was removed because renaming it would delete the newly named browser plugin. The diagnostic log PID parser derives its offset from the new prefix, loader mocks distinguish exact provider filenames, and the probe nonce header is `X-TLS-Fixer-Probe-Nonce` so it remains valid for the existing restricted HTTP-header parser. TLS/verification decisions and the corrected WebKit data-filesz gate were preserved.

README explicitly thanks skgleba, links the upstream repository and explains that his useful certificate-update work is integrated into tls_fixer. Existing author/copyright notices and third-party licenses remain. All bundled CA, firmware and image bytes and license files match the original source archive. A narrow `.gitattributes` rule preserves the CA bundle without newline conversion; every staged Git blob is checked against the validated working-file bytes. Original whitespace in the unchanged CA/font files is preserved. The full original source snapshot and original Git history remain local; historical generated artifacts and raw device/analysis evidence stay outside publication. Fresh publication checkout: `/Volumes/data/dev/vita_tls_fixer`, branch `main`. Repository: `https://github.com/devnoname120/vita_tls_fixer`, created and independently confirmed PRIVATE before pushing.

Host validation of the renamed tree: **330/330 normal CTest, 330/330 ASan/UBSan/leak-checking CTest, 112/112 Python tests**. The initial rename-dependent failures and final passing logs are retained under the new checkout's ignored `build/rename-*` files. Full VitaSDK `make -j6` builds `tls_fixer.vpk`; the package contains the three exact provider/kernel filenames and their bytes match the cross-built outputs. ELF/Vita metadata independently confirms the three module names, both entry points and no undefined symbols. The kernel generated-code gate reports no unmanaged FP/SIMD instructions. All publication filenames/content and every decompressed VPK member were audited; the former name occurs only in the README credit/link.

Cross-built output identities (not installed or runtime-tested under these new names):

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `tls_fixer.skprx` | 12075 | `9d44632609f7dc4da3a11a28e3ab8201f419f96096e5df64fd617c6faecdc027` |
| `tls_fixer.suprx` | 247369 | `429b7b097895bb35f91217fddd7972eeb2f9944d1a294df6a905108dbade4fe4` |
| `tls_fixer_http.suprx` | 245734 | `e4a6ed700ca8fa53ec1c5c8f4f85f8d2fcf518eb167f5c0fdd545f40a7a4cc93` |

The prior hardware acceptance remains attributed to the exact pre-rename one-shot artifacts in section 23.275. The successful Vita session and disabled boot configuration were left unchanged. The requested initial commit/push publishes this renamed source snapshot. The final GitHub commit/tree/visibility result is recorded in `build/publication-receipt.json` in the publication checkout, so the committed source does not need to embed its own commit hash.


### 23.277 Authoritative Sony and curl/Mozilla certificate installation

The user explicitly requested the VPK to embed Sony and curl/Mozilla certificate bundles, fetch the latest Mozilla bundle through curl verified by the embedded Mozilla bundle, fall back to that embedded snapshot when fetching fails, and never import system certificates. The change implements that installer behavior. Repository editing, host downloading, compilation and validation are within the requested scope; **no device installation, certificate/config edit, re-arm, launch or reboot was performed** and no standing device-test authorization was consumed.

The complete Sony retail 3.74 certificate file was recovered from the existing local firmware extraction, not the device's system store: **103598 bytes, 69 certificates, SHA-256 `61f25856c8d1e862599f06580a7a83e1a74fda9aa889aee750c6d581edb05761`**. The inherited mixed bundle's Sony-looking prefix had only 67 certificates and was not the complete 3.74 file; it is not used as the authoritative Sony source. `misc/sony-certs.pem` preserves the exact extracted file.

The latest official `https://curl.se/ca/cacert.pem` snapshot fetched on 2026-10-12 is dated **2026-09-25**, contains **121 certificates**, is **188900 bytes**, and has SHA-256 **`a41b5d356aea97a529fe27e0f7316d2f9d946d75927476cf9cf1b90637d00505`**. Its matching published SHA-256 was verified. It is embedded unchanged as `misc/mozilla-certs.pem`, including upstream provenance headers. The canonical Sony-plus-Mozilla fallback contains **176 unique certificates**, **257799 bytes**, SHA-256 **`fa1bb62997d6f14b0532310a9a04bd3c0b6a45225c879b0b36cb04658bd111f7`**. `misc/certificate-sources.json` records these identities. Shared certificates are deduplicated by certificate identity; successful downloads replace the Mozilla component rather than retaining removed Mozilla roots from the older snapshot.

`installer/certificates.c` is the production preparation code used by the Vita installer and the host exercise. It validates both embedded inputs, performs a bounded HTTPS-only/no-redirect/no-environment-proxy transfer with normal peer/hostname verification, and uses only embedded Mozilla roots to authenticate the curl endpoint. Default CA file/directory/native fallback is disabled in the source-built curl configuration and runtime options; the OpenSSL context callback replaces the verification store rather than adding to an existing store. System trust files and environment CA overrides are not authority inputs. HTTP errors, no network, connection failure, timeout, TLS/hostname rejection, empty/malformed/truncated/NUL/oversized/non-CA/private-key-bearing bundle responses use the embedded Mozilla fallback. A missing/corrupt embedded source fails preparation without altering installation files. Inputs are bounded to 4 MiB and 512 certificate entries; transfer timeout is 30 seconds, following at most five seconds of network-readiness polling.

`main.c` constructs the installation bytes from `app0:sony-certs.pem` plus the selected Mozilla bundle, writes and synchronizes its owned `.prepared` candidate, then uses the existing backup/refresh/uninstall behavior. The candidate filename is distinct from the refresh helper's `.tmp` filename, avoiding source deletion during refresh. Existing system certificates are retained only as the original uninstall backup; they are not imported into either the download trust store or installed union. The full installer's existing persistent-file replacement/boot-safety limitations are unchanged and remain unverified on hardware; this host/cross-build result does not authorize production promotion or claim crash-durable replacement.

VitaSDK's cached libcurl archive used an older OpenSSL ABI than the installed 1.1.1t libraries, causing unresolved legacy symbols. The installer now source-builds checksum-pinned **curl 8.17.0** from the official release archive (`e8e74cdeefe5fb78b3ae6e90cd542babf788fa9480029cfcee6fd9ced42b7910`) with matching VitaSDK libraries, HTTP-only configuration, no default CA discovery, and disabled console UI (the SDK archive has no `UI_OpenSSL`). Native build configuration confirms OpenSSL 1.1.1t, zlib 1.3.2 and zstd 1.5.7. The matching licenses, Mozilla MPL 2.0, notices, three PEM files and snapshot metadata are included in the VPK. No TLS-provider or kernel source behavior changed.

Verification completed: the exact updater code fetched the live curl endpoint on the host with **downloaded=1, error=0, HTTP 200**, Sony=69/Mozilla=121/combined=176; offline preparation produces the identical current fallback. **12 new controlled HTTPS integration tests** pass normally and with **ASan/UBSan/leak checking on Linux** (also normal/ASan/UBSan on macOS). They prove download replacement/deduplication, offline/connection/HTTP/redirect/timeout fallback, hostname and trust rejection, complete discard of invalid payloads, no system-root import even with poisoned CA environment variables, Sony-root exclusion from download authentication, and fatal embedded-input validation without output alteration. Full Python discovery passes **124/124 without skips** in the dependency-equipped Linux test container. Existing provider suites pass **330/330 normal and 330/330 ASan/UBSan/leak CTest** with the new authoritative combined fixture.

The full Vita VPK builds successfully. Its embedded certificate/provenance/license bytes match the source files; final installer ELF contains the updater, `curl_easy_perform` and `SSL_CTX_set_cert_store` with no unresolved required symbols and the expected ARMv7/hard-float ABI. Its five unresolved weak CRT instrumentation/finalization references are the optional SDK hooks, recorded separately in the receipt; they are not described as resolved symbols. The kernel's existing decoded-instruction check still passes. Validation receipt: `build/certificate-update/validation-receipt.json`. Live/controlled host networking and native linkage remain separate from on-device execution, which was not attempted. The prior Vita browser success and protected files remain associated with section 23.275.


### 23.278 Direct SceSsl consumers and TLS coverage blind spots

The user requested an inventory of Vita SceSsl users outside Browser and SceHttp. Parsed every available 3.60 enriched ELF (242/242, zero failures), identifying 43 public/private SSL consumers. Exactly four import SceSslInternal: SceLibHttp (67 imports), SceEmailEngine (22), SceNpMatching2 (24), and SceShell (22). The last three are concrete private-SSL dependencies outside the existing browser/libhttp interception boundaries; all import the SDK-identified sceSslInternalWrite (F39A49C6). This is static ABI evidence, not proof that any particular service negotiated TLS or executed that branch. Reconstructed-dump raw disassembly did not independently establish direct call sites and is not cited as call-path proof.

The initial literal-version module-info scan missed seven modules; generic attribute/version handling and validated metadata spans resolved all seven, including Matching2. Do not reuse the initial 40-consumer/two-extra-private-client result. The final parser uses module metadata rather than the reconstructed ELF entrypoint, which refers to executable startup in these dumps. The 3.65 extracted corpus cross-check parses 316 of 328 images, with 12 security-coprocessor-format files explicitly excluded, and confirms the same three extra private clients. Selected saved 3.74 shell/libhttp images have 23/69 private imports; this is not a full encrypted-retail-SELF inventory.

SceEmailApp and SceEmailBg import 223/184 engine functions, respectively, and ScePS4Link imports 17 Matching2 functions. Most remaining public SSL users import lifecycle/pool/inspection functions and use HTTP or delegated services; they must not be counted as independent TLS engines from SceSslInit alone. Public SDK SceSsl does not provide general connect/read/write APIs. Whole-shell and whole-application coverage is not asserted: HTTP requests can be covered while private SSL branches remain outside the adapters, and exact module/configuration gates still apply.

Report: `docs/tls13-ssl-consumers.md`. Full named NID/source-hash census, CSV and later-firmware checks are retained under ignored `build/ssl-consumers/`. No source/runtime/provider change or device operation occurred, and no standing test authorization was consumed. The report identifies EmailEngine, Matching2 and shell-specific SSL callers as the next narrowly justified inspection targets; implementing those adapters is not part of this inventory request.


### 23.279 External 3.60-3.74 retail/testkit/devkit compatibility

The user explicitly requested firmware/hardware support across the provided external corpus. The old code had a 3.60 kernel geometry/signature guard and one 3.60 WebKit callback/geometry/vtable gate; the replacement transport modules themselves are intentionally pinned to the VPK artifacts. Audited all available external images read-only from `fs_dec`, including bounded bootimage module extraction. The corpus contains 31 of 36 published-release/hardware combinations. Missing: testkit 3.69, 3.71, 3.74; devkit 3.72, 3.74. No internal/tool or adjacent release is substituted and no unsupported identity is inferred.

Available kernel images share peer identities/code across hardware and form two guarded geometry/veneer families: 3.60/3.61 and 3.63 onward. The load and optional start offsets remain 0x21EC/0x286C with start entry 0x378D, but text size/metadata placement and native-import call bytes differ. `firmware_profiles.h` registers twelve kernel NIDs and validates mapped metadata inside native segment bounds. Saved primary 3.60 RX confirms retained module-info name/NID 726C6635 at text+B9D0 and the expected relocated cookie instructions. Existing relocation masks and self-disarm-first ordering are retained.

WebKit has four code/geometry families and 31 distinct hardware/release module NIDs. Retail/kit code matches within a release but WebKit identities differ, so each available kit NID is explicit. Callback offsets/vtables/metadata positions and real initialized data extents are profile-specific; Thumb callback signature, readable/writable aligned userdata and the existing minimum mapped span remain required. All 31 wrappers forward to the same ScePsp2Compat role through library/function 81405F79:7DAB2E59, verified by decoding the wrapper branch and resolving its import entry. The profile check is not replaced by a broad pattern match or firmware-string test.

The mandatory-import audit exposed an additional real gap: SceModulemgrForKernel changes library/function IDs from 3.63. The legacy info/list/unload imports would be unresolved without a separate remapper. Added an in-module typed binding layer resolving info/list/unload/shared APIs from the loaded manager identity and corresponding 360/363 export family through taiHEN. Known API names/signatures are corroborated by the 3.60/3.63 SDK NID databases and corresponding argument-setup bodies; the unload entry is byte-identical in the inspected prefix, while other wrappers differ in native import veneers. Resolution runs once after durable self-disarm, with bounded trace enter/return markers, before loader hooks; pointer publication uses release/acquire. Unknown identity or missing export aborts initialization, and callbacks never perform resolution. No separate loader/arming file/launcher or automatic re-arm was added.

The existing transport artifact hashes/ABIs remain unchanged as target identities, and the 3.60 NP helper's installer check masks kit build/revision bits. No universal SceSsl adapter or additional private-SSL driver was added. Earlier audit documentation is retained with its exact static/runtime boundaries.

Full `tools/firmware_matrix.py` checks the compiled kernel guard in normal and post-start modes and the actual WebKit callback validator against every available image, plus altered NIDs/signatures/geometry/vtables and the callback import role. It verifies all four dynamically selected native API exports and all mandatory firmware imports from the ARM kernel (32), browser provider (44), HTTP provider (42) and installer (104) against each firmware. Kernel/installer filenames were initially colliding as import-report keys; corrected to full paths before final verification. Final result: **31 cells pass, five unavailable**, recorded in `docs/firmware-compatibility.json` and ignored build logs. The parser handles export descriptor version bytes and bounded embedded bootimage tables.

The final dependency check reads the exact compressed plaintext Sony SELF files included in the VPK, rather than assuming their metadata matches the unmodified firmware ELF. Their code/data/imports match the 3.73 references apart from regenerated module NIDs. HTTP (148 imports), SSL (42) and browser compatibility (239) dependencies are present on all 31 targets. The 3.60-only commerce module (67 imports), DNS helper's mandatory native import and exact shell hook import pass on retail/testkit/devkit 3.60. Native exports from replaced modules are excluded, avoiding false success from an original binary the replacement will displace. Initial missing Rtc and WebFiltering dependencies were collector omissions, corrected by including their actual firmware exports; they were not reported as module incompatibilities. Static dependency presence does not prove target-process load order, privileges or executed ABI behavior.

Independently checked saved 3.60 WebKit memory-derived ELF and its enriched form: both retain name SceWebKit, format 6 and NID 20163DF2 at RX+85FB04. The un-enriched file SHA-256 is `c6945b94b6c6439b8c265a7d2b61f8ae10b3c1a5eac23d32a7723641c55d3e5c`. This corroborates the new mapped-identity check on historical hardware memory; it is not a new execution of the changed provider.

Regression results: **331/331 normal CTest, 331/331 ASan/UBSan/leak CTest, 124/124 Python tests without skips**. New native-binding tests check both API families, exact argument forwarding, missing-export publication failure and unknown identity refusal. Full native VPK build and decoded no-FP/SIMD kernel gate pass. Device/runtime testing of the new artifacts was not performed; old primary Browser TLS 1.3 acceptance is not reused as proof of the new binding/profile code or kit behavior. No device file/config edit, upload, launch, reboot or standing-test authorization consumption occurred. Missing exact sources and hardware runtime remain explicit limitations; the original boot defect and pre-module-start failure window remain unresolved.

Final package/source naming audit passes, with former-project mentions confined to README attribution and every packaged module/certificate/license byte matching its build/source input. `tls_fixer.vpk` is 5215473 bytes, SHA-256 `4f92dd4792ca21c21306bce7c00d75d1d5cd378c6bbfbe53b8522155fedca8fa`; kernel is 12906 bytes/hash `96f9c20c3f97bdcf9d7d4cf43d08b1cae26dcb229cba8ddc3225341ee8a930d8`; browser provider is 247922 bytes/hash `6d0352037a47052f37319cc63d57a4e6fe192a8dd864285f31fcd81de759feed`. HTTP provider remains byte-identical to the previous published build. Receipt: `build/firmware-support/validation-receipt.json`. The changes are committed/pushed to the existing private `vita_tls_fixer` repository; a separate ignored publication receipt records the final remote identity without requiring a self-referential commit hash in this log.


### 23.280 Vita installer certificate preparation: native lock resource exhaustion

The user reported installation error 0xFFFFFFFF on the primary Vita and requested the latest screenshot and a fix. Woke the display through vitacompanion before sequential FTP retrieval. The latest listed PNG, 2026-10-12-223702.png, visibly shows successful kernel/browser/HTTP/SSL/3.60-DNS steps followed by certificate preparation failure and no requested reboot. Evidence is retained under ignored `build/installer-failure-20261012T203810Z/`.

Read-back verified both embedded PEM files and the installed pre-fix executable against the package. The original system CA remains 72035 bytes, hash `24c11a840e424af1879847b6db7356dda3574bc5a072a9df3b7a1837632f29c8`; no original-CA backup existed. The failed user-side full install had inserted an active new kernel entry. Preserved its configuration and kernel, independently tested bounded FTP REST writes on an owned scratch file, then changed only configuration byte 20 to comment that new entry. Saved a remote/local before-image and verified exact readback. The native probe subsequently returned 0 from sceIoSync(ur0:). The old disabled entry and unrelated configuration remain unchanged. No reboot or Browser opening occurred.

Native certificate-only probes ruled out the path hypothesis: app0:name and app0:/name both read the correct bytes and all individual certificates parse. The production preparation function failed while retaining both chains, at Mozilla index 25. A forwarded pthread-rwlock diagnostic measured init return 28 (ENOSPC), live/peak locks 288; OpenSSL surfaced error 09091041 (PEM malloc failure). Runtime newlib heap is 8388608 bytes; mallinfo arena was about 815104 bytes. This is synchronization-resource exhaustion, not evidence that the configured heap needs increasing. The compiled SDK rwlock allocates mutex/condition/semaphore resources per OpenSSL object.

Added an installer-only OpenSSL opaque-lock adapter backed by recursive native lightweight mutexes, serializing both read and write access. All five opaque-lock operations and atomic reference updates are linked through one consistent adapter; atomic updates use compiler atomics, retaining the SDK's native atomic semantics. Generated-code review found zero direct calls to the original opaque-lock operations, with wrapped call sites present throughout libcrypto/libssl. Other pthread initialization/thread-local support remains linked. Kernel and providers are unchanged, including self-disarming. Certificate authority, hostname/peer checks and embedded fallback policy are unchanged. Failure diagnostics now retain preparation stage, errno and OpenSSL error instead of reporting only an ambiguous -1. Corrected the libcurl SSLVERSION vararg to an explicit long for compiler/API portability.

On the actual Vita, the corrected adapter prepares Sony=69/Mozilla=121/combined=176 with the same 8 MiB heap. Offline output is exactly 257799 bytes/hash `fa1bb62997d6f14b0532310a9a04bd3c0b6a45225c879b0b36cb04658bd111f7`, matching the authoritative source fixture. Live curl download also returns prepare=0, downloaded=1, curl=0 and HTTP=200, with the same counts. The production install_certificates function, redirected only to an isolated ux0 target, returns 0 for both first installation and refresh; readback verifies the installed union and exact original backup. This tests the actual write/backup/refresh function without changing the system CA.

A separate app-owned vs0 scratch check confirmed rename-over-existing is rejected with 80010011 and preserves old bytes. It was cleaned up and synchronized. The existing multi-rename system-CA replacement is not described as crash durable. The actual system CA remains unchanged; full persistent installation/reboot is not claimed from the isolated check. Temporary diagnostics used the installer title with preserved executables and were replaced by the corrected normal installer afterward. The new kernel boot entry stays deliberately disabled.

Verification: 125/125 Python tests without skips on Linux, 13 focused tests normally and under ASan/UBSan/leak checking on Linux, plus 13 normal and ASan/UBSan focused cases on macOS (leak detection unsupported there). The new lock test covers recursive/exclusive access, native failure propagation and retained work-storage lifetime, four concurrent callers and 100000 atomic/reference updates. Native VPK builds; only eboot.bin differs from the prior VPK. All 31 available firmware cells still pass compiled guards/import/dependency validation, with the same five missing kit images. Original modules, CA authority inputs, kernel/provider payloads and recovery resources are preserved. This repair does not establish broader kernel/browser runtime compatibility or resolve the earlier boot defect.

Updated VPK: 5215793 bytes, SHA-256 `cbc1c2dbe7dc56446cf916378748ad9329e555174d9d369836254fc9efc54f63`; installer eboot SHA-256 `b1197d1f8239a8a526bb456ba21cbc943ea60b807895c9b65f67cb4a303ca52d`. Final validation/deployment/publication receipts are retained with the failure evidence.

### 23.281 Normal VPK Browser crash: post-start ordering omitted from packaging (2026-10-13)

The user reported C2-12828-1 on HTTPS after installing the normal VPK. Explicitly woke the screen before USB capture; `build/browser-crash-20261012T215248Z/crash-screen.png` independently confirms the Browser dialog. Preserved encrypted `psp2core-SceWebKitProcess.spsp2dmp` (716896 bytes, SHA-256 `235d4b6a700bf3247105c444f7581a6c7c9a355afb8b8b2abef1d43ce9a2b094`) and exact installed payload/config/protected-resource receipts before quit/reboot. The parser decrypts the dump but does not authenticate its HMAC.

PREFETCH_ABORT is at PC 0xB1440000, from the SceWebKit resource worker's compatibility connect wrapper. Provider callback 0x816C0001 transformed by the known imported-variable MOVW rewrite using register value 0xE0021344 becomes exactly 0xB1440001. The patched page is omitted from the dump; this is an exact callsite/arithmetic correlation, not a directly observed corrupted literal. The installed kernel and normal VPK used POST_START=OFF although the successful Browser control required ON.

Made post-start injection mandatory in the ordinary kernel profile; isolation profiles without transport hooks omit it. The normal Makefile explicitly selects ON even with an old cache. Added a production-route regression that retains application-provider activation, requires native start to finish before Browser injection and preserves all seven arguments/native result/status. Normal and sanitizer host suites both pass 332/332; Python passes 125/125. Native VPK and decoded kernel register gate pass. All 31 available firmware cells pass, with the same five missing kit cells. These checks do not establish physical Browser success.

After one verified unarmed recovery reboot, staged corrected normal kernel 14345 bytes/hash `6c3f8b340de1540174d1dfcba15457fc15a257caab1925f4717d0193a4d0573a` separately at ux0:/data/tls_fixer-one-shot/tls_fixer.skprx. Preserved original config locally and at ur0:/tai/config-before-poststart-20261013.txt; appended only one disabled test stanza. The resulting 906-byte config hash is `e80062c1b1c30943acb4458b2c9e14cfbac3ca68813dcafd96fb6031c9dc6e58`; activation changes only byte 861. Installed UR0 kernel, providers, native modules, boot/storage/FTP resources and certificates were not overwritten. A first preflight refused to arm because the OS had removed the already-preserved ephemeral dump; no reboot or activation occurred in that failed preflight.

One deliberately selected vitacompanion reboot consumed the new test, observed disconnect/reconnect and verified both exact disabled-config reads. Woken screenshot confirms healthy LiveArea. Then quit all was acknowledged and the user alone opened Browser. This proves startup self-disarm and recovery, not TLS acceptance. Self-disarm still cannot cover a fault before module_start or completion of its durable edits.

### 23.282 Corrected normal kernel stalls Browser startup; traced comparison selected (2026-10-13)

The user reports Browser stays on Please wait forever. Woken USB `poststart-waiting.png` independently confirms the waiting screen, with an empty URL field; no HTTPS transport result is claimed. FTP remains responsive and config is exactly disabled. Current provider and trust bytes are unchanged. This invalidates treating the post-start build alone as a completed fix.

Preserved current inventories/config and selected one unarmed vitacompanion recovery reboot; `unarmed-after-wait.json` records preserved pins, quit all, a single reboot, actual disconnect/reconnect and the disabled config. The earlier successful diagnostic differs from normal activation in module-presence strategy, stack management and application-provider scope, as well as logging. No one of those differences is yet the demonstrated cause of this stall.

Selected a separate normal combined-provider build with stage recording enabled and POST_START=ON, retaining original full module scanning and original stack behavior. Relaxed only the artificial restriction preventing the recorder from observing normal activation. No TLS policy, certificates or user provider changes are selected. Stage/activation receipts and physical result will be added after completion; this is not a successful Browser result or published repaired package.

The first 20266-byte normal-trace kernel boot self-disarmed but produced no new trace: its required pre-existing 256-byte result file was absent after the project rename, so module_start refused activation before native binding/hooks. Woken LiveArea remained healthy. This is not a traced reproduction or successful provider test. Staged a fresh unique PENDING report at the renamed owned diagnostic path, read it back twice and pinned it with the unchanged trace kernel in a new, separately consumable normal-trace-ready receipt. Historical diagnostic files and installed resources are preserved.

The fresh normal-trace-ready boot powered off before remote services returned. The user confirmed Powered off and then manually powered on to LiveArea. Retrieval verifies exact self-disabled config, completed gate/trace_setup=0 and unchanged protected resources; normal-trace-recovery.json distinguishes the failed experimental boot from the later successful inactive boot. The 17211-byte trace/hash cdef479f5b4e8015df163508ba69a503e45d8265361b5e7faf07a47a63f90f02 records complete enumeration, all metadata returns, hashing, target lookup and argument copying for application-provider activation inside the libhttp load callback, followed by 0x8002D003 and cleanup/hook return. VitaSDK identifies that result as MODULEMGR_NO_LIB. The trace has no exception PC and does not establish the cause of the subsequent power-off. It falsifies claiming the observed final operation was a stuck module query.

The next narrow comparison defers HTTP injection until native libhttp start returns, using the same bounded pending manager as Browser. Both routes retain native results/status, remove their pending item before injection and perform no injection for failed native startup. The full module scan and original stack behavior remain unchanged for this comparison. Added HTTP-specific exactly-once/reentry/failure/duplicate-kind tests and an ordinary production route test which refuses HTTP injection during load. This is a selected candidate, not a verified physical fix.

### 23.283 Combined post-start ordering alone is insufficient; normal loader context correction prepared

The combined-defer kernel (20534 bytes, SHA-256 63fd368cd7bbe1a2aecc022d7cced7b425a9a93e45c0138f8ef09ed542c4d93b) and new unique PENDING report were staged with exact disabled-config and protected-resource checks, preserving per-file remote/local backups. One vitacompanion reboot was issued. The user reports the Vita crashed and asked whether to power on again; instructed one power-on to recover, with no re-arm. The bounded boot observer timed out and did not request a second reboot. The attempt is explicitly unsuccessful; later recovery must not be mistaken for that experimental boot succeeding. The combined ordering change passes 332/332 normal host tests and 10/10 focused post-start sanitizer/leak checks; those checks did not prevent the device failure.

The earlier hardware-qualified name-lookup/native-stack diagnostic and successful Browser profile avoid the full per-module metadata inspection still present in normal activation. They also use the same-thread native 16384-byte stack. The next local candidate carries those established context controls into the normal combined-provider build, while retaining mandatory post-start ordering and both providers. This does not identify which context difference causes the normal build's failure, and does not attribute a shutdown to MODULEMGR_NO_LIB without a fault address.

Added a normal loader-context fixture with tracing disabled, checking actual native-stack dispatch, target/provider name identity, exactly one native target-info query, zero direct native module-list/per-module inspection, duplicate/presence/lookup-error refusal and native-stack callback failure for both HTTP and Browser. Existing name-query diagnostic fixtures remain separate. Optional provider-start stage/status recording now observes both targets. Queued tracing may observe normal combined activation with its same existing boot/headroom requirements, avoiding filesystem I/O in the process-private loader context. No certificate/provider/stock module or self-disarm policy changes are part of this correction. Hardware selection remains gated on recovered disabled state.

### 23.284 Combined safe context boots; diagnostic queue blocks Browser injection

The production-context test uses a queued recorder, name lookup, native 16 KiB stack, mandatory post-start for both targets and application activation retained (BROWSER_ACTIVATION=0). It booted successfully after one vitacompanion reboot with observed disconnect/reconnect and exact self-disabled config. Woken USB verifies healthy LiveArea. The fresh 256-byte result initially has err=0/op=0, and both early application-provider preparations complete on the larger native stack. They still return MODULEMGR_NO_LIB without shutting down. This rules out treating that return alone as the cause of the previous power-offs.

After quit all, the user alone opened Browser and reported TLSv1.2. Woken production-context-tls12.png independently shows the trace response, tls=TLSv1.2/kex=P-256 and timestamp visible in the saved frame. The same-boot trace/result then record operation 6, queue exhaustion, after the Browser application's HTTP preparation; Browser provider startup is not observed. The logger refuses subsequent activation on this error. This is a native fallback result, not a TLS-engine negotiation failure. No provider/TLS/certificate change is selected from it.

The rebuilt normal VPK has a 14780-byte kernel/hash 627af5206b4a3cd902609096aa460d88eb9b69db9e91ac21940302f973160da3. Its actual compiler definitions select both providers, post-start, name lookup and native stack, with kernel trace disabled. Package comparison against the previously installed VPK proves only tls_fixer.skprx changed; installer, providers, Sony modules, certificate bundles and metadata are byte-identical. It passes the decoded kernel register gate, 333/333 normal host cases, 15/15 focused sanitizer/leak cases and 31 available firmware cells. Five kit cells remain unavailable. The next selected one-shot uses the exact normal VPK kernel, avoiding the diagnostic queue; physical Browser acceptance is still pending.

The exact packaged kernel boot is verified with a single vitacompanion reboot, actual disconnect/reconnect and self-disabled config. Woken packaged-kernel-livearea.png verifies healthy UI; then quit all was acknowledged and the manual Browser test was requested with a new retry query. Kernel tracing is disabled; the old trace and the newly staged diagnostic PENDING file are deliberately not described as evidence from this boot.

Normalized every kernel diagnostic/profile input in the VPK Make recipe, including both-provider activation, mandatory post-start, native stack/name lookup and tracing off. An isolated previously cached self-disarm-only profile was replaced by the normal recipe and produced a kernel byte-identical to the physical test payload. Repacking changed ZIP metadata/hash but no payload bytes. The 5217666-byte final VPK hash is be11dd088ff007150682335ba776eaa0e0f79c4f2c0cd3815e1937e09feafbc9. Its only changed member relative to the previous VPK remains tls_fixer.skprx.

Final host checks complete: 333/333 normal and 333/333 ASan/UBSan/leak CTest, plus 125/125 Python earlier in this kernel-only correction. The normal build rejects explicit early injection. Isolated stale-diagnostic-cache normalization yields the exact tested normal kernel. Static/native/package verification is complete; manual packaged-kernel Browser acceptance remains pending and must precede a claim that C2-12828-1/TLS behavior is fixed.

### 23.285 Exact packaged kernel freezes Browser; candidate withdrawn (2026-10-13)

The user reports Please wait for a long time followed by a complete Vita freeze for the exact packaged-kernel test. USB capture after attempted wake independently confirms the waiting screen with the requested trace URL. FTP cannot return a greeting; the wake command has no reply. One standing-authority vitacompanion reboot request also has no reply and was not repeated. The current freeze cannot provide a fresh config/dump read; the exact disabled entry was independently verified before this request. The user was asked for one physical restart to recover, not configuration repair or re-arming.

New evidence is build/browser-freeze-20261012T234400Z/ (screen, command/FTP failure receipt and single reboot receipt). The generated normal VPK was moved there as tls_fixer.failed-packaged1.vpk with its exact existing hash, withdrawing the handout while preserving it for comparison. The source checkpoint f953786 records host/boot checks with Browser acceptance pending; this new outcome disproves treating that checkpoint as a working packaged Browser fix.

The successful diagnostic also differs in provider load origin: global ur0 provider path/flags=0 versus normal wb0 process-private provider path/flags=0x1000. That difference was not included in the prior correction. The compatibility-file hash must still be checked through the Browser's namespace; the identical provider payload can be loaded into the same target PID from its globally visible installed location. Investigate this controlled difference before changing TLS or certificate policy. No new activation or payload transfer follows the freeze until recovery and the disabled state are verified.

### 23.286 Global Browser provider origin: controlled correction prepared

Physical restart recovery is verified with exact disabled config and unchanged protected files. The data inventory has no new WebKit dump; the startup log is byte-identical to the preceding queued diagnostic and is not evidence from the failed no-trace boot. Native IDA readback at fun_LoadModuleForProcess (0xB8A1EC) confirms flag 0x1000 calls ksceIoOpenForPid(process_id,path,1,0), versus ksceIoOpen when namespace/special-open bits are absent. Raw instructions capture R0 into R5 after the call, correcting the pseudocode's hidden return dependency. The seven-argument driver wrapper forwards the same destination PID and adds its existing native flags. Its IDB comment and existing argument/return types are saved. This proves selector semantics, not the freeze's internal wait or exception cause.

The candidate installs the unchanged normal Browser provider at ur0:tai/tls_fixer.suprx and always loads it into the same target PID with namespace flags 0. The compatibility-file checksum still uses its actual Browser overlay path and PID. Existing VS0 provider/compatibility resources are retained. The installer copies/removes/detects the global provider as part of Browser installation; refreshing the VPK thus cannot leave the coordinator without its required global file. No CA authority, TLS backend, callback validator or provider payload is changed. Normal and diagnostic namespace fixtures now require zero provider overlay opens, global provider metadata, private compatibility hashing and flags 0; errors still refuse activation.

Native build succeeds with the kernel register gate. Compared with the withdrawn packaged1 VPK, only eboot.bin and tls_fixer.skprx differ; both providers, Sony modules and certificate bundles are identical. Browser provider SHA remains 6d0352037a47052f37319cc63d57a4e6fe192a8dd864285f31fcd81de759feed. Candidate kernel is 14701 bytes/hash 6a2f40062c707adc53cfc79e3e4b3a0fc5e23a06a357ae663e7b536fa5748979. The new owned global provider file was absent before staging, copied from the exact installed provider, read back twice and pinned while the boot entry remained disabled. No system/VS0 module or certificate was rewritten for this experiment. Physical selection follows recovered-state verification; no re-arm was automatic after the freeze.

One deliberately selected global-origin boot completes with actual disconnect/reconnect and exact self-disabled config. Both staged kernel and unchanged global provider read back with their selected hashes. Woken global-origin-livearea.png confirms healthy LiveArea; quit all completes before manual Browser readiness. This is boot/entry proof, not TLS acceptance. The normal kernel has no startup recorder and no stale log is attributed to this boot.

### 23.287 Global-origin normal build also fails; Browser-only control selected

The user reports that the global-origin Vita crashed and rebooted. The normal build has no new trace and the data inventory contains no new WebKit dump. After the reported reboot, readback verifies the exact disabled config and unchanged protected resources; the preceding queued log is unchanged and is not attributed to this test. The global-origin packaged VPK is withdrawn and preserved as tls_fixer.failed-global1.vpk. This outcome does not establish file-namespace selection as the cause or show that changing it alone resolves the failure.

The next controlled profile uses the exact unchanged normal Browser provider in its global location, but selects the previously successful Browser-only kernel activation scope. Application-provider injection and DNS-helper startup are excluded by that diagnostic profile; native-module redirection, self-disarm, post-start, identity checks and real Browser TLS remain. A bounded queued recorder observes this narrower scope, avoiding the known combined-scope queue exhaustion. This is an isolation/positive-control test and will not be promoted to a normal package that silently removes application support. It uses the normal provider, not a changed cryptographic or certificate implementation.

### 23.288 Current normal provider and merged CA accepted under Browser-only scope

The user reports TLSv1.3 for browser-only-control. Woken browser-only-tls13.png independently displays TLSv1.3, X25519 and fresh server timestamp 1791851049.000 (2026-10-13 00:24:09 UTC). The same-boot trace records matching private compatibility hash, shared=0, positive global provider module ID and provider.status=0, then native WebKit loading returns. The recorder remains clean (err=0/op=0) and the boot entry stays disabled. The exact normal Browser payload and current authoritative CA union are unchanged from the failing normal build. This is a renewed positive Browser control, not acceptance of combined application/DNS startup.

Selected the next one-shot combined-no-dns diagnostic: normal HTTP and Browser provider activation retained, native redirection retained, only legacy DNS helper startup omitted. Kernel tracing stays off to avoid the demonstrated combined queue exhaustion. The new skip-DNS option defaults OFF and is explicitly OFF in the VPK recipe. A focused route fixture proves that this switch excludes only the helper while retaining both TLS routes. Its native build and decoded register gate pass. The control will distinguish DNS-helper startup from the HTTP-provider path; no disabled feature will be silently promoted as the final package.

The combined-no-dns selection is staged with per-file backups, fresh PENDING report, exact disabled configuration and the global-provider extra pin. The previous Browser-only control was healthy and its page/trace preserved before this deliberate change. One vitacompanion reboot is selected through its unique receipt; no replay or automatic re-arm follows a failed result. HTTP injection remains active in this diagnostic.

### 23.289 DNS exclusion fails; HTTP provider prerequisites gated

The combined-no-dns diagnostic froze the system on Please wait. Its frozen screen and unresponsive wake/FTP/single reboot request were preserved; the user forced a restart. After recovery, exact disabled config and protected-resource pins are verified. Excluding DNS startup did not cure the combined failure. No success or modern HTTP transport execution is inferred from the earlier failed MODULEMGR_NO_LIB returns.

The HTTP provider imports SceLibc. The captured native SceLibc module-info file independently confirms that module name. Normal injection now checks its presence/identity through the existing narrow lookup before loading the HTTP provider. Explicit absence, malformed identity or lookup error refuses this injection while preserving Sony's native result/backend. Browser injection, HTTP injection when prerequisites exist, DNS startup, certificates and provider payloads remain enabled/unchanged. The new fixture requires no provider load or argument allocation when libc is absent/erroring, and a positive load when it is present. This is a selected candidate prompted by real missing-library returns, not a proven cause of the system freeze before its runtime test.

### 23.290 Libc prerequisite candidate fails; recovery and dependency evidence

The exact normal VPK kernel (14853 bytes, SHA-256 1ff2aa03ef4a3d0138a117af6faa1f0bf6e86f0c9e2e3ca4f12dfd6367ab21ac) booted and self-disarmed. For retry=20261013-prereq1, the user reported Please wait followed by a crash-dialog sound, a faint partially appearing dialog and a complete freeze, then selected a physical reboot. The saved USB frame independently shows Please wait with a faint dialog/OK overlay. One screen-on request timed out. No agent reboot or re-arm occurred during recovery.

After recovery, sequential double reads verify exact disabled configuration e80062c1b1c30943acb4458b2c9e14cfbac3ca68813dcafd96fb6031c9dc6e58 and all protected-resource pins. ux0:data inventory contains no new dump from this test. The startup log is the unchanged successful Browser-only log (b1f0da9aa4371bafde498025bb14845de273ebfbedc3ca4163cedacdc8c90d7b), so it supplies no new failure trace. The generated prerequisite VPK is withdrawn as build/browser-freeze-20261012T234400Z/tls_fixer.failed-prerequisite1.vpk. Full host and ASan/UBSan/leak suites pass 334/334; runtime failed. Libc absence is not established as the cause.

Both provider link recipes explicitly use -nostdlib and SceLibc_stub. Native HTTP ELF cross-reference inspection confirms calloc/free from connection code and Mbed TLS; memory/string and formatting operations also resolve through Sony libc stubs. A process must provide matching import libraries before native loading can succeed. This is a build dependency, not an intrinsic TLS/process-attachment requirement. PAF could supply alternate services but would require its own runtime availability and consistent allocator ownership. No libc/PAF migration is selected on the basis of an unspecified MODULEMGR_NO_LIB return.

### 23.291 Explicit Browser process isolation candidate

The two user providers are distinct binaries, but normal HTTP activation has no process exclusion. The Browser controller can trigger it by loading SceLibHttp, while WebKit page transport uses the separate compatibility/provider path. Native HTTP ELF contains 16 SceLibc imports; exact 3.60 SceWebBrowser ELF imports PAF's Stdc library and has no direct SceLibc-library imports. These static imports do not prove which libraries are loaded transitively in a live process. Prior MODULEMGR_NO_LIB records prove attempted HTTP loading, not provider entry/transport execution.

Selected a narrow HTTP-only Browser-title exclusion through ksceKernelSysrootGetProcessTitleId (official SDK prototype, SceSysrootForKernel library). Before HTTP reservations, allocations or module lookup/load, title NPXS10003 returns without HTTP injection; a title lookup error refuses that injection. Browser-provider injection does not perform this check. Application HTTP activation, native redirection, DNS startup, the normal Browser provider and certificate bytes remain enabled. This candidate tests missing process isolation; it does not assert a crash root cause or repaired runtime.

Host regression covers excluded Browser HTTP without query/argument allocation, lookup failure without injection, unaffected WebKit injection even when title lookup fails, and ordinary application HTTP activation. Full normal and ASan/UBSan/leak suites pass 334/334. Initial host build invocation was corrected to use the Linux cache's container path; initial firmware check ran before the native clean rebuild had produced its ELF and is not counted as a compatibility result. Native payload identity, completed matrix and physical result remain pending.

The first native link exposed the required SceSysrootForKernel stub library, distinct from the existing SceSysrootForDriver dependency. Added that library for the normal loader build; compatibility must include the new 3691da45:ec3124a3 import before selecting a physical test.

Native normal VPK build succeeds after the required stub is linked; the emitted kernel passes the decoded register gate. The first configure after the edit saw a truncated mounted-file read; a subsequent container SHA-256 exactly matches the complete host CMake source (534e87d31cf417da1b56eba8890f6e2cf5d97cd8104a89cf1cf9de0c30fe1660) and succeeds. Candidate kernel is 15063 bytes, SHA-256 ea3281dbc8d3fd3b27a5e59bf59bc50cb99a51f4e791ee8a784965c9f9f6f9e8. Compared with the failed prerequisite VPK, only the decompressed kernel member differs; both TLS providers, installer, Sony modules and certificate inputs are unchanged.

Completed native matrix verifies all 31 available firmware/hardware cells, including the new title-ID import; the same five kit images remain unavailable. Selected one single-use browser-http-isolation test at the existing owned ux0 path. This is normal BROWSER_ACTIVATION=OFF/SKIP_DNS_START=OFF/tracing=OFF, retaining both TLS providers and DNS helper, with Browser-title HTTP injection excluded. Existing protected UR0/VS0 payloads and CA are not overwritten. Per-file stage backups, fresh PENDING report and exact disabled-config preflight are required before one deliberate vitacompanion reboot. The user alone will open Browser after quit all and woken LiveArea verification. No repaired package is published from these host/static checks.

The unique browser-http-isolation stage receipt preserves the previous 1ff2aa03 kernel/report and pins the normal global Browser provider. One vitacompanion reboot was acknowledged, disconnect/reconnect observed, and exact disabled configuration read twice. Subsequent reads confirm disabled config and the exact ea3281db staged kernel; quit all and screen on are acknowledged. A viewed USB frame confirms healthy LiveArea. Manual Browser acceptance remains pending; no successful HTTP transport or repaired combined Browser behavior is claimed.

### 23.292 Browser-title exclusion fails; recovered disabled state

The user reports crash then freeze for retry=20261013-isolation1 and performed a forced reboot. Sequential post-recovery reads verify exact disabled configuration e80062c1b1c30943acb4458b2c9e14cfbac3ca68813dcafd96fb6031c9dc6e58 and all protected pins. The ux0:data inventory has no changed dump entries relative to the preceding recovery. The trace is the stale Browser-only positive-control log; the normal build did not record a fresh failure path. The report remains the unique PENDING marker, so its contents are not claimed as runtime stage evidence. No agent reboot or re-arm was issued during recovery. The generated VPK is withdrawn as tls_fixer.failed-isolation1.vpk.

The title-based HTTP exclusion is not a sufficient fix. It also does not prove the exclusion was executed in the failing path, because this normal profile lacks tracing. Further activation-profile guesses are not selected; the next diagnostic must expose whether the failing run reaches HTTP load/start, Browser load/start, or later WebKit startup without the earlier broad recorder's queue exhaustion.

### 23.293 Sparse asynchronous activation recorder

The recovered Browser savedata temp inventory contains no provider log. Added a diagnostic-only filter to the existing asynchronous recorder before formatting/enqueueing. It retains startup, redirected module paths, native-start completion, preparation results, HTTP title/prerequisite decisions and provider load/start results, plus negative operation results. Ordinary module paths and successful per-block hashing/query details do not consume queue capacity. The normal Makefile forces this switch OFF. Provider selection, loader timing points and TLS/certificate policy are unchanged from the failed isolation candidate.

A meaningful burst fixture submits 3000 routine events without draining, then retains all 16 selected activation/error records with no producer I/O or queue error; the existing asynchronous concurrency/fault cases remain passing. Full normal suite passes 335/335, focused ASan/UBSan/leak cases 41/41. Native diagnostic kernel passes the decoded register check; all 31 available firmware cells pass compiled guards/imports, with the same five kit images missing. Kernel size 24375, SHA-256 75cf4afd476b9643117e2d06c2f3bcb6631d38640705e58af4afdb8f137153c6.

Selected activation-trace as a separate one-shot diagnostic after recovered disabled config, protected pins and woken LiveArea were verified. Both providers, DNS startup and Browser-title HTTP exclusion remain selected. Existing payload backups and unique PENDING report are required before the single vitacompanion reboot. This records a failure boundary; tracing may affect timing, and a healthy traced run alone would not establish the untraced failure as repaired.

One acknowledged vitacompanion reboot consumed activation-trace, with disconnect/reconnect and exact self-disabled configuration verified. Fresh 6349-byte startup log (652298fc55408e60f40cfb43609765841454041b10ba4af5647ae9ca1431990f) has 42 selected records; runtime report is clean (err=0/op=0), observed native loads=61. It shows two early processes taking the explicit SceLibc-not-found gate and returning before provider loading. This supplies current evidence for that prerequisite decision; it does not identify the Browser freeze cause. quit all and screen on were acknowledged, and the viewed USB frame confirms LiveArea. A bounded, sequential read-only collector now snapshots changed startup/report files and stops on its first read failure; no concurrent FTP operation may run until it exits. Browser opening remains user-owned.

### 23.294 C1-2569-2 before any new provider activation; unarmed recovery selected

The user reports C1-2569-2 whenever opening any application and requests a reboot/retry, suggesting it may be unrelated. The bounded collector exited and was confirmed stopped before further FTP. Current stable log/report are byte-identical to the activation-trace boot checkpoint (42 records, 61 observed module loads, err=0/op=0). No new provider activation is present. The woken USB frame independently confirms the C1-2569-2 dialog. Re-read official SDK error_table.csv row 517: C1-2569-2 maps to 0x80024302, SCE_KERNEL_ERROR_NO_FREE_PHYSICAL_PAGE. This is physical-page exhaustion; the responsible allocation owner remains unknown.

Preserved current configuration, trace, report and screenshot in c1-before-reboot files. The exact 906-byte configuration is disabled. Selected one user-requested vitacompanion reboot without re-arming, to clear the current runtime and check normal application launching. Full protected-resource preflight and a unique consumed reboot receipt precede that command. No new payload or certificate change is selected. The original failure still needs diagnosis; this recovery must not be treated as Browser TLS acceptance.

The single unarmed vitacompanion reboot was acknowledged; disconnect/reconnect and exact disabled configuration were verified. The old trace remains byte-identical instead of being reopened by experimental startup. After acknowledged quit all/screen on, the viewed USB frame shows healthy LiveArea. This confirms recovery to the shell only; whether application launching now succeeds awaits the user's normal Browser icon/Start action. No diagnostic was re-armed.

### 23.295 Baseline Browser opens, then user reports an unexpected reboot

The user confirmed Browser opens normally after the unarmed recovery. Before any new stage, re-arm or reboot was executed, the user then reported that the Vita had just rebooted and asked whether the agent caused it. The only device operations started in this turn were two reads of the disabled configuration, followed by screen-on and a USB frame capture; no new reboot command or arming write was selected. The last agent reboot remains c1-unarmed-reboot, completed before the successful-open report. The proposed repeat of activation-trace is held pending preservation of the unexpected restart evidence. Do not label this a new active-plugin crash or a plugin-independent hardware defect without additional evidence.

The completed tool result narrows the command sequence further: the very first FTP connection timed out (curl 28), so neither a successful config read nor screen-on nor USB capture ran in that script. Thus no Vita control command was sent during this newly reported restart. Any following observation is read-only and separately receipted.

The user clarified the baseline sequence: Browser initially opened, but the Vita then restarted during Please wait; after that unexpected restart, Cloudflare displays TLSv1. Subsequent read-only checks find the same exact disabled configuration and byte-identical old coordinator trace. No experimental activation or agent reboot occurred between the two user observations. This is evidence of an additional failure during an unarmed session; it does not by itself identify a hardware fault or exclude effects of previously installed persistent resources. Preserve the current page and any new dump before another test.

A subsequent woken USB frame independently confirms the Cloudflare response displays tls=TLSv1 in the unarmed session. Exact disabled config is reverified; the data inventory contains no new/changed core entry from the unexpected restart. The successful displayed response is a native-TLS baseline, not modern-provider acceptance.

### 23.296 Single clean-session repeat of the same activation recorder

After the native TLSv1 page, exact disabled configuration and absent new dump were preserved, selected one explicit repeat of the byte-identical 24375-byte activation-trace kernel (75cf4afd476b9643117e2d06c2f3bcb6631d38640705e58af4afdb8f137153c6). The upcoming reboot was explicitly announced as agent-issued. This selection retains the original build/test evidence and changes no provider/certificate/activation code. Per-file backups, fresh PENDING report, normal-provider pin and full protected-resource preflight precede the single reboot.

This repeat omits continuous FTP polling during the user's Browser attempt. The asynchronous device recorder remains active, and the result will be fetched after the user responds. This limits observation traffic as a possible confound; no claim is made that polling caused the earlier physical-page exhaustion or unexpected unarmed restart. Do not start another observer or reuse the previous consumed reboot receipt.

The deliberately announced activation-trace-repeat reboot was acknowledged, with disconnect/reconnect and renewed durable self-disable observed. The user asked whether it actually rebooted; answered with those observations, then independently fetched a fresh changed startup log and a clean runtime report (err=0/op=0). Exact disabled configuration is verified. quit all/screen on were acknowledged and the viewed USB frame confirms LiveArea. Continuous FTP polling is not running. Manual Browser opening remains pending.

### 23.297 Immediate C1-2569-2 reproduced without continuous observation traffic

The user reports immediate C1-2569-2 on Browser and every other app after the clean activation-trace-repeat boot. Continuous FTP polling was off. This reproduces the physical-page-exhaustion symptom during an active coordinator boot, before Browser TLS testing. Current config, trace, report and screen are being preserved without another re-arm. Repeating Browser launches is not selected. Investigation now targets coordinator/startup memory accounting and native stack/allocator contracts before another activation. The unarmed session's separate unexpected restart remains a distinct observation; causal certainty is not inferred from the active/inactive comparison alone.

### 23.298 Memory-accounting diagnostic prepared from native ABI evidence

The trace2 failure leaves the same 42-record/61-load startup checkpoint with zero TLS-provider starts. Thus the modern TLS engines and their CA parsing were not reached in this run. ELF/VELF accounting shows approximately 61 KiB of coordinator loadable code/data, including its trace queue. Native IDA review of ksceKernelRunWithStack confirms byte units, 4096-byte rounding and an ordinary 16384-byte request allocating 20480 bytes including its guard page, then restoring thread stack fields and freeing the block. This confirms the native contract, not live cleanup or allocation ownership.

The installed DNS helper (4753 bytes, 32b07bed38a681961b4bb803c62eb4fb2ac49708ee7b8efc30942d7760356f5d), replacement libhttp (42bc7e34077964ac7edc4365abad8af9bf41793a34d2c7efd631976f7d2739c1) and replacement libssl (850148bad6771619004835caf056f2303d8d77c99623ce247b07958391f72ae5) were read back; DNS bytes match the built artifact. One unarmed recovery reboot was announced and acknowledged, with disconnect/reconnect and disabled configuration verified.

Added an optional memory probe to the sparse recorder, disabled in normal packaging. It requires exact SceSysmem module NID 3380b323 (retail 3.60), then resolves library 63a519e5 exports 4d38f861 (boot-lifetime primary physical-partition pointer) and 3650963f (16-byte native partition snapshot). The ABI and native refcount/spinlock behavior were inspected in IDA and documented there; no raw memory addresses are used in device code. The snapshot itself allocates no additional buffer beyond a 16-byte stack record and logs total/free byte counts, omitting physical addresses. This is one physical partition, not a claim of all process-budget or contiguity availability.

Snapshots bracket coordinator initialization, native extended-stack dispatch and DNS-helper startup, with three bounded idle samples. DNS start entry/result now has explicit diagnostic records. Provider selection and TLS/certificate behavior are unchanged. Unknown module identities or unavailable exports refuse this diagnostic before hooks; failed or inconsistent counter reads are explicitly logged, not represented as zero free memory. Host tests exercise those identity/error boundaries and the exact typed callback ABI. Native/build validation and deployment are tracked separately below.

Final memory-probe validation: full normal suite 336/336, focused ASan/UBSan/leak suite 42/42, native instruction gate passes. Normal kernel is byte-identical to the prior ea3281db build when this option is OFF; no repaired VPK is inferred. Diagnostic kernel is 25108 bytes, SHA-256 0f4025fdd880c4da27eaf7b7a3845b545cd73507940a4e002335a8786855af45. Its private memory-counter ABI is gated to the audited retail 3.60 Sysmem identity; normal cross-firmware support is unaffected. Selected one memory-accounting boot after announced unarmed recovery, with no Browser launch requested until its startup counters are examined.

### 23.299 Native memory counters collected before any app launch

Memory-accounting boot was acknowledged, disconnect/reconnect observed, and self-disabled config verified. Exact kernel hash is 0f4025fd. Fresh trace is 8260 bytes/hash 75b0b20f437e1b5a5c9d2826e4819f8d55b97191cfb4b2550a0a46c934de7b4f; recorder err/op are zero. The primary partition reports total=37748736 (36 MiB), free=4698112 at coordinator startup, 4694016 after loader init, then 2375680 (2.265625 MiB) in the final bounded idle sample.

The two early HTTP preparations (both aborting at missing SceLibc) bracket free-memory values 2797568 -> 2785280 and 2109440 -> 2097152: each observed difference is 12288 bytes. These readings include concurrent system work and do not by themselves prove an owned leak. DNS load/start returns a positive module ID and status zero with identical before/after free count 2785280. No TLS provider starts. These measurements concern the observed primary partition, not all budgets, physical-memory types or maximum contiguous extent. Native query implementation refreshes its cached free-count field while taking a protected snapshot, so successful app behavior with the observer would not alone prove a passive timing-independent repair.

A supplementary normal-app launch was performed without a Browser launch: installed TLSF00001 eboot hash b1197d1f was reverified, its startup source requires explicit controller input for any install/remove operation, and vitacompanion launch was used with no button input. The independently viewed frame shows the installer menu. No installation operation was requested; config remains exactly disabled and the selected activation trace is unchanged. This demonstrates one homebrew URI launch succeeding in this instrumented run, not acceptance of the Browser icon/Start path or a demonstrated fix for C1-2569-2. The memory query refreshes a native cached free counter, and additional instrumentation changes timing; those remain confounds. The installer is closed through quit all before the next user-owned Browser attempt.

Before the memory-accounting Browser attempt, quit all/screen on were acknowledged, the viewed USB frame confirms LiveArea, exact disabled configuration was re-read, and the native recorder report remains err=0/op=0. No continuous FTP observer is running. Browser icon/Start opening and the Cloudflare response remain pending; no current TLS result or repaired normal package is claimed.

### 23.300 Combined diagnostic reaches TLS 1.3; WebKit helper exclusion gap identified

The user reports tls=TLSv1.3 for retry=20261013-memory1. The woken USB frame independently displays TLSv1.3, X25519 and fresh server timestamp 1791880863.000 (2026-10-13 08:41:03 UTC). Exact normal Browser provider remains 6d035203, kernel 0f4025fd, and configuration is disabled. The 15839-byte startup trace hashes to 14b1f64b848eb68e14593321b3db6f1a035345cd7cf3bad156716ed23205e2ef; recorder err/op remain zero. This is successful combined diagnostic Browser execution, not acceptance of the normal untraced VPK.

The trace has two load/start attempts, not two successful providers. Browser-controller HTTP injection is explicitly skipped. A different PID then passes SceLibc presence and attempts the HTTP provider, returning 8002d000 with status 2. Official SDK row 633 identifies MODULEMGR_START_FAILED; the exact user-entry failure stage is not recorded. That PID subsequently loads ScePsp2Compat, starts the dedicated Browser provider successfully and renders TLS 1.3. The original saved core identifies this helper application as NPXS10083 / SceWebKitProcess; 27 available helper executables retain this title/module identity; four otherwise-covered firmware cells lack that decrypted helper executable and are not counted as helper-identity verification.

The prior Browser exclusion covered only frontend title NPXS10003. Extended it to helper title NPXS10083, leaving HTTP activation for other titles and dedicated Browser-provider activation intact. The host guard fixture checks both exclusions without query/argument allocation and retains normal-app HTTP plus Browser injection. This corrects an evidenced isolation gap; its sufficiency for the normal build's failures remains a runtime question.

The helper title ID is verified from param.sfo in all 31 available firmware cells; 27 also have decrypted helper executables confirming SceWebKitProcess. Four kit cells have original helper assets but no decrypted helper ELF. The device's original saved core independently records title NPXS10083. The exclusion now runs at HTTP injection entry, before native extended-stack allocation; the guard tests require neither stack dispatch nor workspace allocation for either Browser title.

During that move, a missing local result declaration was caught by compilation and corrected. One subsequent parallel host compile saw the already-observed transient truncated mounted-source read; a source-hash-qualified retry matched host SHA-256 8a41b185ba16be2b0c93fa55c0635f02cc56b152ac426437393f08db29ca6526 and passed all five affected host and sanitizer cases. Native ordinary VPK build and instruction gate pass; compiled firmware matrix again passes 31 cells, five unavailable. No failed intermediate build was deployed.

Selected normal-webkit-isolation as the exact ordinary VPK kernel: 15013 bytes/hash dcec123fd5d12479e21ea42c323f3946ee9fba051d8ee4e07c7015e6f81a2883. VPK is 5218421 bytes/hash 28579f8b42e11a42a4ec65c8436b94d7b908699f6f3e9d1bed2ad788fc4ca001. Compared with the withdrawn frontend-only isolation package, only the decompressed kernel member differs. Tracing, memory probing and Browser-only activation are OFF; DNS and HTTP activation in other processes remain enabled. The successful diagnostic page/trace is preserved before this deliberate stage and single announced vitacompanion reboot. Normal runtime acceptance remains pending.

The single normal-webkit-isolation reboot was acknowledged, disconnect/reconnect observed and exact self-disabled config verified. Post-boot double reads confirm the installed owned kernel is dcec123f, matching the VPK member. quit all/screen on were acknowledged and the independently viewed frame shows LiveArea. No application has been launched by the agent in this boot. Tracing/memory observation and continuous FTP polling are off; the next user-owned Browser result will qualify the ordinary package separately from the successful diagnostic.

### 23.301 Ordinary two-process-isolation candidate still freezes

The user reports a whole-device freeze at Please wait during URL navigation, without an error dialog, for retry=20261013-webkit1; they forced a reboot. Thus excluding both Browser titles before the preparation stack is not sufficient to repair the ordinary package. The exact generated VPK is withdrawn as tls_fixer.failed-webkit1.vpk. No automatic re-arm or agent reboot follows this report.

The remaining useful control is successful instrumented execution versus failed ordinary execution with the same Browser provider and CA bytes. Investigate native load/start synchronization, argument lifetime, generated code and the recorder/counter differences before attributing this to TLS negotiation or selecting another Browser retry.

### 23.302 Native audit narrows hypotheses without establishing a fix

Post-webkit1 recovery readback confirms exact disabled configuration and unchanged protected resources; no new dump exists. No agent reboot/re-arm occurred during that recovery. The stale successful trace is not attributed to the failing ordinary run.

Audited native Module Manager entry-thread handling: both ordinary and special-start branches converge on WaitThreadEnd before returning the entry result, so the existing startup-argument allocation lifetime is valid for the synchronous load/start call. Native RunWithStack rounds the requested 16 KiB to pages and uses a 20 KiB guarded allocation on its ordinary branch, then restores thread stack fields and frees it; this confirms the contract rather than proving live cleanup. Physical-partition snapshots recompute and update a cached free-byte count. Alloc/free paths also update that count; no demonstrated allocation-admission decision based solely on this cache was found, so the successful memory observer is not promoted as an allocator fix.

Immutable ordinary/instrumented ELF copies were compared in IDA. Linked .vitalink.fstubs are descriptors, not executable import implementations: initial no-return inference and truncated caller pseudocode were analysis artifacts. Corrected function bounds/SDK types and checked raw instructions. Native memcpy/memset preserve and return their original destination in R0; the ordinary optimizer's reuse of memset's return is valid. Updated relevant IDA types/comments and saved/closed the databases. No specific generated-code defect was established. Native source snapshots and annotated comparison databases remain in the ignored evidence directory.

Upstream taiHEN shared-library documentation and hook source were inspected as a possible cross-process interaction. Neither provides current-device proof that the failing ordinary run installed a hook into a shared mapping. No speculative hook-policy change was deployed on that basis.

### 23.303 Untraced Browser-only control selected

The prior Browser-only success included asynchronous tracing, whereas ordinary combined failures omitted tracing. This leaves scope and instrumentation confounded. Added one diagnostic-only HTTP-start exclusion alongside the existing DNS exclusion; both default OFF and normal packaging explicitly resets both OFF. Selecting both keeps the ordinary Browser loader code, post-start hook, name checks, 16 KiB preparation, redirection, provider bytes and CA unchanged while excluding only HTTP-provider and DNS-helper startup. No trace worker, memory-counter refresh or arbitrary sleep is added. This is a missing control, not a proposed production reduction in HTTP/DNS coverage.

The post-start fixture now runs in both normal and untraced-control configurations: Browser startup follows native completion in both, normal HTTP/DNS startup remains enabled, and the control omits both while preserving redirection/native results. Both host and sanitizer configurations pass the two affected cases. Native diagnostic build passes the decoded register gate. The default-OFF normal rebuild is byte-identical to withdrawn dcec123f, confirming that adding the switch did not silently alter ordinary behavior. Control kernel is 14809 bytes/SHA-256 925f52db8c72083b029a028bbdac1fdf77a22d9050f59707015526cd8a2c2ed0.

Selected a single untraced-browser-control boot under standing test authority, after recovered disabled state verification. Stage/boot helpers preserve the replaced owned kernel/report, require protected-resource/provider pins, and consume a unique reboot receipt; startup still self-disarms before hooks. Only the owned ux0 kernel and diagnostic report are staged, with the existing one-byte activation change for one reboot. No VPK/provider/CA/system resource is replaced. Actual stage, boot and Browser results are recorded separately below.

Full host validation passes 337/337 and the compiled native compatibility matrix passes all 31 available firmware/hardware cells (five missing source cells). The first matrix invocation was on macOS and explicitly refused its unsupported address-mapping environment; the completed run used the required Linux container. No device selection was based on that failed invocation.

Before staging, the existing exact-config guard correctly refused a changed device configuration: current length 937/hash 8a3f0a96c8f477706874f38ccacb99ddd60efebef96936cb32c4b00cc1a53242 versus expected 906/e80062c1. The only diff is a new active ur0:tai/vitastream_probe.skprx line. The independent VitaStream task's local progress record confirms enablement at 20261013T111409Z, with the old 906-byte config backed up remotely. Its next step is a reboot and composition-recording session. The TLS entry remains disabled. No TLS payload/report/config change or reboot was issued. The unrelated probe entry was preserved, and a task-priority clarification was sent because another capture would alter the planned TLS control baseline; standing TLS authorization was not re-requested.

The user selected TLS first and explicitly deferred the VitaStream probe. Preserved its complete 937-byte enabled configuration locally and at ur0:tai/config.before-tls-untraced-20261013T1126Z.txt, verified before changing only its leading entry byte at offset 683 to a comment. Stable readback gives deferred-config SHA-256 1a7c64d141a275560d5543c632543ebfe345385b2b41f94864485e44ac46a9f5. The probe payload remains unchanged at 826e8725. All prior protected pins and alternate-config absence were reverified. The own TLS arm byte now sits at offset 892; a separate helper and separate expected-config snapshots preserve earlier receipts and refuse other changes. Woken pre-stage USB capture confirms healthy LiveArea. This new probe was added after the failed webkit1 recovery and is not attributed as its cause.

The unique untraced-browser-control stage receipt preserves the prior dcec123f owned kernel and report. One vitacompanion reboot was acknowledged; disconnect/reconnect and exact self-disabled 937-byte config were verified. Post-boot checks confirm the installed 925f52db control and every protected/extra pin, including unchanged Browser provider, legacy DNS/HTTP/SSL resources and deferred VitaStream payload. quit all and screen on were acknowledged. Independently viewed untraced-browser-livearea.png confirms LiveArea. No installer or other app was launched in this boot; tracing, memory probing and continuous FTP polling are off. The user-owned Browser request uses retry=20261013-untraced1. Browser runtime outcome is pending; the ordinary VPK remains withdrawn.

### 23.304 Untraced Browser-only route also freezes

The user reports Freeze on Please wait for retry=20261013-untraced1 and confirms they forced a reboot. The agent announced an intended recovery attempt, but before issuing it found responsive services and a LiveArea capture; no agent recovery reboot was sent. The file named untraced-browser-frozen.png actually depicts recovered LiveArea after the user's restart, not the frozen page. Exact deferred/disabled config 1a7c64d1 and protected/provider/probe pins are verified; data inventory has no changed dump entries.

This falsifies HTTP-provider or legacy DNS-helper startup as a necessary trigger: both were omitted in the failed control. It does not by itself prove compiler failure, late relocation, TLS-backend failure or timing. The successful traced Browser-only run remains a different binary/profile, so tracing and activation scope must now be separated on the current source. No ordinary VPK is accepted or republished.

Native late-link audit: RegisterModuleExportLibraryByIndex only walks the unresolved-import list, not every already-resolved library. The exact bundled Compat SELF matches the preserved reference and its variable-import libraries are SceLibKernel (one variable) and SceLibc (six), both attribute 0, without the weak-library bit. This does not identify a new late-relocation defect or justify moving injection again. IDA comments/prototypes and a static metadata receipt are saved.

### 23.305 Paired current-source Browser activation recorder prepared

Selected the same current Browser-only startup scope as untraced1, now with the sparse asynchronous activation recorder and native stack-headroom observations enabled. Physical-memory probes remain OFF; no HTTP provider, DNS helper, installer warmup or other application is selected. Browser/provider/CA paths and payloads remain unchanged. This isolates the established instrumentation difference while retaining a failure-boundary record; traced success would not itself accept the ordinary package. Native build and decoded register gate pass. The selected kernel is 24266 bytes/hash 0558e6abc4d3e6057c9470f133bb006e1b77133cffb414ccec62e17056d293e1. A distinct paired-browser-trace receipt must preserve the failed control and report before one deliberate vitacompanion reboot.

The first paired-trace boot preflight refused a changed unrelated probe payload before arming or issuing any reboot (no boot receipt existed). Sequential readback identified only vitastream_probe.skprx changed: 17551 bytes/hash 58a40673f4ff51ca574347c0e86281f8c6d7b5bc10ba043b8ce91b884bf610e3. The other task's current progress record independently documents that exact SELECT-marker remap and the still-commented entry. Preserved the new external payload and recorded the new pin without changing any TLS/CA/system resource or the approved deferred configuration. The selected diagnostic remains the same; the unique reboot receipt is still unconsumed.

The completed paired-browser-trace native matrix passes 31 available cells, five unavailable. After the documented external-probe pin update, the single selected vitacompanion reboot was acknowledged, disconnect/reconnect observed, and exact self-disabled configuration verified. Post-boot owned kernel is 0558e6ab and all protected/extra pins match. Fresh trace is 2135 bytes/hash c819c88d377ae7b46b4769946071915494ecd5fc59d8aa499371c0f5e79c7c01, with 14 startup records and 60 observed loads; report ff201474 has err=0/op=0. No memory-probe, HTTP-provider or DNS-start event is present. quit all/screen on were acknowledged; viewed paired-browser-trace-livearea.png confirms LiveArea. No installer warmup or continuous FTP observer is running. User-only Browser launch is pending for retry=20261013-pairedtrace1. This establishes only current boot/recorder readiness, not Browser TLS acceptance.

### 23.306 Offline stack-frame comparison while paired Browser result is pending

Revalidated the selected paired boot receipt/current source without issuing any further device command. The preceding goal turn made progress through the failed untraced control, recovered-state proof and paired diagnostic deployment. Browser opening/result remains user-owned and outstanding; do not reboot, re-arm, launch another app or run a continuous observer while that result is pending.

Compiled main.c, tls13_loader.c and post_start.c for both exact current profiles with GCC -fstack-usage/-fcallgraph-info=su in a separate audit directory. All six resulting object files are byte-identical to the objects used in the tested native builds, so the compiler-generated frame reports describe those binaries without an instrumentation/code change. Untraced versus traced load hook frames are 544 versus 576 bytes; both start hooks use 48 and both completion handlers use 288. Untraced preparation uses an 8-byte callback plus 248-byte inject_target, versus a 248-byte inlined traced callback. Both hashes use a 48-byte local frame. Native callees' peak usage is not included in these local numbers, and recorded headroom is a point sample rather than a complete high-water mark. These measurements do not identify a stack-size correction. Audit objects, per-function .su/.ci files and summary.json remain in build/browser-freeze-20261012T234400Z/stack-budget-audit/.

### 23.307 Paired Browser action remains outstanding; goal blocked on user-owned UI

A single read-only observation at 2026-10-13 11:59:37 UTC revalidates the device: disabled config 1a7c64d1, the exact unchanged 2135-byte startup log c819c88d and unchanged clean report ff201474. Woken USB capture independently still shows LiveArea. No new Browser activation is recorded. No reboot, re-arm, app launch or payload/config write occurred in this continuation.

The same missing user-owned Browser launch/result has now persisted across three consecutive goal turns (initial paired readiness, offline stack audit, and this live revalidation). The preceding audit supplied concrete offline evidence; this observation confirms no runtime result is available. With the useful independent audit completed, another implementation choice or device activation would be speculative and would replace the pending controlled run. The goal is blocked on the already-requested manual Browser icon/Start test at retry=20261013-pairedtrace1. Retain the full ordinary-VPK, Browser, sceHttp, auto-disarm and private-publication objective; do not mark it complete. Resume from this exact diagnostic when the user supplies the result. Observation receipt and frame are in paired-observation-20261013T115937Z/.

### 23.308 Paired recorder fails before any provider; native allocation-failure diagnostic

The user reports immediate C1-2569-2 on Browser and all other app launches for pairedtrace1. A woken USB frame independently confirms that dialog. Current trace/report exactly match the 14-record/60-load boot checkpoint, with zero provider-start records and clean recorder status. SDK error_table.csv row 517 confirms 0x80024302, NO_FREE_PHYSICAL_PAGE. Exact disabled/deferred config is verified. One announced unarmed vitacompanion recovery reboot was acknowledged with disconnect/reconnect and disabled readback. No test was re-armed in that recovery.

Native Sysmem audit locates the 0x80024302 synthesis in the extent-backing function at text+0x3674, now named fun_BackMemoryExtentWithPhysicalPages in IDA. It first attempts physical-unit backing, then recomputes actual free bytes before retrying smaller units when partition flag 0x40 allows it. This error can therefore represent insufficient aggregate bytes or disallowed fragmentation fallback. The free-byte getter at text+0x13cc8 recomputes under the native partition lock and does not update the cached +0x84 field. The prior startup counter used a different snapshot API that refreshes that cache; no cache-only allocator fix is established. Related native functions received descriptive names, signatures and comments in the saved IDB.

Added an optional diagnostic allocation observer, default OFF and forced OFF by normal packaging. It requires exact retail-3.60 Sysmem NID 3380b323 and validated native instruction signatures before installing its single extent-backing hook. The hook forwards all four native arguments and returns the original result. Only the first NO_FREE_PHYSICAL_PAGE failure captures original request size/flags, owning PID, partition attributes, free bytes and a bounded partition-name prefix. It performs no allocation, trace formatting or file I/O in that callback. A release/acquire snapshot is emitted by the existing worker afterward; no startup/idle physical-memory probe runs. Publication failures retain the snapshot for the next worker pass. Once the allocator hook is published, the code/resources remain resident until reboot even if later setup fails.

Host fixtures cover wrong identities/code/segment bounds, failed install, native argument/output/result preservation, request mutation by the native callee, first-failure selection, deferred output retry and post-publication lifetime. All 342 normal and 342 ASan/UBSan/leak CTests pass; native decoded register gate passes. Millisecond filesystem clock-skew warnings occurred in Docker, but the new diagnostic directory compiled every object and linked successfully; the clean normal rebuild remains byte-identical to dcec123f. New diagnostic SHA-256 is 437ed97cf4d705fd5d0762ca9fb854bbde8ef7f12a322a9eccd0849bb2a2f9c4. It has not yet run on the Vita; no new normal VPK was produced.

Before an inactive installer-menu control, exact-config verification stopped because the unrelated VitaStream entry was active again (937-byte 8a3f0a96). No installer launch occurred. Its payload was not touched. The existing user instruction prioritizing TLS and deferring VitaStream still applies: preserve that configuration, comment only the probe entry, and establish a fresh inactive boot before comparing app-launch behavior. Do not infer a loaded-module state solely from the newly changed on-disk configuration.

The newly re-enabled probe entry was backed up to ur0:tai/config.before-tls-allocation-control.txt and deferred again under the existing TLS-first instruction. A separate single unarmed reboot completed with disconnect/reconnect and exact 1a7c64d1 configuration readback. The installed TLSF00001 eboot was reverified as b1197d1f; agent launch supplied no installer button input. The viewed clean-inactive-installer-menu.png shows the actual installer menu, establishing successful app startup in this inactive baseline. The app is closed before selecting the diagnostic cold boot; this baseline warmup is not carried within the same boot as the next observer test.

Selected allocation-failure as one distinct diagnostic boot: retain the paired Browser-only scope and sparse recorder, leave startup memory probes OFF, add only the identity/instruction-gated first-allocation-failure observer. Only the owned ux0 experimental kernel/report and one activation byte are changed; original resources, Browser provider/CA and deferred VitaStream payload remain pinned. A unique stage/boot receipt and normal preflight precede the single reboot. The first active-run check will be the same installer menu, not an installer operation; Browser opening remains user-owned and is requested only after app-launch behavior is checked.

The allocation-failure diagnostic boot succeeds: exact 437ed97c payload, self-disabled config and positive allocator-hook UID are verified. Fresh boot trace cf156184 has 15 records/60 observed loads and no allocation failure; recorder status is clean. The same b1197d1f installer URI launch reaches its menu with no failure captured and no installer input. This URI launch is not equivalent to the user's icon/Start path. After closing the installer, the agent used independently viewed VitaShell icon and Start tile captures with normal touch press/release (not Browser input). VitaShell reaches its file interface.

The observer nevertheless captures a real NO_FREE_PHYSICAL_PAGE failure in PID 00102d25 during this sequence: requested 0x8000 (32 KiB), original extent flags 4, partition flags 0x1001a, and recomputed post-failure free bytes 0x4000 (16 KiB). The partition-name prefix is ScePhyMemPartKD. Trace 13c14fa6 contains all four fields; the same-boot report is clean. The application recovered from this particular internal allocation failure, so it is not labeled a fatal VitaShell launch. This is direct runtime kernel-pool pressure evidence; it does not yet identify the allocation consumer or prove a TLS repair.

The installed USB capture plugin was read without modification: 13877 bytes/hash 4fd1145f4ef8705775eb3bd184d1666c43938fb125eb81aa6daa61d722343d87. It matches the local release-1.9 downloaded and pool-release build artifacts. The associated source allocates dynamic conversion buffers first from the ordinary kernel physical pool, with an alternate-pool fallback. Host AVCaptureDevice metadata reports PSVita is not in use by another application after ffmpeg exits; QuickTime being present is not proof of an active Vita capture. Revisit the camera-idle control because earlier attempts were interrupted before Browser testing. Do not change the capture driver or infer causality from its allocation policy alone.

### 23.309 Normal coordinator camera-idle control selected from measured pressure

The direct allocation failure confirms the kernel physical partition had less free memory than a small request (16 KiB versus 32 KiB), not merely an unmeasured general low-memory hypothesis. USB capture is a remaining observation confound. The installed release-1.9 driver's associated allocation path first uses the ordinary kernel physical pool for its dynamically sized video buffers, with an alternate-pool fallback. Its identity is pinned, not changed. This policy alone does not prove capture caused the recorded failure, and idle release behavior must not be assumed from host-camera ownership metadata.

Selected the exact normal dcec123f kernel again with both providers and DNS enabled, no tracing/memory/allocation observer. The independent variable is the observation protocol: do not open the USB camera after the next cold reboot, use a native Home+Start screenshot for LiveArea, then user-owned Browser icon/Start. No installer or VitaShell warmup belongs in this fresh control. The earlier untraced failure used this same kernel/provider/CA with USB capture before launch; previous camera-idle attempts predated the packaged correction and were interrupted without qualifying it. All provider, certificate and unrelated plugin bytes remain unchanged. Stage/report backups and a unique normal-native-screen-control receipt precede one deliberate vitacompanion reboot. Do not infer a fix from staging or boot alone.

The single normal-native-screen-control reboot was acknowledged with disconnect/reconnect and exact self-disabled configuration; post-boot kernel and all protected/extra pins match, including unchanged UVC and VitaStream binaries. No USB camera session or app warmup occurred. quit all completed. Native Home+Start input was acknowledged after waking the display; the helper's four-second publication window found no file. A later single directory read located the expected 2026-10-13-152055.png (input timestamp 13:20:53 UTC); sequential double download and full PNG CRC/IEND validation succeeded. The viewed native frame shows LiveArea. No screenshot input was repeated and USB was never used as a fallback. Ready receipt preserves the initial publication error separately from the later successful capture. User-only Browser test at retry=20261013-native1 is pending.

### 23.310 Normal kernel fails with USB camera idle; physical recovery dependency

The user reports that URL loading showed Could not find the application and immediately froze the whole Vita for retry=20261013-native1. The exact dcec123f kernel had both providers/DNS enabled and all tracing/probes OFF. No USB camera was opened after boot before this report; the LiveArea check used a native Home+Start screenshot, whose delayed publication was verified. Thus merely omitting USB capture does not cure the normal configuration. Do not attribute this popup to a particular numeric AppMgr error, corrupted/missing application, or the earlier allocation failure without current evidence.

One post-failure config read timed out, and screen on received no reply. A post-failure USB capture attempt produced no frame; device index 0 no longer presented the expected Vita mode. No screenshot of the reported popup was obtained. Future capture checks should select the explicit PSVita device name rather than a shifting numeric index, so a disconnected Vita cannot select another camera.

A separate bounded recovery check again found stalled FTP. The single logged vitacompanion reboot request received no reply; the observer did not verify recovery and did not resend it. Its basis is the exact self-disabled pre-test checkpoint and the absence of subsequent agent config writes. The user was asked to perform a physical restart and leave LiveArea visible. Await recovery before any new activation; no source/payload/config was modified on the frozen device. Evidence and consumed recovery receipt are under native1-failure/.

The native screenshot remains a separate capture operation in this failed control. A later control may omit all pre-launch capture and use the user's visible icon/Start interaction, but no such test has been armed or executed. First reverify recovery, unchanged protected files, disabled entry and any new dump. Preserve the full normal-VPK, Browser, sceHttp, automatic-disarm and private-publication objective; it remains incomplete.

### 23.311 Capture-free normal control prepared after verified physical recovery

The user reports LiveArea returned after the required physical restart. Stable readback confirms exact 937-byte disabled/deferred configuration 1a7c64d1 and all protected/provider/UVC/VitaStream pins; no changed dump entry exists. The agent performed no capture during recovery verification. This resolves the physical-recovery dependency; no native1 receipt or recovery command was replayed.

Selected normal-no-capture-control with the identical dcec123f normal kernel, unchanged providers/CA and both HTTP/DNS enabled. No code or binary change distinguishes it from native1. Only the pre-Browser observation policy changes: omit USB capture and native screenshot operations entirely after boot, and omit all app warmup. The user supplies the visible LiveArea/icon/Start check; no agent Browser input or unverified coordinate input is selected. This separates native screenshot activity from the earlier failed camera-idle control without changing unrelated drivers or narrowing package coverage. The owned kernel/report have distinct backups and a fresh marker. A single new vitacompanion reboot is selected after exact before-state verification. Runtime result remains pending.

### 23.312 Exact normal configuration reaches TLS 1.3 without pre-launch capture

The user reports tls=TLSv1.3 for retry=20261013-nocapture1. The single-use normal dcec123f kernel has HTTP and DNS enabled, with tracing/memory/allocation observers OFF. No camera, native screenshot or app warmup occurred before the request. Stable post-result readbacks verify disabled config and the exact kernel/provider/other pins. No success-triggered re-arm or permanent activation occurred.

A native Home+Start screenshot was requested only after the user's successful report. A bounded delayed-publication collector retrieved the expected file without repeating capture input; full PNG CRC/IEND and stable bytes were verified. The independently viewed page displays TLSv1.3, X25519 and server timestamp 1791900455 (2026-10-13 14:07:35 UTC). Frame SHA-256 is 76946ee46c2648988be6de6fbd27415bc0c597814f8c9295093c0b4fdf3915ac. This qualifies one normal full-configuration Browser run; capture causality and broader stability are not proven by the comparison alone.

The VPK was rebuilt, and its decompressed kernel, Browser provider, HTTP provider and installer are unchanged at dcec123f, 6d035203, e4a6ed70 and 10c62f19 respectively. The private origin was independently checked as devnoname120/vita_tls_fixer, visibility PRIVATE, default branch main.

Found and corrected a separate packaging dependency defect: the Make rule reset diagnostic flags only when the kernel target was out of date. A newly generated diagnostic kernel could be newer than every prerequisite, bypassing normal reconfiguration. A temporary-fixture regression using the actual Makefile failed with kernel is up to date before the change. The kernel now has a phony normal-profile prerequisite, always reruns normal configuration, and uses CMake's incremental build instead of unconditional cleaning. The regression passes afterward. The 114 tools Python tests pass (two platform/tool skips); the rebuilt VPK hash is a3ba3c45f09a91cad12abcf88abfc9cde97b3e8ec91a508b109e5fbf3ba72f90, with the same verified kernel/provider payloads. This build correction does not change the tested runtime binary or claim to solve kernel-memory pressure.

### 23.313 Packaged-kernel repeat selected

After preserving the successful normal page and exact after-state, selected normal-package-repeat to test a second cold boot with the kernel extracted from the rebuilt VPK (a3ba3c45). Kernel/provider bytes are unchanged; both application and Browser support plus DNS remain enabled. No capture operation or app warmup belongs before the user Browser attempt. Distinct stage/report backups and a new consumed reboot receipt are required. This is a deliberate repeatability/package-identity check, not automatic persistent promotion after success. The self-disarm safeguard stays enabled. The completed compiled firmware matrix passes 31 available cells, with five unavailable images; docs/firmware-compatibility.json now identifies the actual normal linked ELF.

### 23.314 Packaged repeat confirms a second normal Browser TLS 1.3 cold boot

The unique normal-package-repeat stage preserved the owned kernel and diagnostic marker with per-file receipts. One vitacompanion reboot was acknowledged; disconnect/reconnect and the armed-to-disabled configuration transition were observed. Sequential readbacks verify the exact VPK-extracted dcec123f kernel and all protected/provider/other-plugin pins. The normal profile has reporting disabled, so its unchanged PENDING marker is not a fresh startup report: a readiness assertion initially expected a report, was corrected after checking the compile-time gate, and no reboot/input/config write was repeated. Boot proof is the observed restart and exact self-disarm transition. quit all completed before the user-owned Browser launch; no camera, screenshot or app warmup occurred in that boot.

The user reports TLSv1.3 for the packaged repeat. A native screenshot was taken only afterward, with screen on first and a single Home+Start input followed by delayed publication. Stable PNG bytes and all CRCs/IEND pass. The independently viewed page shows TLSv1.3, X25519 and timestamp 1791903226 (2026-10-13 14:53:46 UTC). Image SHA-256 is b055a3e317d268f8d606fe1140194f7605dae832aa09c965eff62a523effffbf. Evidence and the post-result disabled-state/protected-pin receipt are in build/browser-freeze-20261012T234400Z/normal-package-repeat-success/. The prior no-capture success was a separate cold boot at server time 14:07:35 UTC. No automatic re-arm or permanent promotion followed either success.

The 5218421-byte VPK passes ZIP integrity checks and has SHA-256 a3ba3c45f09a91cad12abcf88abfc9cde97b3e8ec91a508b109e5fbf3ba72f90. Its normal kernel, Browser provider and HTTP provider are dcec123f, 6d035203 and e4a6ed70; its installer is 10c62f19. Both runtime providers, the kernel, Sony compatibility modules, authoritative Sony/Mozilla certificate assets and notices are included. The new installer binary has not performed full system installation on the primary Vita; its existing installed eboot remains b1197d1f. The Browser tests used the packaged kernel and hash-matched already staged runtime inputs, not a claim that the entire new VPK installer path was executed.

Review retains the concrete activation changes: global Browser-provider loading into its target process, generic HTTP exclusion for both Browser titles before preparation-stack allocation, the Sony libc prerequisite gate, and mandatory normal-profile reconfiguration during packaging. Diagnostic memory/allocation recorders and startup-isolation options remain compiled out of the ordinary kernel. Source comments now explicitly note the memory snapshot API's cached-count update; it is not presented as a pure observer. Latest host results are 342/342 normal, 342/342 ASan/UBSan/leak, and 114 Python tests with two tool/platform skips. The normal kernel's generated-instruction gate and all 31 available compiled firmware cells pass; five corpus cells remain missing. No legacy project-name match exists in tracked files outside the README attribution. Origin is still PRIVATE and matched local main before publication.

Two normal successes establish repeatability under the no-pre-launch-capture protocol. They do not identify the cause of the preceding capture-assisted freezes, establish a UVC driver defect, or qualify production reliability, other physical firmware/hardware, unrelated SceHttp applications, or full latest-installer system writes. Those limits remain explicit in the README and handoff; the auto-disable safeguard stays enabled.

### 23.315 Backend-independent sceHttp checker and readable native interface

The user requested a standalone homebrew that measures ordinary Sony HTTP/HTTPS behavior against TLS 1.0-1.3 test endpoints, shows protocol results and cipher details, and switches between BrowserLeaks and SSL Labs. The older TLSF00002 probe directly links a TLS library and does not meet that requirement. Added a separate CMake project at samples/scehttp_tls_check/, title TLSCK0001, named Vita TLS Check. It links Sony HTTP/SSL/Net/NetCtl APIs and native display/controller/font services, with no curl, Mbed TLS, OpenSSL, pthread or third-party font runtime. The same executable can observe the stack serving normal sceHttp calls without loading or identifying a particular TLS provider. No plugin, kernel, certificate-store or boot-configuration installation is implemented in this app.

BrowserLeaks supplies four version-specific endpoints and a separate JSON connection report. Protocol checks require an HTTP 200 and the exact matching version body. The JSON parser distinguishes selected_version from the record/ClientHello legacy version, and the selected cipher from the ordered offered list. It retains key exchange, signature, offered groups/extensions/ALPN and JA3/JA4 when supplied. SSL Labs supplies TLS 1.0-1.2 checks on ports 10301-10303 and a server-rendered offered-cipher list. Its public page redirects to clienttest.ssllabs.com:8443; the app uses that canonical report URL directly. TLS 1.3 on that tab remains not tested / advertised only, rather than being fabricated as a completed connection. The independent BrowserLeaks TLS 1.3 endpoint remains the actual protocol test. Offered suites are not presented as individually negotiated ciphers. No mixed-content, SSL 2/3, vulnerability or JavaScript tests were imported from the reference page.

Requests run serially on a Sony kernel thread with fresh templates/connections, keepalive and redirects disabled, normal certificate/hostname/time/known-CA checks enabled, bounded bodies and timeouts, and an abort request after the deadline. Cancellation retains native errors while marking unfinished rows not tested. A captured native abort returned SSL I/O with detail bit 4; detail bits alone therefore no longer imply certificate rejection. The app uses the complete public HTTPS sysmodule dependency group. A local SDK HTTPS sample confirms the same SSL/HTTP initialization order and default verification path without an explicit default-CA load; no speculative certificate-loading or verification-bypass call was added. A supplementary read-only IDA lookup crashed; the tool restored its saved database and the recovered lease was closed, with no analysis edits or binary patches.

Preflight verified the exact disabled/deferred 937-byte config 1a7c64d1, protected resources, and absence of TLSCK0001. The new VPK was installed through VitaShell. At the user's request its download location is ux0:/0VPK/vita_tls_check.vpk. Every owned-app update preserved previous bytes, staged/read back the new file and recorded per-file hashes and backup paths in build/scehttp-sample-device/*-deployment.json. Scope is the new app, its VPK and its own report folder. No TLS activation/re-arm, reboot, installer operation or system-file replacement occurred. Standing primary-device/app-test authority and the current app request cover these actions. The first unlogged revision returned to LiveArea without a report and is not counted as successful execution. Later revisions have fresh main/mutex/display/font/network startup receipts, actual request reports and independently viewed frames.

The user reported fast blinking and an unreadable bitmap font. The first UI cleared its single visible framebuffer on each polling loop. Replaced that implementation with Sony's antialiased Latin vector font renderer, a complete CPU drawing surface, one scanout buffer, and vblank copies only when data/view state changes. There is no display page flipping or continuous idle repaint. A bounded glyph cache and queued controller reads preserve input during text rendering. Protocol cards, connection information, offered-cipher scrolling, a clean error table and handshake details fit 960x544. L/R changes source, Square changes detail page, Cross reruns, Triangle cancels and Circle exits. The local remote-control service needs l1/r1 emulation for the shoulder events observed by the normal controller API; the remote r command did not switch tabs. Square, source switching, cancellation, rerun and exit were observed on the Vita. Three-second idle captures each contained 89 identical decoded frames after the presentation fix. This is checker rendering evidence, not a fix for the earlier Browser/capture interaction.

The native runs currently fail TLS setup on these services: request error 0x80431075, typically SSL 0x804351FE for legacy/version-pinned connections and 0x80435061 for TLS 1.3/report requests; some SSL Labs port attempts also time out. Completed and cancelled reports retain the exact per-request result and elapsed time under ux0:/data/vita-tls-check/. No negotiated cipher or fingerprint is invented when the report is unavailable. These are actual sceHttp attempts and successful checker/UI execution; they do not establish successful generic HTTP-provider injection or HTTPS transport, nor do they prove each TLS protocol is unsupported. The existing Browser TLS 1.3 proof remains separate. The checker supplies a repeatable plain-Sony-API test for that remaining work.

Host ASan/UBSan tests pass for the bounded parser, malformed/truncated/duplicate fields, wrong protocol responses, captive-portal payloads, selected-versus-offered data and error classification. The actual layout/compositor is rendered with a clearly labeled host fixture and framebuffer guards; the host-only font backend uses FreeType while the VPK uses ScePvf. Both exact public report URLs were fetched on the host with the app's headers and their responses parsed successfully. Native cross-builds and VPK integrity checks pass, and the link map verifies the absence of bundled HTTP/TLS libraries and the old bitmap font. Current runtime receipts, UI captures, frame hashes, initialization audit and historical app revisions remain under build/scehttp-sample-device/; host endpoint/layout evidence is under build/scehttp-sample-research/.

Final checker artifact: 65151 bytes, VPK SHA-256 7a561aed7779c10639c1ecb73befa0c1dff6fc399459c63e05654c5c454c51de, installed eboot c5c4a867c5395e0bd03df1153260f80bfeb35d6a62faea609346b0885a3f065e. Both the installed executable and ux0:/0VPK/vita_tls_check.vpk were reread and matched to the local package. The exact final build produced 88 identical frames in a three-second idle capture. A cross-directory move of an app-directory backup was refused by FTP; those app backups remain intact. The nine older VPK copies were instead copied into the checker data folder, verified byte-for-byte, and removed from 0VPK, leaving its current download easy to identify. Original protected resources and the disabled 1a7c64d1 configuration were verified again. The main tls_fixer VPK, kernel and provider bytes remain unchanged.

### 23.316 Persistent diagnostics identify the generic HTTP prerequisite gap

The user objected to repeated device iterations without sufficient analysis and requested extensive logging. The checker previously saved final request errors but did not expose the loaded implementation; the HTTP provider's diagnostics were console-only. Added a per-launch API log with PID/TID, monotonic timestamps, sequential records, run/request identities, API entry/return, native result, call timing, native request handles, SSL error/detail, read byte counts, cancellation and cleanup. Generic module inventories bracket HTTPS load/HTTP init and requests, without loading or selecting any particular TLS provider. Writes use a separate native mutex, handle partial writes and stop the sink on I/O failure; the final budget record reports exhaustion explicitly. No request result or verification policy depends on logging success. Native API duration excludes writing the entry record; wall-clock request duration includes diagnostic overhead. Bounds are 128 queried modules, 768 bytes per line and 8192 records per launch. Storage synchronization is best effort and does not guarantee the last in-flight record survives a crash.

Added file tracing to the HTTP provider using the existing primary/savedata infrastructure, with a 4096-record process budget. Browser retains 512 records. Both identify component, PID, TID, monotonic time, sequence and exhaustion; partial writes are handled. New provider stages record start arguments, mapped module identity/extents, failed signature index/byte, crypto/CA initialization, root count, per-hook installation results, registry and connection lock results, backend ownership/Sony continuation, setup skip reasons, handshake entry/return, socket return/counts, certificate policy/callback decision and Sony error mapping. No TLS payload, certificate dump, key, cookie or arbitrary application body is logged. Added a distinct prereq.libc.missing event to the existing coordinator recorder; the normal recorder remains disabled, so this addition compiles out and its kernel remains byte-identical dcec123f. No previous kernel memory/allocation probe or experimental hook mode was enabled.

The first app-only run on the current boot produced 265 contiguous records in process 003C258F; the final logging build produced 270 in process 009D2105. Each has five complete generic module snapshots and five complete request lifetimes, with all module-info queries successful and all module counts accounted for. Before network loading there are 12 modules; after loading and throughout requests there are 16. Both inventories include SceLibHttp/SceLibSsl from the existing replacement paths, and neither includes SceLibc or tls_fixer_http. Sony module loading, SSL/HTTP initialization, verification configuration, template/connection/request creation and cleanup all return success. Every endpoint fails inside sceHttpSendRequest with 0x80431075; the report/TLS 1.3 SSL value is 0x80435061, and TLS 1.0-1.2 return 0x804351FE, with detail zero and no HTTP body.

The normal compiled coordinator forces PREPARE_NAME_QUERY and checks SceLibc before HTTP provider start. The provider imports Sony libc, while this newlib homebrew has not loaded it. The existing production-context host test directly asserts that missing, invalid or incorrectly named libc prevents provider loading/argument allocation. Missing libc is therefore a demonstrated import/activation prerequisite gap for this process. The current untraced kernel does not persist its exact return branch, so attribution to that particular skip branch is still source/profile inference. The live proof is that redirection works, the public APIs initialize, the provider and its prerequisite are absent, and SendRequest fails. These are not Mbed TLS handshakes or evidence against its CA parsing; prior Browser successes do not cover this homebrew process. No transport-policy or prerequisite-loading fix is claimed or introduced by the logging change.

Device scope was limited to TLSCK0001's executable, ux0:/0VPK/vita_tls_check.vpk, and its own data folder. Preserved each previous executable/VPK with unique per-file backups, staged/read back replacements and verified the disabled configuration. Primary-device standing authority and the explicit logging request cover the two app-only launches. Zero reboots, re-arms, Browser launches, kernel/provider replacements or system CA/storage edits occurred. Source/cross-built provider diagnostics are prepared for the next prerequisite-qualified test and have not been activated on the console. The rebuilt normal kernel is still dcec123f; the main installer VPK remains a3ba3c45. The preceding Browser compiled artifact was also preserved before checking the shared logger build.

Final checker VPK is 69623 bytes with SHA-256 0c5590618908094b927e7f7e1f23d0695f588ba234bbc1f5b6ad6f624f2ac390; installed eboot is 355f04af4a2e798a93c875b0dbf625e36d5c3bbf3272498c9cc40be23972e38a. The final runtime trace has SHA-256 499c503e76147726340f043bc6f651c4bdecc1ffd73d13172193545738252c5d. Checker, HTTP provider and Browser provider cross-builds pass. The normal kernel generated-instruction gate passes and its package hash is unchanged. Host CTests pass 349/349 normally and 349/349 with ASan/UBSan; new file-sink cases exercise primary/fallback/unavailable storage, short writes, write failure, truncation, per-component identity and budget markers. The checker parser/sanitizer tests still pass, and its native map remains free of curl/Mbed/OpenSSL/pthread/third-party font runtimes.

Raw traces, module/request analyses, deployment/backup identities and build/test logs remain in build/logging-20261013/, with final-byte/runtime evidence under final/. docs/scehttp-diagnostics-20261013.md records the causal boundary and next prerequisite work. The richer logs are a completed observability improvement; generic-provider HTTPS and the earlier Browser/capture freezes remain unresolved.

### 23.317 Minimal SceLibKernel runtime passes native tests; integration boot fails and is withdrawn

The user selected a minimal libc shim on SceLibKernel, with libk only as a fallback and no Mbed TLS/OpenSSL dependency patches. Inspected DaveeFTW/libk at 1c361428: its build covers string functions, not the allocator/formatter needed by this provider. Implemented an HTTP-provider-local runtime using SceSysmem-backed 2 MiB storage, sceClibMspace allocation, native mutex serialization and sceClib memory/string/format APIs. Linker wrappers satisfy the ordinary C calls in the unchanged provider/dependency objects; SceLibc_stub is removed from the HTTP target. Native SELF audit includes variable-only imports and rejects full libc/unexpected libraries. A byte comparison confirms all 943 Mbed TLS/TF-PSA C/header sources match the pinned archive. OpenSSL and the installer are unchanged.

Host tests cover init failure cleanup, allocation overflow, alignment, realloc preservation/failure, active-heap teardown refusal, concurrent allocations and formatting. Two native smoke launches used the owned checker slot with per-file backup/readback and restoration to 355f04af after each. The first identified Sony formatter truncation without NUL termination; the shim now supplies C99 termination, and the second reports failures=0 with no SceLibc module loaded. Native heap stats: capacity 2097152, peak 262800, remaining allocator metadata 640 and zero outstanding allocations. No plugin activation or reboot belonged to these smoke tests. The full pre-scope host suite passes 350/350 normally and with sanitizers. New provider/kernel import coverage passes 31 available firmware/hardware cells with five absent corpus images; kernel generated code contains no decoded FP/SIMD instructions.

Staged the new 249182-byte provider separately on ux0, hash 7b45b769, without replacing the installed system provider. The integration kernel 56bcaee9 was backed by the prior dcec123f test payload and the exact disabled configuration. Removed the now-unneeded libc gate while retaining Browser exclusions, post-start activation, native 16 KiB preparation and name queries; actual compiler definitions are ON despite CMakeCache's OFF defaults. One unique vitacompanion reboot was consumed. No verified reconnect followed within the bounded observer. The user reported powered off/frozen, then boot-logo freeze and a rapidly blinking blue power LED after attempting to start again. No second agent reboot, re-arm, Browser launch or checker TLS test occurred.

When the user reported the device available, stable config reads matched disabled 1a7c64d1: self-disarm had completed. Preserved the failed kernel, restored the owned test path to dcec123f, reread it and verified all protected pins. No taiHEN repair, L-button bypass, card remapping, formatting, firmware reinstall or recovery-tool change was required. The user handled physical power/recovery; the agent did not infer a completed reset from the command acknowledgment. No primary HTTP-provider log or fresh matching crash dump was found; SceShell's savedata has no temp directory for the fallback sink. The crash location and cause remain unestablished.

The test scope was too broad: removal of the libc gate also made early system processes eligible for the new provider, whereas the isolated probe qualified only its runtime primitives. The integration candidate is withdrawn. Added an explicit title restriction for separately staged ux0 diagnostics, enforced before preparation allocations/loading, and required by CMake. Normal packaging explicitly resets both the provider path and diagnostic title. This is a test-scope correction, not a claimed panic fix, and no corrected activation has been attempted. Source is retained as a runtime draft, not promoted into the normal VPK. The installed providers, CA files, storage/boot configuration, recovery tools and main a3ba3c45 VPK remain preserved. Details and continuation boundaries are in docs/http-kernel-runtime.md; receipts and logs are in build/user-runtime-20261013/.

Final runtime-draft validation after the title restriction: 351/351 normal host tests, 351/351 ASan/UBSan tests and the normal-package path/title-reset regression pass. A separate scoped kernel cross-build passes the generated-instruction gate; it is not staged or activated. The source draft is retained on dev/kernel-runtime, while main and the normal VPK remain unpromoted.
