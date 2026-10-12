# TLS 1.3 Hardware Validation Protocol

## Status

This document defines the real-hardware validation required before tls_fixer may claim that TLS 1.3 works in the PlayStation Vita browser. Passing host tests, static binary validation, and VitaSDK builds is necessary but not sufficient.

**Implementation status:** two distinct providers are packaged: `tls_fixer_http.suprx` for SceHttp and `tls_fixer.suprx` for the recovered browser backend. The matrix below is now applicable to the test build, but every device row remains unverified until executed. Browser tests must show the browser provider, not merely the SceHttp provider, negotiating TLS 1.3. See `docs/tls13-browser-test.md` for the initial test.

Record every result with:

- Vita model and firmware;
- enso/taiHEN version and relevant plugins;
- tls_fixer VPK SHA-256;
- `tls_fixer.skprx`, `tls_fixer_http.suprx` and `tls_fixer.suprx` SHA-256;
- endpoint configuration and server-side TLS log;
- provider/kernel debug output;
- observed browser or API result;
- whether the browser/WebKit process was restarted between cases.

Do not promote a case from **unverified** to **passed** without preserving enough evidence to distinguish TLS negotiation from a cached page, proxy response, or legacy BSAFE connection.

## 1. Test Environment

### 1.1 Vita configurations

At minimum, test:

| ID | Hardware | Firmware | Purpose |
| --- | --- | --- | --- |
| V1 | retail Vita | 3.60 enso | oldest supported kernel/module environment and 3.60 compatibility paths |
| V2 | retail Vita | 3.65 enso | common permanent-custom-firmware installation |
| V3 | retail Vita or PSTV | 3.60/3.65 | second hardware/process-layout sample |

Record all kernel and user plugins. Repeat the core transport matrix once with unrelated plugins disabled if any failure appears process- or timing-sensitive.

### 1.2 Controlled server

Use a server under the tester's control. It must expose independent hostnames or ports for each protocol/certificate behavior and log:

- accepted TCP connections;
- ClientHello supported versions, SNI, groups, signature algorithms, and cipher suites;
- selected protocol and cipher;
- alert direction and code;
- application request path;
- session resumption, when enabled;
- connection close mode.

The test DNS names must resolve from the Vita. Do not use public third-party TLS test sites as the only evidence because their protocol, certificates, redirects, and CDN behavior can change independently.

### 1.3 Required endpoints

| ID | Endpoint behavior |
| --- | --- |
| E13 | TLS 1.3 only, valid public or private test chain trusted by the installed CA bundle |
| E12 | TLS 1.2 only, otherwise identical to E13 |
| EBOTH | TLS 1.2 and TLS 1.3 enabled |
| EBADCA | chain signed by an untrusted CA |
| EHOST | valid chain for a different hostname |
| EEXPIRED | expired leaf certificate |
| EFUTURE | leaf certificate not yet valid |
| EEOF | complete handshake, then close TCP without TLS `close_notify` |
| ECLOSE | complete request/response and send TLS `close_notify` |
| ESLOW | configurable handshake/read delay longer than the request timeout |
| ERESET | reset the TCP connection during handshake and during application data |
| EREDIRECT | valid HTTPS response redirecting to another TLS endpoint |
| EKEEP | supports multiple requests over one persistent TLS connection |
| EPROXY | reachable only through the configured HTTP CONNECT proxy |

Use the same HTTP response body for E13, E12, and EBOTH. Include a unique endpoint ID and server timestamp in the body so cached responses are obvious.

## 2. Artifact and Installation Gate

### 2.1 Pre-install evidence

Record SHA-256 for:

```text
tls_fixer.vpk
tls_fixer.skprx
tls_fixer_http.suprx
tls_fixer.suprx
lhttp.suprx
lssl.suprx
certs.cer
```

Confirm the VPK includes `THIRD_PARTY_NOTICES.md`, `licenses/Mbed-TLS-LICENSE.txt`, `licenses/TF-PSA-Crypto-LICENSE.txt`, and `licenses/mldsa-native-LICENSE.txt`. Record the source archive checksum and engine versions; the current source target is Mbed TLS 4.2.0 / TF-PSA-Crypto 1.2.0.

### 2.2 Full install

1. Install the full package.
2. Confirm the installer reports success and requests reboot.
3. Reboot.
4. Confirm these files exist:

```text
ur0:tai/tls_fixer.skprx
vs0:/data/external/tls_fixer/libhttp.suprx
vs0:/data/external/tls_fixer/libssl.suprx
vs0:/data/external/tls_fixer/tls_fixer_http.suprx
vs0:/data/external/tls_fixer/ScePsp2Compat.suprx
vs0:/data/external/tls_fixer/tls_fixer.suprx
vs0:/data/external/cert/CA_LIST.cer
```

5. Confirm the exact tls_fixer taiHEN block exists once in `ur0:tai/config.txt`.
6. Re-run the installer and verify it detects the complete installation rather than offering a false repair caused by configuration parsing.

### 2.3 Fail-open installation cases

Exercise each case separately:

| Case | Mutation | Expected result |
| --- | --- | --- |
| G1 | remove `tls_fixer_http.suprx` | replacement `libhttp`/`libssl` continue to provide TLS 1.2; no provider injection |
| G2 | alter one byte of replacement `libhttp.suprx` | exact hash gate disables provider injection; normal module behavior must not be corrupted |
| G3 | restore file hash but force provider start failure | `libhttp` remains loaded and BSAFE TLS 1.2 remains usable |
| G4 | force one transport hook installation failure | all earlier provider hooks are released; no mixed hook set remains |
| G5 | corrupt or remove CA bundle | provider activation fails rather than disabling verification; BSAFE path remains available where its trust setup succeeds |

Restore exact files and reboot after every mutation.

For the browser, repeat G1-G5 using `tls_fixer.suprx` and `ScePsp2Compat.suprx` instead of the SceHttp pair. G4 has a deliberately different safe outcome: once any browser hook has been published, a later installation failure keeps disabled forwarding hooks resident until process exit. The connect hook is installed last, and provider TLS remains disabled unless the complete set succeeded. Browser fallback is to its embedded OpenSSL, not BSAFE. A modified SELF may itself fail to load; the hash gate does not make arbitrary corrupted firmware executable.

## 3. Process Coverage and Injection

Start from a cold reboot and capture kernel/provider logs. **First identify the actual TLS consumer:** observing a libhttp load is not proof that the browser sends its traffic through that module. The independent compatibility-module backend needs its own completed adapter and activation evidence.

1. Launch the browser without opening an HTTPS page.
2. Record every PID that loads replacement `SceLibHttp`.
3. Record every PID that receives `tls_fixer_http.suprx` or `tls_fixer.suprx`, and distinguish their activation messages.
4. Identify whether networking occurs in the browser process, a WebKit process, or both.
5. Close the browser and confirm the relevant processes terminate or unload as expected.
6. Repeat launch/close at least 20 times.
7. Confirm no process receives duplicate provider loads or duplicate hook installation.
8. Repeat after opening multiple tabs and after a browser crash/forced termination.

Expected provider diagnostics include one activation line per process and connection lifecycle lines without plaintext payload, secrets, or certificate private data.

## 4. Protocol Negotiation Matrix

For each case, clear browser cache where relevant, restart the browser process, and preserve both client and server logs.

| Case | Endpoint | Expected server result | Expected Vita result |
| --- | --- | --- | --- |
| P1 | E13 | TLS 1.3 selected | page succeeds through provider |
| P2 | E12 | TLS 1.2 selected | page succeeds through provider |
| P3 | EBOTH | TLS 1.3 selected | page succeeds; provider log names TLS 1.3 and selected cipher |
| P4 | E13 without provider file | handshake fails because BSAFE lacks TLS 1.3 | failure is controlled; browser/process remains stable |
| P5 | E12 without provider file | TLS 1.2 selected | legacy fallback succeeds |

In browser P1-P5, "provider file" means `tls_fixer.suprx`. For SceHttp application tests it means `tls_fixer_http.suprx`. Both source-built providers remain loaded until process exit; disable by removing the corresponding file and rebooting, not by hot unloading.

Verify SNI on the server. A successful connection to a single-certificate default virtual host is not sufficient evidence that SNI works.

Record the selected TLS 1.3 cipher. At least one AES-GCM suite must be exercised. Exercise ChaCha20-Poly1305 only if the packaged configuration advertises it and the server can select it.

## 5. Certificate Verification

### 5.1 Default policy

| Case | Endpoint | Expected result | Expected detail mask |
| --- | --- | --- | ---: |
| C1 | E13/E12 valid chain | accept | `0x00` |
| C2 | EBADCA | reject | includes unknown CA `0x20` |
| C3 | EHOST | reject | includes CN/hostname `0x04` |
| C4 | EEXPIRED | reject | includes not-after `0x08` |
| C5 | EFUTURE | reject | includes not-before `0x10` |
| C6 | malformed/signature-invalid leaf | reject | includes invalid certificate `0x02` or internal `0x01` as justified |

Use an API test application in addition to the browser where necessary to call `sceHttpsGetSslError` and record both the public HTTPS error and detail value.

### 5.2 HTTPS option policy

For each public option bit, use the normal Sony API to enable/disable it and verify that the provider observes the resulting effective option word. Do not patch provider memory or bypass firmware policy.

Required cases:

- disable only CN check and connect to EHOST;
- disable only known-CA check and connect to EBADCA;
- disable only not-after and connect to EEXPIRED;
- disable only not-before and connect to EFUTURE;
- disable server verification where firmware policy permits it;
- attempt prohibited option changes from a game/application context and confirm Sony's API rejects them before the provider observes a bypass.

### 5.3 Application callback

Install `sceHttpsSetSslCallback` and record:

- verification bits passed to the callback;
- certificate count and order;
- user argument identity;
- negative callback return rejecting the connection;
- zero and positive callback results accepting a valid chain;
- zero and positive results for invalid chains being rejected unless Sony's recovered post-callback process/version/system-parameter policy explicitly allows them;
- failure of the policy query never becoming permission merely because an output buffer contains a nonzero value.

During the callback, exercise every compatibility function:

```text
sceSslGetSerialNumber
sceSslGetSubjectName
sceSslGetIssuerName
sceSslGetNotBefore
sceSslGetNotAfter
sceSslGetNameEntryCount
sceSslGetNameEntryInfo
sceSslFreeSslCertName
```

Compare provider results with OpenSSL/Mbed TLS inspection of the same peer chain and, where possible, with BSAFE TLS 1.2 callback results. Test invalid indexes, short output buffers and repeated name free. Borrowed certificate handles must become stale after callback return. Returned subject/issuer names must remain inspectable after callback return and connection destruction, until explicitly freed; old freed name handles must not become valid when another name reuses a slot.

## 6. Custom Certificate and Client Authentication Fallback

The first provider release deliberately falls back to BSAFE for new connections after successful `sceHttpsLoadCert` with custom CA or client material.

1. Establish a provider-owned connection before calling `sceHttpsLoadCert` and keep it open.
2. Load a custom CA, then create a new request.
3. Confirm the new request uses BSAFE, not the provider.
4. Confirm the existing provider connection remains stable and is not migrated.
5. Call `sceHttpsUnloadCert`.
6. Create another request and confirm provider use resumes.
7. Repeat with client certificate/private key material.
8. Verify a failed `sceHttpsLoadCert` call does not disable provider use.

Do not claim TLS 1.3 client-certificate support from these tests; the expected behavior is TLS 1.2 compatibility fallback.

## 7. Nonblocking, Timeout, and Error Translation

Use an API test application capable of setting request nonblocking mode and explicit connect/send/receive timeouts.

### 7.1 Handshake EAGAIN

- In nonblocking mode, force the socket to require multiple handshake iterations. Expected: `SCE_HTTP_ERROR_EAGAIN`, preserved provider state, eventual success.
- In blocking mode, force socket EAGAIN at the same point. Expected: `SCE_HTTP_ERROR_TIMEOUT`, no fatal HTTPS error stored by that mapping, and controlled request termination by Sony's HTTP state machine.

### 7.2 Application read/write

- Force WANT_READ and WANT_WRITE during application data.
- Verify positive partial reads/writes are preserved.
- Verify each provider engine call is bounded to 1500 bytes while the Sony caller completes larger transfers.
- Verify zero-length read/write returns zero.
- Verify null buffer with nonzero length returns Sony invalid-value behavior and does not crash.

### 7.3 Network failures

| Case | Failure | Expected public result |
| --- | --- | --- |
| N1 | handshake TCP reset | HTTP SSL failure with stored handshake/network detail |
| N2 | application TCP reset | HTTP SSL failure with stored HTTPS I/O detail |
| N3 | ESLOW connect timeout | HTTP timeout |
| N4 | ESLOW receive timeout | HTTP timeout |
| N5 | EEOF | fatal HTTPS I/O, not clean EOF |
| N6 | ECLOSE | clean zero-length EOF after close-notify |

Confirm a timeout does not independently poison provider memory or crash teardown. Sony may terminate the request immediately; it need not reuse the timed-out connection.

## 8. HTTP Behavior Preserved Above TLS

Exercise Sony HTTP behavior through both TLS 1.2 and TLS 1.3 endpoints:

- GET and POST bodies larger than one TLS wrapper chunk;
- redirects across hostnames and protocol versions;
- cookies;
- basic/digest authentication if available;
- gzip content decoding;
- chunked transfer encoding;
- Content-Length responses;
- connection reuse through EKEEP;
- abort during handshake, request upload, and response download;
- proxy CONNECT through EPROXY.

The purpose is not to revalidate every Sony HTTP feature independently, but to expose transport return-value or lifecycle mismatches that corrupt the existing state machine.

## 9. Resource and Stability Measurements

### 9.1 Memory

Measure process memory at:

1. browser process start before provider load;
2. after provider load and CA parsing;
3. during peak TLS 1.3 handshake;
4. with 1, 4, 8, 16, and 32 concurrent provider connections;
5. after all connections close;
6. after browser process termination.

Record allocation failure behavior at registry capacity and under induced low-memory conditions. The expected result is a controlled BSAFE fallback before provider bytes are sent, or a Sony out-of-memory error for a provider-owned connection, not memory corruption.

### 9.2 Performance

For E13 and E12, record at least 30 cold handshakes and 30 reused/resumed connections where supported:

- TCP-to-handshake completion latency in milliseconds;
- time to first response byte;
- CPU utilization if available;
- negotiated cipher/group/signature;
- provider memory increase.

Report median, 95th percentile, minimum, and maximum. Do not compare against BSAFE without controlling DNS, network path, server, and cache state.

### 9.3 Repeated lifecycle

The current provider rejects manual hot unloading and remains resident until process exit. Verify that a stop request fails without releasing hooks or state. Do not interpret an empty connection registry as proof of safe hot unload; active continuations and concurrent hook entry require a separate, proven quiescence mechanism.

Run at least:

- 100 sequential HTTPS requests;
- 50 browser launch/close cycles;
- 20 mixed TLS 1.2/TLS 1.3 redirects;
- 20 forced aborts at varying handshake/application phases;
- a 30-minute persistent connection/download test.

Any freeze, blue-screen restart, black screen, kernel panic, process crash, leaked hook, duplicate provider load, or monotonically increasing memory invalidates the runtime-validation claim until explained and fixed.

## 10. Uninstall and Recovery

1. Uninstall the HTTP/SSL package.
2. Confirm `libhttp.suprx`, `libssl.suprx`, and `tls_fixer_http.suprx` are removed from the tls_fixer external directory.
3. Confirm the exact tls_fixer taiHEN configuration block is removed without modifying unrelated entries.
4. Reboot and verify stock behavior.
5. Reinstall after uninstall and repeat P1, P2, C2, N5, and one callback case.
6. Interrupt installation at controlled file-copy points and verify the installer reports failure, does not reboot, and permits a repair run.

## 11. Evidence and Acceptance

### Source/build acceptance

The implementation is source/build complete when:

- normal and sanitizer host tests pass;
- exact `libhttp` static validation passes;
- hard-float provider/kernel/installer/VPK builds pass;
- generated artifacts contain the expected licenses and modules;
- fail-open paths are statically reviewed;
- no generated reverse-engineering database or proprietary SDK content is committed.

### Runtime acceptance

TLS 1.3 may be described as validated only after all of the following have evidence:

- P1, P2, and P3 pass on at least V1 and V2;
- certificate cases C1-C6 return the expected public behavior;
- callback wrappers and all eight public inspection functions pass;
- nonblocking handshake retries and timeout translation pass;
- EEOF and ECLOSE remain distinguishable;
- redirects, connection reuse, abort, and proxy paths remain stable;
- repeated lifecycle and memory tests reveal no unresolved leak or crash;
- exact-hash/provider-start/hook-failure cases preserve BSAFE TLS 1.2.

Until both the separate browser adapter and this runtime evidence exist, release notes must state **SceHttp adapter under development; browser adapter incomplete; no Vita runtime validation**. A build-complete SceHttp component must not be presented as a build-complete browser feature.
