# Vita TLS Check 1.3

A standalone 960 x 544 homebrew application that exercises the Vita's public `sceHttp` / `sceHttps` APIs. It does not link curl, OpenSSL, Mbed TLS, a plugin SDK, or another HTTP/TLS implementation. The same VPK can be run with the stock networking stack or with a system plugin: it observes whichever implementation serves the ordinary Sony calls.

The earlier `tls13/probe` application directly uses a TLS library and tests a different boundary. This sample does not share its transport, CA loader, or provider code.

## Use

Install `vita_tls_check.vpk` through VitaShell, then open **Vita TLS Check** (`TLSCK0001`). It starts the BrowserLeaks and PlayStation checks automatically. No kernel/plugin installation, boot configuration, certificate-store modification, or reboot is performed by this application.

- **Cross:** repeat all checks after the current run finishes.
- **Up / Down or either joystick:** scroll offered cipher suites. Hold to repeat after 220 ms, then every 40 ms; stick movement has a dead zone.
- **Square:** cycle offered ciphers, request errors, and handshake details.
- **Triangle:** cancel the running sequence.
- **Circle:** cancel if necessary, then exit after the worker returns.

TLS 1.2/1.3 tiles show green Connected / secure after a verified endpoint response. Verified TLS 1.0/1.1 connections show an orange exclamation with Insecure / vulnerable. Expected legacy rejection by the active tls_fixer provider shows a green tick, Blocked / secure, and Disabled by tls_fixer (secure) in Details. This requires runtime detection of the started provider, a failed TLS 1.0/1.1 request without an HTTP response, and its recognized peer-alert or out-of-range-version error detail. It annotates the provider's known TLS 1.2 minimum; a generic peer alert alone is not proof of its precise cause. Stock detail=0, unknown provider state, successful/unverified responses and unrelated failures do not meet this rule. An expected policy block skips the certificate retry and retains the original native errors in the report.

Certificate rejection remains orange Cert error, DNS/network/timeouts are Unreachable, and other TLS failures remain red TLS error, including when tls_fixer is enabled. TLS error does not mean the client disabled that version; cipher, SNI, server configuration and other handshake incompatibilities can also cause it. Other HTTP/body/API failures remain Failed. Provider detection alone never turns a failed request green.

Each of the four protocol checks starts with certificate verification enabled. If it fails at the TLS stage before receiving an HTTP status, the app attempts at most one fresh request to that same public protocol endpoint with certificate checks disabled, if Sony permits that policy change. HTTP 200 plus the exact version-specific body is still required. A successful retry with an explicit original certificate error keeps Cert error and reports TLS works; certificate rejected in Details. If the original error was ambiguous, the tile says Unverified and Details says Connected with certificate checks off. An unverified response is diagnostic evidence, not an authenticated connection. Both attempts' native errors, HTTP status, timing and verification policy are preserved in the saved report; Details shows the original errors and combined time. Failed retries do not establish a disabled protocol or a particular missing root certificate.

Stock 3.60 can refuse `sceHttpsDisableOption` with `0x8043506B` under its caller/target-SDK policy. In that case no retry request is sent: Details says cert retry unavailable, and the report records retry_verification=unavailable plus the setup error. It does not pretend the handshake was retried without validation. The app neither changes the registry nor patches Sony's policy; it also preserves its normal target SDK rather than changing the native stack's compatibility behavior to evade the restriction. An ordinary permissive certificate callback is subject to the same native policy gate.

The top-right tls_fix indicator begins with neutral checking... until detection completes, then uses Sony's module inventory in this process and requires tls_fixer_http to be STARTED (state 6). It never reads taiHEN configuration, loads a provider, calls private plugin APIs, or infers activation from endpoint success. It indicates the provider serving this application's HTTP boundary, not coverage of every process on the console.

The interface uses antialiased Latin system fonts through Sony's `ScePvf` API. There is one display buffer, no page flipping, and a separate CPU drawing surface. Complete frames are copied at vblank only when the data or selected view changes; idle frames are never cleared or repainted.

Results are written to `ux0:/data/vita-tls-check/`, one small text file per run. A separate bounded `startup.txt` records initialization results for the most recent launch. Reports include endpoint, request result, HTTPS error/detail, HTTP status, elapsed time, negotiated details and the server-observed offered lists. Request results preserve Sony API errors; checker-local HTTP/payload validation failures use -1 with an explicit message. They do not contain response bodies, application traffic, TLS keys, or cookies. Lists are bounded to 64 entries each; responses are limited to 96 KiB.

Each launch also creates `api-<PID>-<monotonic-time>.log` in that folder. It records process/thread IDs, sequential record numbers, run/request IDs, verification mode, API entry and return, native result, time spent in the call, SSL error/detail, bytes read, cancellation and cleanup. Module inventories before and after HTTPS loading/initialization and requests include module names, UIDs, state, segment sizes and source paths. The full diagnostic inventory remains generic; the separate status indicator recognizes the started HTTP provider without loading or modifying it.

Diagnostic writes are serialized on their own native mutex. Short writes are completed, an I/O failure disables the sink, and logging failure never changes a networking return value. Logs are limited to 8192 records per launch; the last record explicitly reports the limit. API durations exclude writing the entry record, while total request duration includes diagnostic overhead. Record and request boundaries are synchronized to storage on a best-effort basis; logging cannot guarantee the last in-flight record survives a system crash. No response bytes or TLS key material are logged.

## What BrowserLeaks establishes

**BrowserLeaks:** four independent connections to the documented `tls10`, `tls11`, `tls12` and `tls13.browserleaks.com` endpoints. A check requires HTTP 200 and the exact matching `TLS 1.x` body. Checks run in the order TLS 1.3, 1.2, 1.1, then 1.0, publishing each tile's result immediately.

After those four checks, a separate GET to `https://native-vita.np.ac.playstation.net/` tests PlayStation HTTPS reachability. The PlayStation servers row shows green Connected for a successful connection, or an independent failure result. Any final HTTP response from 200 through 599 counts as reachable, including 403/404: the root URL is not a public Store operation, and a service error still confirms an HTTPS connection with certificate verification enabled. The response body is not read, redirects are not followed, and no credentials, account requests or commerce operations are sent. Details and the saved report include its HTTP status, request/SSL errors and elapsed time. Reachability does not establish that Store sign-in or purchases work.

Last, a separate request to `https://tls.browserleaks.com/tls?minify=1` retrieves the selected protocol, selected cipher, key exchange, signature, JA3/JA4 and offered ciphers/groups/extensions. This optional request has its own result in the TLS REPORT section. Each check runs even if an earlier request fails. A report request or parsing failure leaves all four protocol results and PlayStation reachability intact; report availability is not a prerequisite for the other checks. Its negotiated cipher belongs to that connection; the version-only endpoints do not report their selected ciphers. Offered ALPN values are labeled as offered, not negotiated.


All requests use fresh templates/connections with keepalive disabled. Redirects and cookies are disabled and responses are not cached. Primary requests, the PlayStation check and the detailed TLS report use certificate/hostname/time/known-CA verification. Only the four protocol endpoints allow the diagnostic retry described above, using public `sceHttpsDisableOption`/`sceHttpsEnableOption`. The single HTTP worker restores verification on every retry exit and enables it before every new request. A failed restoration stops the remaining checks. No global system setting, trust store, custom certificate callback, alternate roots, explicit cipher selection, private SSL getter, or forced client protocol is used. The server endpoints impose protocol restrictions.

The UI remains responsive while a Sony kernel thread performs requests serially. Resolver/connect/send/receive timeouts are set; the UI requests abort when a request exceeds 20 seconds. Cancellation relies on `sceHttpAbortRequest` returning normally: the app does not forcibly terminate a thread executing the networking stack. Service failures do not cause plugin changes or automatic reboot.

Only the BrowserLeaks protocol/report endpoints and the PlayStation endpoint above are used. No JavaScript engine, mixed-content test, SSL 2/3 test, or vulnerability reproduction is included.

Reference: [BrowserLeaks TLS client test](https://browserleaks.com/tls) and its linked JSON endpoint.

BrowserLeaks is an external service without a versioned schema contract. A changed response produces an explicit parse failure rather than a successful capability result.

## Build and verify

This is an independent CMake project; building it does not build or package tls_fixer.

```sh
cmake -S samples/scehttp_tls_check -B build/scehttp-check-vita \
  -DCMAKE_TOOLCHAIN_FILE="$VITASDK/share/vita.toolchain.cmake" \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build/scehttp-check-vita -j4
```

Output: `build/scehttp-check-vita/vita_tls_check.vpk`. Its only package members are `eboot.bin` and `sce_sys/param.sfo`. The generated `vita_tls_check.map` records the standard Sony networking imports and absence of bundled TLS libraries.

Parser and protocol-evidence tests run on a host compiler:

```sh
cmake -S samples/scehttp_tls_check -B build/scehttp-check-host \
  -DTLS_CHECK_HOST=ON \
  -DCMAKE_C_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer'
cmake --build build/scehttp-check-host -j4
ctest --test-dir build/scehttp-check-host --output-on-failure
```

When host FreeType is available, the optional preview renderer uses the actual layout and alpha compositor with a host font, includes a visible simulated-results label, and checks framebuffer guard words. The Vita build uses only Sony's system font renderer; FreeType and font files are not bundled in the VPK. Set `TLS_CHECK_PREVIEW_FONT` to a host TrueType font path on systems without the macOS Arial default. Its synthetic results are not Vita execution evidence. `check_tests` also accepts a captured BrowserLeaks JSON path to validate current external response formats.
