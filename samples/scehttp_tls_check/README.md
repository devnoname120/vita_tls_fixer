# Vita TLS Check

A standalone 960 x 544 homebrew application that exercises the Vita's public `sceHttp` / `sceHttps` APIs. It does not link curl, OpenSSL, Mbed TLS, a plugin SDK, or another HTTP/TLS implementation. The same VPK can be run with the stock networking stack or with a system plugin: it observes whichever implementation serves the ordinary Sony calls.

The earlier `tls13/probe` application directly uses a TLS library and tests a different boundary. This sample does not share its transport, CA loader, or provider code.

## Use

Install `vita_tls_check.vpk` through VitaShell, then open **Vita TLS Check** (`TLSCK0001`). It starts the BrowserLeaks checks automatically. No kernel/plugin installation, boot configuration, certificate-store modification, or reboot is performed by this application.

- **L / R:** switch BrowserLeaks and SSL Labs. A service runs once when first selected.
- **Cross:** repeat the selected service after the current run finishes.
- **Up / Down:** scroll offered cipher suites.
- **Square:** cycle offered ciphers, request errors, and handshake details.
- **Triangle:** cancel the running sequence.
- **Circle:** cancel if necessary, then exit after the worker returns.

A green check means a request completed with the expected response. A red cross means that request failed; it does **not** identify unsupported TLS by itself. DNS, routing, timeouts, certificate rejection, HTTP errors and unexpected payloads remain visible. Legacy TLS support is not marked as a security recommendation.

The interface uses antialiased Latin system fonts through Sony's `ScePvf` API. There is one display buffer, no page flipping, and a separate CPU drawing surface. Complete frames are copied at vblank only when the data or selected view changes; idle frames are never cleared or repainted.

Results are written to `ux0:/data/vita-tls-check/`, one small text file per run. A separate bounded `startup.txt` records initialization results for the most recent launch. Reports include endpoint, request result, HTTPS error/detail, HTTP status, elapsed time, negotiated details and the server-observed offered lists. Request results preserve Sony API errors; checker-local HTTP/payload validation failures use -1 with an explicit message. They do not contain response bodies, application traffic, TLS keys, or cookies. Lists are bounded to 64 entries each; responses are limited to 96 KiB.

Each launch also creates `api-<PID>-<monotonic-time>.log` in that folder. It records process/thread IDs, sequential record numbers, run/request IDs, API entry and return, native result, time spent in the call, SSL error/detail, bytes read, cancellation and cleanup. Module inventories before and after HTTPS loading/initialization and requests include module names, UIDs, state, segment sizes and source paths. This is a generic inventory; the checker neither loads nor searches for a specific TLS provider. It helps distinguish an inactive provider from a failing handshake without changing certificate verification or request policy.

Diagnostic writes are serialized on their own native mutex. Short writes are completed, an I/O failure disables the sink, and logging failure never changes a networking return value. Logs are limited to 8192 records per launch; the last record explicitly reports the limit. API durations exclude writing the entry record, while total request duration includes diagnostic overhead. Record and request boundaries are synchronized to storage on a best-effort basis; logging cannot guarantee the last in-flight record survives a system crash. No response bytes or TLS key material are logged.

## What each service establishes

**BrowserLeaks:** four independent connections to the documented `tls10`, `tls11`, `tls12` and `tls13.browserleaks.com` endpoints. A check requires HTTP 200 and the exact matching `TLS 1.x` body. A separate request to `https://tls.browserleaks.com/tls?minify=1` reports the selected protocol, selected cipher, key exchange, signature, JA3/JA4 and offered ciphers/groups/extensions. Its negotiated cipher belongs to that connection; the version-only endpoints do not report their selected ciphers. Offered ALPN values are labeled as offered, not negotiated.

**SSL Labs:** TLS 1.0, 1.1 and 1.2 requests use the service's version-specific ports 10301, 10302 and 10303. Success requires HTTP 200 and the expected 1 x 1 PNG header. The main client page supplies the offered cipher list. The checker calls its canonical `https://clienttest.ssllabs.com:8443/ssltest/viewMyClient.html` endpoint directly; the public `www` page redirects there. That list is not a per-cipher handshake sweep and does not reveal the selected cipher. TLS 1.3 is shown as an advertisement / not tested on this tab; use the independent BrowserLeaks TLS 1.3 connection test. Port filtering can make the SSL Labs checks fail while normal HTTPS works.

All requests use fresh templates/connections with keepalive disabled. Redirects are disabled, responses are not cached, and certificate/hostname/time/known-CA verification stays enabled. No custom certificate callback, alternate roots, weakened verification, explicit cipher selection, private SSL getter, or forced client protocol is used. The server endpoints impose protocol restrictions. The app therefore measures ordinary `sceHttp` behavior and its configured trust store.

The UI remains responsive while a Sony kernel thread performs requests serially. Resolver/connect/send/receive timeouts are set; the UI requests abort when a request exceeds 20 seconds. Cancellation relies on `sceHttpAbortRequest` returning normally: the app does not forcibly terminate a thread executing the networking stack. Service failures do not cause plugin changes or automatic reboot.

Only the protocol and handshake-report functions of the reference sites are used. No JavaScript engine, mixed-content test, SSL 2/3 test, or vulnerability reproduction is included.

Service references, inspected on 2026-10-13:

- [BrowserLeaks TLS client test](https://browserleaks.com/tls) and its linked JSON endpoint.
- [SSL Labs client test](https://www.ssllabs.com/ssltest/viewMyClient.html) and its page-provided protocol endpoints.

These are external services without a versioned schema contract. A changed response produces an explicit parse failure rather than a successful capability result.

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

When host FreeType is available, the optional preview renderer uses the actual layout and alpha compositor with a host font, includes a visible simulated-results label, and checks framebuffer guard words. The Vita build uses only Sony's system font renderer; FreeType and font files are not bundled in the VPK. Set `TLS_CHECK_PREVIEW_FONT` to a host TrueType font path on systems without the macOS Arial default. Its synthetic results are not Vita execution evidence. `check_tests` also accepts captured BrowserLeaks JSON and SSL Labs HTML paths to validate current external response formats.
