# tls_fixer 0.2.3

TLS 1.2 and TLS 1.3 for the PS Vita browser and supported applications using Sony's `sceHttp` APIs. By **devnoname120**.

tls_fixer provides modern TLS transport using Mbed TLS 4.2.0 and TF-PSA-Crypto 1.2.0, alongside an authoritative Sony + curl/Mozilla certificate bundle. Sony's HTTP implementation continues to handle URLs, redirects, authentication, cookies and request processing.

**[Download the latest release](https://github.com/devnoname120/vita_tls_fixer/releases/latest)**

## Installation

A hacked PS Vita with working taiHEN is required.

**iTLS and vitals are incompatible with tls_fixer.** Installing or refreshing any option, including Browser-only, System-only and Certificates-only, automatically removes their taiHEN entries, kernel plugins, redirected modules and vitals settings. Entries are removed from both `ur0:tai/config.txt` and `ux0:tai/config.txt`, including relocated plugins with their standard filenames. The original Sony certificate backup is preserved; certificate updates follow the selected option. Installer application bubbles are not runtime plugins and may remain installed.

1. Install `tls_fixer.vpk` through VitaShell, then open **tls_fixer**.
2. Select the components to install:
   - **Full:** browser plugin, system plugin and certificates. Recommended for a new installation.
   - **Browser plugin only**
   - **System plugin only**
   - **Certificates only**
3. Press **Cross** to install the selected option. If it is already installed, Cross removes it instead; **Square** reinstalls or refreshes the selected option.
4. After a successful operation, the installer reboots the Vita automatically.

Browser and system installations include the shared kernel coordinator. Removing one provider preserves the coordinator while the other remains installed. Certificate-only installation does not enable a plugin. The installer keeps the original system files for uninstall and leaves unselected components unchanged.

The release uses **persistent activation**: it stays enabled across reboots until uninstalled or disabled. Provider file/console logging, runtime UDP diagnostics and kernel trace/probe modes are disabled in the release build. The installer still displays its progress and errors on screen.

The installer displays version `0.2.3`; the VPK's two-part metadata version is `00.23`. Both identify release **0.2.3**.

## Coverage

- **Browser:** a dedicated provider replaces the TLS transport in the bundled `ScePsp2Compat`/libcurl backend. HTTP processing remains with libcurl; ALPN advertises HTTP/1.1.
- **System HTTP:** Mbed TLS is embedded in a replacement copy of Sony's `SceLibHttp`. Applications continue to call the ordinary Sony `sceHttp`/`sceHttps` APIs, with Sony handling HTTP processing and the normal module lifecycle.
- **Certificates:** Sony roots are combined with curl/Mozilla roots while preserving the original Sony file's byte layout, which native certificate selectors require.
- **PSN sign-in:** the system component includes a small Shell/Store hostname redirect helper. It sends `native.np.ac.playstation.net` requests to `native-vita.np.ac.playstation.net`, without requiring a separate reAuth installation.

The modern providers support TLS 1.2/1.3. TLS 1.0/1.1 are intentionally excluded from their configuration. This is not a universal replacement for every `SceSsl` consumer. Unsupported transport settings, client-certificate authentication, unsupported modules and provider initialization or validation failures can retain Sony's native transport. There is no second handshake fallback after Mbed TLS has sent handshake bytes.

The coordinator redirects module loads to separately installed copies, leaving the stock system-module `.suprx` files intact. The system HTTP backend loads with Sony's normal sharing flags and contains its TLS implementation in the same module, rather than injecting a second HTTP provider afterward. Browser, PSN and Store helpers remain separate. Kernel code is checked for unmanaged floating-point/SIMD instructions; the HTTP runtime uses native Vita allocation and synchronization APIs without importing SceLibc.

The system component recognizes HTTP and SSL paths redirected by reAuth or older TLS plugins. Sony's SSL module continues to supply its native certificate APIs and fallback transport. Mbed TLS and native SSL share the fixed memory pool reserved by the application's `sceSslInit(poolSize)` call.

The Store helper fills missing cover URLs using Sony's catalog artwork. It applies only to PlayStation Store and preserves existing cover URLs.

Firmware profiles cover the available **3.60–3.74 retail, testkit and devkit** images. Static checks passed for 31 supplied combinations; five kit images were unavailable. Physical-device validation is on **retail 3.60**. See the [firmware evidence matrix](docs/tls13-firmware-support.md) for the exact coverage; static checks do not establish hardware execution on every model/firmware combination.

## Memory and application compatibility

- The augmented HTTP provider uses the application's existing Sony SSL pool, without a second TLS heap reservation.
- Both providers keep a small index of the system CA bundle. Certificates are parsed one at a time to build that index, then released; matching roots are read and parsed during verification.
- Applications can load PEM or DER CA certificates with `sceHttpsLoadCert` while continuing to use modern TLS. Their CAs supplement the system roots. Repeated loads add CAs; `sceHttpsUnloadCert` removes that additional trust. Client certificate/private-key authentication still uses Sony's implementation.
- The system installer replaces the previous 3.60 hostname helper with the integrated Shell/Store redirect helper.

### Host redirects

Edit `ux0:data/tls_fixer/redirects.txt`, with one source and destination hostname per line:

```text
old.example.com community.example.com
```

Matching is exact and case-insensitive. `#` starts a comment. The destination replaces the hostname for connection and URL-based request creation, including the name used for certificate verification and SNI. Scheme, port, path and query are preserved. Invalid lines are ignored; up to 32 rules are loaded, with a 64 KiB read limit. Restart the application after editing. Reinstallation preserves this file, and uninstall leaves it available for later use.

The kernel reads the list for sandboxed games. The Shell/Store helper also reads it and supplies the PSN sign-in mapping by default; an explicit rule for that host overrides the default. Browser URL rewriting is not part of this feature.

## Certificates

Full and certificates-only installation attempt to fetch the latest [curl/Mozilla CA bundle](https://curl.se/ca/cacert.pem). The download uses libcurl with certificate and hostname validation against **only the embedded Mozilla bundle**. If the network, download or bundle validation fails, installation falls back to the Mozilla snapshot embedded in the VPK.

The selected Mozilla bundle is merged with the embedded Sony bundle. The complete original Sony PEM prefix, including its comments and line endings, is preserved; only additional certificate identities are appended. This preserves the fixed offsets and hashes used by native Sony services.

The existing system trust store is **not imported**. The embedded Sony roots and selected Mozilla bundle are authoritative. The old system certificate file is retained only for uninstall. Missing or invalid embedded inputs stop certificate installation.

Packaged fallback:

- Sony firmware 3.74 bundle: **69 certificates**.
- curl/Mozilla snapshot dated 2026-09-25: **121 certificates**.
- Combined bundle: **176 unique certificates**.

The separate Sony, Mozilla and combined files are included in the VPK, with provenance and hashes in `certificate-sources.json`. There is no separate certificate-download menu option; use Full or certificates-only refresh.

## Validation

Release qualification on retail 3.60 confirmed Browser TLS 1.3 with the Cloudflare control, certificate-verified system HTTP TLS 1.2/1.3 requests, and the BrowserLeaks detailed report. PlayStation HTTPS connectivity and normal Store sign-in have also been confirmed after the native certificate-layout repair. Store sign-in still requires the account linked to the console and a PlayStation Device Setup Password; legacy account-management operations are separate server features.

Version 0.2.2 was checked on retail firmware 3.60 with Browser's refreshed Cloudflare TLS 1.3 page, verified TLS 1.2/1.3 requests and the BrowserLeaks report, PlayStation HTTPS connectivity, and Store artwork for 10 Second Ninja X, Blind Men and Brotherhood United. Earlier compatibility tests reached the PSP menu in Adrenaline 7 and game/dialog checks in HELLDIVERS, MotorStorm RC and Need for Speed Most Wanted. These observations do not establish compatibility with every game, Adrenaline version or endpoint.

Version 0.2.3 changes the installer and package version; its runtime modules are unchanged from 0.2.2. Installer tests cover both taiHEN configs, duplicate and relocated entries, cleanup retries, failed reads/writes/synchronization/removal, and preservation of unrelated configuration and Sony's certificate backup. The new migration has not been exercised on physical hardware.

The shared-pool implementation passed 385 AddressSanitizer/UndefinedBehaviorSanitizer host tests, native builds and import checks, and static compatibility checks against 31 available firmware/hardware combinations. The modern HTTP payload is checked to reject memory-block allocation/free and heap creation/destruction imports. Pool tests cover exhaustion, failed-reallocation data preservation, concurrent users, initialization order, cleanup and reuse. Five kit firmware images were unavailable; physical validation remains retail 3.60.

Host tests cover transport handshakes, certificate and hostname checks, callbacks, nonblocking retries, cancellation, module guards, hook lifetimes, certificate merging and installer options. Native builds enforce the normal kernel/provider configuration even if a diagnostic build was previously cached.

The independent [Vita TLS Check sample](samples/scehttp_tls_check/README.md) uses Sony networking APIs without linking another TLS implementation. It can compare the stock stack and installed providers, including protocol results, certificate errors, negotiated cipher information and PlayStation connectivity. It is a separate diagnostic application and is not installed by `tls_fixer.vpk`.

## Building

Use a compatible hard-float VitaSDK toolchain. Fetch the pinned source archives on the host, then build the release package:

```sh
python3 tools/fetch_mbedtls.py
python3 tools/fetch_curl.py
docker run --rm -v "$PWD":/src -w /src vitasdk/vitasdk:latest \
  sh -lc 'make augmented-http-release-vpk'
```

Output: `build/augmented-release/tls_fixer-augmented-release.vpk`. It contains the Full/Browser/System/Certificates installer, the embedded HTTP backend and persistent coordinator. Runtime logging, diagnostic probes and startup self-disarming are disabled. Building it does not install or activate anything on a device.

Source archives are checksum-verified and cached under ignored `build/deps/`. The embedded HTTP backend uses pinned Mbed TLS 4.2.0 with the client compatibility and receive-buffer patches under `tls13/crypto/patches/`, configuration headers and a native Vita platform adapter. The installer uses source-built libcurl with VitaSDK OpenSSL and native lock wrappers. See [Third-Party Notices](THIRD_PARTY_NOTICES.md) for dependencies and licenses.

The system component installs replacement copies under `vs0:/data/external/tls_fixer/native/` and its coordinator at `ur0:tai/tls_fixer.skprx`. Individual receive buffers start at 4 KiB and grow within Sony's reserved SSL pool; incoming plaintext records retain the 16 KiB limit and outgoing buffers are 2 KiB. Connection tracking also grows within that budget, without a separate fixed connection count. Pool exhaustion returns an allocation failure. Sony retains ownership of the pool through `sceSslInit` and `sceSslTerm`.

`make augmented-http` builds only the replacement HTTP module at `build/augmented-http/augmented/libhttp.suprx`. Legacy provider targets and the separate self-disarming diagnostic package remain available for development. The ordinary `make` target builds that older provider architecture; use the explicit release target above for the current release.

The independent tester can be built using the [Vita TLS Check instructions](samples/scehttp_tls_check/README.md).

Host verification:

```sh
python3 -m unittest discover -s tools/tests
docker run --rm -v "$PWD":/src -w /src vitasdk/vitasdk:latest sh -c '
  cmake -S tls13 -B build/tls13-transport-san \
    -DTLS_FIXER_BUILD_HOST_TESTS=ON -DTLS_FIXER_BUILD_TRANSPORT_TESTS=ON \
    -DTLS_FIXER_RESTORE_RSA_CLIENT=ON -DTLS_FIXER_SMALL_RX_BUFFER=ON \
    -DTLS_FIXER_ENABLE_SANITIZERS=ON -DCMAKE_BUILD_TYPE=Debug &&
  cmake --build build/tls13-transport-san -j4 &&
  ASAN_OPTIONS=detect_leaks=1 ctest --test-dir build/tls13-transport-san --output-on-failure'
```

The Linux firmware audit checks function and variable imports together with compiled loader/WebKit guards. Missing corpus images are reported separately:

```sh
python3 tools/firmware_matrix.py --firmware-root /path/to/decrypted/external \
  --http-module build/augmented-http/augmented/libhttp.suprx \
  --coordinator build/augmented-release/kernel/tls_fixer.skprx \
  --output build/augmented-http-firmware.json
```

This is static compatibility evidence, not execution on every firmware or hardware model. Diagnostic builds must use the existing separately staged, self-disarming test procedure; they are not the persistent release package.

## Credits and third-party software

**Thanks to SKGleba for the initial [iTLS plugin](https://github.com/SKGleba/iTLS-Enso)!** His work updating the Vita's certificates has been very useful and is integrated into tls_fixer, together with the original installer and module-redirection foundations. Existing author notices are preserved in the source.

Additional thanks to Reiko Asakura for reAuth, Team Molecule, the HenKaku Discord testers, Cuevavirus for the 3.60 NP hostname fix, CreepNT for the `vshIoMount` fix, and olokos for the external CA bundle.

See [Third-Party Notices](THIRD_PARTY_NOTICES.md) and [licenses](licenses/) for component versions, source archives and license texts. The required third-party notices and licenses are included in the VPK.
