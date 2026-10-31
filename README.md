# tls_fixer 0.2.1

TLS 1.2 and TLS 1.3 for the PS Vita browser and supported applications using Sony's `sceHttp` APIs. By **devnoname120**.

tls_fixer provides modern TLS transport using Mbed TLS 4.2.0 and TF-PSA-Crypto 1.2.0, alongside an authoritative Sony + curl/Mozilla certificate bundle. Sony's HTTP implementation continues to handle URLs, redirects, authentication, cookies and request processing.

**[Download the latest release](https://github.com/devnoname120/vita_tls_fixer/releases/latest)**

## Installation

A hacked PS Vita with working taiHEN is required.

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

The installer displays version `0.2.1`; the VPK's two-part metadata version is `00.21`. Both identify release **0.2.1**.

## Coverage

- **Browser:** a dedicated provider replaces the TLS transport in the bundled `ScePsp2Compat`/libcurl backend. HTTP processing remains with libcurl; ALPN advertises HTTP/1.1.
- **System HTTP:** a separate provider replaces the TLS transport inside the bundled `SceLibHttp` for compatible processes with private mappings. Applications continue to call the ordinary Sony `sceHttp`/`sceHttps` APIs.
- **Certificates:** Sony roots are combined with curl/Mozilla roots while preserving the original Sony file's byte layout, which native certificate selectors require.
- **PSN sign-in:** the system component includes a small Shell/Store hostname redirect helper. It sends `native.np.ac.playstation.net` requests to `native-vita.np.ac.playstation.net`, without requiring a separate reAuth installation.

The new providers support TLS 1.2/1.3. TLS 1.0/1.1 are intentionally excluded from their configuration. This is not a universal replacement for every `SceSsl` consumer: Shell/Paf shared consumers, the native PSP emulator, client-certificate configurations, unreadable app CA material, unsupported modules and other unsupported transport settings can retain Sony's native implementation. The PSP emulator keeps Sony's HTTP transport to preserve Adrenaline startup compatibility; its separate firmware downloader remains eligible for the modern provider. Provider initialization or validation failure also retains the original path. There is no second handshake implementation fallback after the provider has sent TLS handshake bytes.

The coordinator validates module identities, signatures and mappings before injecting providers. Browser processes use their dedicated provider and are excluded from generic HTTP injection. Kernel code is checked for unmanaged floating-point/SIMD instructions; user providers use a small native Vita runtime and process-private transport state.

Sony PSN networking libraries that load later are kept with the application's HTTP instance, including their static callers. This avoids mixing shared PSN imports with a private HTTP transport. Processes using Sony's shared HTTP instance retain their normal loading mode.

Version 0.2.1 also recognizes HTTP and SSL library paths redirected by reAuth or older TLS plugins. This fixes applications retaining the old TLS stack and TLS Check reporting `tls_fix: not enabled` despite the kernel plugin being installed.

Firmware profiles cover the available **3.60–3.74 retail, testkit and devkit** images. Static checks passed for 31 supplied combinations; five kit images were unavailable. Physical-device validation is on **retail 3.60**. See the [firmware evidence matrix](docs/tls13-firmware-support.md) for the exact coverage; static checks do not establish hardware execution on every model/firmware combination.

## Memory and application compatibility

- The HTTP provider reserves **128 KiB** of heap per injected process, down from 2 MiB.
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

The 0.2.1 loading fix was confirmed by two affected users. One supplied logs showing the provider running and certificate-verified TLS 1.2/1.3 connections. An additional isolated retail 3.60 test of the candidate kernel and HTTP provider passed the same checks through the normal library-loading path. Automated checks passed 367 sanitizer-enabled C/C++ tests and 129 Python tests, alongside native builds, kernel instruction checks and import checks against the available firmware images. These checks do not establish hardware testing on every supported firmware/model combination.

Host tests cover transport handshakes, certificate and hostname checks, callbacks, nonblocking retries, cancellation, module guards, hook lifetimes, certificate merging and installer options. Native builds enforce the normal kernel/provider configuration even if a diagnostic build was previously cached.

The independent [Vita TLS Check sample](samples/scehttp_tls_check/README.md) uses Sony networking APIs without linking another TLS implementation. It can compare the stock stack and installed providers, including protocol results, certificate errors, negotiated cipher information and PlayStation connectivity. It is a separate diagnostic application and is not installed by `tls_fixer.vpk`.

## Building

Use a compatible hard-float VitaSDK toolchain. Fetch the pinned source archives on the host, then build:

```sh
python3 tools/fetch_mbedtls.py
python3 tools/fetch_curl.py
docker run --rm -v "$PWD":/src -w /src vitasdk/vitasdk:latest \
  sh -lc 'make clean && make'
```

Output: `tls_fixer.vpk`. The archives are SHA-256 verified and cached under ignored `build/deps/`. The normal provider build uses unmodified upstream TLS sources with the project's configuration headers and native platform adapter. The installer uses source-built libcurl with VitaSDK OpenSSL and native lock wrappers.

The experimental augmented Sony HTTP module has a separate build target:

```sh
make augmented-http
```

It produces `build/augmented-http/augmented/libhttp.suprx`, with the intermediate ELF and input report beside it. This target uses the embedded backend's compatibility profile, generates its optional kernel import, and keeps diagnostic recording disabled. Mbed TLS source filenames are normalized so different build directories produce the same module with the same toolchain. The normal VPK build remains separate; device activation uses the existing self-disarming test procedure.

Before publishing the build output, the runtime import audit rejects SceLibc, additional libraries outside the native dependency set and the TLS runtime allowlist, and a redirect-reader import that is no longer optional.

`make augmented-http-test` also builds `build/augmented-http-kernel/tls_fixer.skprx` for a system test. This kernel uses `ux0:/data/tls_fixer-runtime-augmented/libhttp.suprx`, keeps normal shared/private loading, and disables separate HTTP-provider injection and private GUI routing. Diagnostic recording is off. Its startup synchronizes the disabling of its own boot entries before installing hooks; a fault before that completes remains outside this safeguard. The command only builds the pair and does not install or activate it.

The opt-in installer package is built with:

```sh
make augmented-http-vpk
```

Output: `build/augmented-package/tls_fixer-augmented-test.vpk`. It builds in an isolated source snapshot, preserving the normal build outputs. This experimental package offers System installation/removal and Exit. Its backend is fixed at compile time, with no backend selector. The normal installer retains its Full/Browser/System/Certificates menu during migration.

The test stages HTTP, paired Sony SSL, PSN and Store modules under `ux0:/data/tls_fixer-runtime-installer/`, and the kernel at `ux0:/data/tls_fixer-one-shot/tls_fixer.skprx`. It preserves the normal plugin files and certificates. Configuration changes keep the existing file in place, disable tls_fixer entries before payload updates, and activate the prepared test with a verified one-byte edit. A missing entry is first appended as comments, then its section and path are enabled in order. The app asks for a restart instead of restarting automatically. The kernel disables its own boot entries before hooks, so activation lasts one boot; a fault before startup disarming completes remains outside that safeguard. Diagnostic recording is off.

The installer executable and packaged payloads have passed native System install, refresh, one-boot TLS 1.2/1.3 and uninstall checks on the retail 3.60 device. The actual executable/assets were run through the existing diagnostic application slot; VPK container promotion was checked offline. This is a System-only test package, not the normal release installer.

To build the augmented backend in release mode with persistent activation:

```sh
make augmented-http-release-vpk
```

Output: `build/augmented-release/tls_fixer-augmented-release.vpk`. This package restores Full, Browser only, System only and Certificates only. The system component installs the augmented HTTP module and paired Sony SSL under `vs0:/data/external/tls_fixer/native/`; the coordinator uses `ur0:tai/tls_fixer.skprx`. Logging, diagnostic probes and startup self-disarming are disabled. There is no backend selector. Building this package does not install or activate it on a device.

The augmented HTTP backend starts with a 128 KiB TLS heap. When concurrent requests need more memory, it adds pools on demand, up to 512 KiB total, and releases empty extra pools. Its outgoing TLS buffer is 2 KiB; incoming records retain the standard 16 KiB limit. This avoids reserving the maximum in every application while allowing busy clients such as PlayStation Store to complete their handshakes.

Host verification:

```sh
python3 -m unittest discover -s tools/tests
docker run --rm -v "$PWD":/src -w /src vitasdk/vitasdk:latest sh -c '
  cmake -S tls13 -B build/tls13-transport-san \
    -DTLS_FIXER_BUILD_HOST_TESTS=ON -DTLS_FIXER_BUILD_TRANSPORT_TESTS=ON \
    -DTLS_FIXER_ENABLE_SANITIZERS=ON -DCMAKE_BUILD_TYPE=Debug &&
  cmake --build build/tls13-transport-san -j4 &&
  ASAN_OPTIONS=detect_leaks=1 ctest --test-dir build/tls13-transport-san --output-on-failure'
```

Diagnostic source/build options remain available for development; they are not enabled in the normal VPK.

The Linux firmware audit can check the augmented pair against a decrypted firmware corpus:

```sh
python3 tools/firmware_matrix.py --firmware-root /path/to/decrypted/external \
  --http-module build/augmented-http/augmented/libhttp.suprx \
  --coordinator build/augmented-http-kernel/tls_fixer.skprx \
  --plugin-elf build/augmented-http-kernel/tls_fixer.elf \
  --plugin-elf build/augmented-http/tls_fixer_http_embedded \
  --output build/augmented-http-firmware.json
```

It checks function and variable imports against the firmware and paired replacement modules, together with the compiled loader/WebKit guards. Missing corpus images are reported separately. This is offline compatibility evidence, not execution on every firmware or hardware model.

## Credits and third-party software

**Thanks to SKGleba for the initial [iTLS plugin](https://github.com/SKGleba/iTLS-Enso)!** His work updating the Vita's certificates has been very useful and is integrated into tls_fixer, together with the original installer and module-redirection foundations. Existing author notices are preserved in the source.

Additional thanks to Reiko Asakura for reAuth, Team Molecule, the HenKaku Discord testers, Cuevavirus for the 3.60 NP hostname fix, CreepNT for the `vshIoMount` fix, and olokos for the external CA bundle.

See [Third-Party Notices](THIRD_PARTY_NOTICES.md) and [licenses](licenses/) for component versions, source archives and license texts. The required third-party notices and licenses are included in the VPK.
