# tls_fixer

tls_fixer updates the PlayStation Vita HTTPS stack on systems using enso. This development build adds separate TLS 1.2/1.3 providers for applications using Sony's `SceHttp` and for the browser's libcurl backend in the exact bundled `ScePsp2Compat` module. Both use source-built Mbed TLS 4.2.0 and TF-PSA-Crypto 1.2.0.

**Current test status (2026-10-14):** the normal combined coordinator, with HTTP and DNS enabled and kernel diagnostics disabled, passed the Cloudflare Browser TLS 1.3 test on retail 3.60. The independent Sony-API checker then passed strict TLS 1.2 and TLS 1.3 requests in three separate processes, including two normal exits/relaunches. The HTTP provider uses a small SceLibKernel/SceSysmem runtime and private transport mappings. The exact rebuilt VPK kernel and providers passed the same Browser control and nine successful modern requests across three fresh checker processes, including two normal exits/relaunches. See `TLS13_PROGRESS.md` sections 23.329–23.331.

**Earlier test packages are withdrawn.** Earlier broad activation failed while Sony shared consumers linked private HTTP exports; scoped tests also exposed stale hooks in shared mappings. The coordinator now preserves Sony transport for shared or unclassified consumers, including Shell/Paf, and verifies private mappings before publishing application hooks. The original historical boot fault is not established as having a single cause. Only retail 3.60 has physical-device execution evidence; other firmware/hardware profiles remain offline checks. This is a one-shot development build.
The experimental kernel now disables its own taiHEN boot entries before other initialization. It does not re-enable them automatically. This is a single-use test safeguard, not permanent production activation or restoration of previously overwritten files.

## Installation

The installer procedure is retained for development. It writes persistent system files and is not the isolated one-shot procedure used for the successful Browser test. Do not install withdrawn packages or infer approval for permanent activation from the recorded result.

1. Install the VPK.
2. Run the application. Press **SQUARE** to install or refresh the full package, including an existing installation. This updates the kernel loader and both TLS providers while retaining the original CA backup.
3. Reboot after the installer reports success.

The normal CROSS menu toggles the selected component. Browser installation deploys both `ScePsp2Compat.suprx` and `tls_fixer.suprx`; it requires the current kernel plugin and a usable CA bundle. Refreshing the full package avoids leaving an old loader installed. The CA-only option does not install the redirection plugin.

The rebuilt package installs its HTTP provider at `vs0:/data/external/tls_fixer/native/tls_fixer_http.suprx` and Browser provider at `ur0:tai/tls_fixer-native/tls_fixer.suprx`, with a mirror at `vs0:/data/external/tls_fixer/native/tls_fixer.suprx`. Previous provider copies remain available during qualification.

The packaged installer has been verified to open its menu on the qualified retail 3.60 boot. This check did not run a full system-file installation or prove its interruption safety. The bubble is only an installer and uninstaller and may be removed after a successful installation.

## TLS 1.3 architecture

The Vita `libssl.suprx` is a Sony-adapted RSA BSAFE Micro Edition Suite 3.2.1 implementation. The firmware 3.73 binary adds Vita-specific TLS 1.2 support but cannot be incrementally configured for TLS 1.3.

The application provider, `tls_fixer_http.suprx`, replaces only the internal TLS transport used by the exact bundled `libhttp.suprx`:

```text
application using SceHttp
        |
        v
Sony libhttp HTTP state machine
        |
        | six validated internal hooks
        v
tls_fixer_http.suprx
        |
        v
Mbed TLS 4.2.0 / TF-PSA-Crypto 1.2.0
        |
        v
SceNet socket
```

Sony's URL handling, redirects, authentication, cookies, proxy logic, gzip handling, request state machine, and public `SceHttp` ABI remain in use. The original `libssl` remains loaded for imports and for connections that use the compatibility fallback.

The browser provider, `tls_fixer.suprx`, has a different boundary:

```text
WebKit -> bundled ScePsp2Compat/libcurl -> browser TLS backend
       -> Mbed TLS 4.2.0 -> SceNet socket
```

It hooks the complete connection driver, pending-data check, keep-alive health check and close operation, then installs TLS send/receive callbacks in libcurl's existing slots. OpenSSL objects are not impersonated. A one-byte lookahead preserves the old non-consuming health-check behavior. Libcurl still owns HTTP processing, redirects, sockets and request deadlines. Only HTTP/1.1 is advertised through ALPN; HTTP/2 is not advertised to the old HTTP engine.

Activation is intentionally narrow:

- the kernel plugin hashes each installed replacement module and injects only its matching provider;
- generic HTTP injection excludes the Browser controller (`NPXS10003`) and WebKit helper (`NPXS10083`) before allocating its preparation stack; page TLS uses the dedicated Browser provider;
- Browser and HTTP injection wait until native module start/import linking returns successfully; the normal kernel build requires this ordering and rejects early injection;
- normal provider preparation uses the native 16 KiB stack and target/provider name lookup; every VPK build reconfigures the normal kernel profile, even when a newer diagnostic artifact is cached;
- the HTTP provider uses a process-private 2 MiB heap, native mutex and a small SceLibKernel/SceSysmem C runtime shim; it imports neither SceLibc nor Paf and does not patch dependency sources;
- shared or unclassified HTTP/SSL importers retain Sony transport; eligible application transports load privately, and the provider validates complete private text/data allocations before heap setup or hooks;
- the Browser provider is installed at `ur0:tai/tls_fixer-native/tls_fixer.suprx` and loaded globally into its target process; the compatibility checksum still uses the Browser's private mount;
- the provider validates the mapped executable/data segment dimensions and masked bytes at every hook site;
- browser connect interception is installed last and TLS ownership is enabled only after the complete hook set succeeds; on an earlier partially published hook failure, inert forwarding hooks stay resident rather than unloading code another thread might execute;
- unknown or mismatched modules stay on their original TLS backend; active user providers and the kernel loader reject hot unload and remain until process exit or reboot.

The kernel translates its internal module GUID to the target process's PUID before passing start arguments. Browser module and CA paths preserve the existing browser mount namespace rather than assuming the process can open an absolute `vs0:` path.

## Compatibility policy

Firmware profiles cover the 31 retail/testkit/devkit combinations available in the supplied external 3.60-3.74 corpus. Compiled kernel/WebKit guards and linked firmware imports pass against those images. Five kit images are unavailable; only the retail 3.60 profile has been exercised on hardware. See [the firmware matrix](docs/tls13-firmware-support.md) for precise coverage and evidence limits. Loaded module identities select profiles, independently of version spoofing.

The current provider supports client-side TLS 1.2 and TLS 1.3 through the bundled `libhttp` HTTPS path. TLS 1.0/1.1 checker requests currently fail after the provider starts; there is no legacy support claim or fresh-socket retry through Sony after a provider handshake fails. It is not a general TLS 1.3 replacement for every Vita `SceSsl` consumer.

The adapter implements Sony's recovered retry/error conventions, hostname verification, and application certificate callbacks. Nonnegative callback results do not automatically permit an invalid certificate: the original post-callback process/version/system-parameter policy is also applied using the gated module's existing imports. Its behavior is covered by host tests; execution of those imports and hooks still requires Vita validation.

Borrowed callback certificate handles expire when the callback returns. Subject/issuer name results have independent storage and remain valid until `sceSslFreeSslCertName`. All eight public certificate inspection hooks are exercised by native loopback tests. The provider remains resident until process exit; hot unloading is rejected because an empty connection registry alone does not prove that no thread is executing hook code.

The following cases retain Sony's transport; the negotiated version depends on that transport and endpoint:

- applications that install custom CA certificates with `sceHttpsLoadCert`;
- applications that install a client certificate/private key;
- Shell and applications with shared or unclassified HTTP/SSL importers, including ScePaf consumers;
- other consumers that bypass both supported transport boundaries;
- unsupported or modified `libhttp` binaries;
- provider initialization, trust-store parsing, module validation, or hook-installation failure.

There is no fallback to a second TLS implementation after provider handshake bytes have been sent on a socket.

The browser adapter supports its recovered default configuration, peer and hostname verification, PEM CA files, TLS 1.2/1.3, nonblocking operation and both libcurl socket slots. The exact built-in `SceWebKit` SSL-context callback is recognized only for the normal clean-chain path with peer and hostname verification enabled and no custom CA; successful Mbed TLS verification supplies the security decision without invoking Sony's OpenSSL callback. Arbitrary callbacks, altered verification policy, client certificates/keys, CA directories, CRLs, issuer restrictions, certificate-info requests, explicit legacy protocol selection or unsupported cipher expressions deliberately remain on embedded OpenSSL **before** any provider handshake. It does not silently ignore these settings, emulate Sony callback objects or synthesize acceptance after a certificate failure. TLS 1.2 cipher support is restricted to the supported ECDHE/AES-GCM suites; obsolete RC4/3DES entries in the old browser default list are not enabled. Cross-connection session resumption and TLS 1.3 early data are not implemented.

Browser diagnostics go to `sceClibPrintf` and first try `ux0:/data/tls_fixer-browser-<PID>.log`. If that mount is not writable in the WebKit process, they fall back to `savedata0:/temp/tls_fixer-browser-<PID>.log`. At most 512 records of less than 512 bytes are emitted per provider lifetime. Failed file logging does not change TLS results. Logs contain activation/error codes, scalar compatibility-rejection reasons, socket identifiers, protocol and cipher, not callback addresses, application payloads, keys or URLs. Restart the browser to start a new diagnostic budget.

## Validation status

Validation is separated into native execution, cross-compilation, and device execution. Native tests compile the production TLS transport, certificate hooks, and crypto platform port against Mbed TLS 4.2.0, with test implementations of Vita/taiHEN services. They cover:

- exact hash/ELF/segment/signature validation for the bundled `libhttp` and `ScePsp2Compat`;
- TLS 1.2 and TLS 1.3 loopback handshakes, SNI, certificate rejection/authorized override, IP identities, nonblocking retries, ticket handling, abrupt EOF, callback reentry and stable write retries;
- all eight certificate inspection functions, retained names, stale handles and hook-installation rollback;
- the actual bundled CA file, failed entropy/RTC initialization, bounded input loading, and registry lifetime invariants;
- AddressSanitizer, UndefinedBehaviorSanitizer, and leak checking across the provider and source-built TLS/crypto libraries.

Browser-specific tests also cover blocking cancellation from another thread, independent peer/hostname policy, expired certificates, custom/missing CA files, socket slot 1, pre-wire native fallback, module activation failures, process-visible module IDs, mount-preserving paths, kernel load recursion and bounded diagnostics.

The source cross-builds with hard-float VitaSDK GCC 15.2. Full build commands and artifact identities are recorded in `TLS13_PROGRESS.md`. On 2026-10-12, one controlled primary 3.60 Vita Browser test rendered the specified Cloudflare trace page with **TLS 1.3 and X25519**, correlated with successful provider startup, a completed verified handshake and application data in the runtime trace. The self-disarming test entry remained disabled afterward; this is one-shot acceptance, not a production deployment or proof that the original boot defect is resolved. Broader firmware, memory, abort/proxy and lifecycle coverage remains unverified. See `TLS13_PROGRESS.md` section 23.275 and `build/browser-tls13-acceptance-20261012.json` for the exact evidence, `docs/tls13-browser-path.md` for the recovered boundary, and `docs/tls13-browser-test.md` for the hardware protocol.

On 2026-10-14, the ordinary combined coordinator passed the Browser cold control followed by strict `sceHttp` HTTP 200 requests for the BrowserLeaks report and dedicated TLS 1.2/1.3 endpoints across three process lifetimes. Each process loaded the authoritative 176-root bundle and reported zero SSL/certificate verification errors. Earlier scoped runs passed the same modern requests. Kernel diagnostic recorders can affect activation when their bounded queues fill; the shipping build resets them OFF. The source passes 355 ordinary and 355 sanitizer-enabled host tests, with compiled compatibility checks for all 31 available firmware/hardware images (five unavailable). The exact rebuilt VPK repeated the Browser and three-process application tests using its final native provider paths. Installer system-file writes remain a separate evidence boundary; qualification preserved the previous working copies.
See `docs/tls13-hardware-validation.md` for the validation protocol and `TLS13_PROGRESS.md` for the reverse-engineering and implementation record.

An independent [Vita TLS Check sample](samples/scehttp_tls_check/README.md) now exercises public `sceHttp`/`sceHttps` calls against BrowserLeaks and SSL Labs. It has a compact native-font interface, protocol results, server-reported cipher details, and per-request error logs. It links no third-party HTTP/TLS implementation and performs no plugin installation or trust-store changes, so the same VPK can compare the stock stack and installed providers. Per-request logs distinguish protocol rejection, SSL failures, network errors and successful HTTP responses. The checker's modern requests have passed with the provider; its legacy TLS 1.0/1.1 checks still fail.

## Building

Fetch the pinned upstream source archive on the host using authenticated `gh`, then build with the hard-float VitaSDK toolchain. The development container command is:

```sh
python3 tools/fetch_mbedtls.py
python3 tools/fetch_curl.py
docker run --rm -v "$PWD":/src -w /src vitasdk/vitasdk:latest \
  sh -lc 'make clean && make'
```

The provider and its dependencies are built with the same project configuration headers from the SHA-256-verified Mbed TLS 4.2.0 release. VitaSDK's prebuilt Mbed TLS libraries are not linked. The release archive is cached under ignored `build/deps/`; CMake rejects a missing or altered archive. No GitHub credentials need to enter the build container.

Core-only tests run on a native C compiler. The full transport tests currently require Linux, Python with TLS 1.3 support, OpenSSL, and pthreads; the VitaSDK container supplies them:

```sh
docker run --rm -v "$PWD":/src -w /src vitasdk/vitasdk:latest sh -c '
  cmake -S tls13 -B build/tls13-transport-san -G Ninja \
    -DTLS_FIXER_BUILD_HOST_TESTS=ON -DTLS_FIXER_BUILD_TRANSPORT_TESTS=ON \
    -DTLS_FIXER_ENABLE_SANITIZERS=ON -DCMAKE_BUILD_TYPE=Debug &&
  cmake --build build/tls13-transport-san &&
  ASAN_OPTIONS=detect_leaks=1 ctest --test-dir build/tls13-transport-san --output-on-failure'
python3 -m unittest discover -s tools/tests
```

Exact bundled-module validation:

```sh
python3 tools/validate_libhttp.py \
  --descriptor tls13/supported_libhttp.json \
  --elf .reverse-tmp/lhttp-3.73-fresh.elf \
  --self misc/lhttp.suprx
python3 tools/validate_libhttp.py \
  --descriptor tls13/supported_browser.json \
  --elf .reverse-tmp/compat-bundled.suprx.elf \
  --self misc/compat.suprx
```

The unpacked analysis ELF is not distributed by the repository and must be produced from the bundled module for this optional static check.

## Firmware modules and CA sources

- bundled HTTP/SSL modules: firmware 3.73
- embedded Sony CA bundle: the complete firmware 3.74 file, 69 certificates
- embedded curl/Mozilla bundle: snapshot dated 2026-09-25, fetched 2026-10-12, 121 certificates
- embedded combined fallback: 176 unique certificates after deduplication

When installing or refreshing certificates, the installer attempts to download the latest [curl/Mozilla PEM bundle](https://curl.se/ca/cacert.pem). That HTTPS request uses libcurl with peer and hostname verification enabled and **only the embedded Mozilla bundle** as its trust source. Default CA files/directories, native CA fallback, environment proxies and redirects are disabled; an OpenSSL callback replaces the verification store with the embedded Mozilla roots.

If networking is unavailable, the transfer fails, or the response is not a complete usable CA bundle, the installer uses the Mozilla snapshot embedded in the VPK. It combines the selected Mozilla certificates with the embedded Sony bundle and removes duplicate certificates before installation. Successful downloads replace the Mozilla component rather than accumulating roots from older snapshots. Download and merge limits are bounded, with a five-second network-readiness wait and a 30-second libcurl transfer timeout.

The **embedded Sony bundle plus the selected curl/Mozilla bundle are authoritative**. The existing system `CA_LIST.cer` is never an input to this merge or to the download's trust store. It is retained only as the original uninstall backup. Missing or corrupt embedded inputs stop certificate installation rather than importing system roots. `certificate-sources.json` records the packaged snapshot hashes and provenance.

The separate Sony, Mozilla and combined PEM files are shipped inside the VPK. The combined file is also the fixture used by provider trust-store tests; the installer constructs its actual installation bytes from the two authoritative source bundles. The updater has passed live-endpoint and controlled HTTPS tests on the host, plus live HTTPS download, embedded fallback preparation and isolated install/refresh checks on retail 3.60. The Vita installer uses native lightweight mutexes for OpenSSL's opaque locks: VitaSDK's pthread rwlocks exhausted synchronization resources while parsing the complete bundles, producing a misleading malloc failure. The 8 MiB newlib heap is retained. The system CA replacement's existing interruption window remains; the isolated test does not establish crash durability.

## Third-party software

Both `tls_fixer_http.suprx` and `tls_fixer.suprx` statically link the source-built Mbed TLS 4.2.0 and TF-PSA-Crypto 1.2.0 libraries. See `THIRD_PARTY_NOTICES.md` and `licenses/`; the corresponding license files are included in the VPK.

## Credits

Thank you to **skgleba** for [iTLS-Enso](https://github.com/SKGleba/iTLS-Enso) and his work updating the Vita's certificates. That work has been very useful and is integrated into **tls_fixer**, together with the original installer and module-redirection foundations. Existing author notices are preserved in the source.

- Team Molecule
- testers from the HenKaku Discord server
- Cuevavirus for the firmware 3.60 NP server fix
- CreepNT for the `vshIoMount` fix
- olokos for the external CA bundle
