# Standalone native TLS probe

This is an ordinary VitaSDK application, title `TLSF00002`, not a browser plugin or installer. It performs one strict TLS 1.3 exchange and one independent strict TLS 1.2 exchange with a controlled LAN server. Both require normal chain and hostname verification. A shared fresh 128-bit run nonce is echoed by the server and recorded on both sides.

The implementation and local package are available. There has been no probe installation or Vita execution. The current package is a build-validation fixture, not a deployment-ready binary: its server address has not been freshly verified, its certificate expires, and the new executable's IDA instruction review was unavailable because the service returned HTTP 502.

## What this test can establish

A matching client/server result can establish native compilation, crypto, entropy, time, sockets, strict-version negotiation and a bounded application exchange in an ordinary process. It cannot establish browser compatibility, the injected provider's Sony-libc initialization, native browser object layouts, TLS-context metadata, stack usage or taiHEN trampoline correctness. The unresolved browser crash and the incomplete passthrough page-load control remain separate.

The app has no taiHEN/kernel imports, boot entry, reboot request, system trust-store operation or plugin installation. Its CA is read from `app0:/probe-ca.pem`, checked against the build's SHA-256 identity, then parsed. Reports are created exclusively at `ux0:/data/tls_fixer-probe/run-<nonce>.log`. It never overwrites an existing run report and does not retry with a different nonce after collision or entropy failure.

## Build with explicit inputs

Use the installed hard-float VitaSDK and the checksum-pinned Mbed TLS archive already used by this worktree. The example address is the current local build fixture, not a claim that a server is running there. Replace it and the certificate path with the intended test configuration before deployment.

```sh
docker run --rm -v "$PWD:/src" -w /src vitasdk/vitasdk:latest sh -ec '
  cmake -S tls13 -B build/probe-vita -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE=/usr/local/vitasdk/share/vita.toolchain.cmake \
    -DVITASDK=/usr/local/vitasdk \
    -DCMAKE_BUILD_TYPE=Release \
    -DTLS_FIXER_BUILD_VITA_PROBE=ON \
    -DTLS_FIXER_PROBE_ADDRESS=192.168.1.249 \
    -DTLS_FIXER_PROBE_DNS_NAME=tls_fixer-probe.test \
    -DTLS_FIXER_PROBE_TLS13_PORT=5443 \
    -DTLS_FIXER_PROBE_TLS12_PORT=5444 \
    -DTLS_FIXER_PROBE_CA=/src/build/your-test-fixture/server.pem
  cmake --build build/probe-vita -j4
'
```

The probe option defaults to OFF. It rejects provider, browser diagnostic, runtime UDP, sanitizer and host-test profiles in the same native build. Release is explicit because the pinned crypto implementation's ARM assembly did not compile in an earlier unoptimized configuration. The address must be canonical RFC1918 IPv4; the verification/SNI name must be DNS, not the numeric address; the two ports must be distinct and within 1024..65535. The CA input must contain exactly one public PEM certificate, at most 65536 bytes, with no private material.

Generated public inputs are in `build/probe-vita/probe-generated/`. The build identity includes endpoint, CA, source, crypto archive/configuration, compiler, toolchain and compile-flag metadata. Probe source and CA changes trigger CMake regeneration. The package is `build/probe-vita/probe/tls_fixer_probe.vpk`; it contains exactly `eboot.bin`, `sce_sys/param.sfo`, `probe-ca.pem` and `probe-build.json`. Do not put the server's private key in that directory or in the package.

The ordinary executable requests an 8 MiB newlib heap. Main-thread stack selection is left to the SDK default; a discarded, unreferenced stack-override declaration was removed rather than claiming that it configured a 512 KiB stack. There is no measured whole-program native stack bound yet.

## Controlled servers

After choosing and validating the host's actual LAN address and an unexpired certificate with the configured DNS subjectAltName, run one foreground server per terminal. These commands do not configure the Vita:

```sh
python3 tools/tls13_test_server.py \
  --bind 192.168.1.249 --port 5443 --tls 1.3 \
  --cert build/your-test-fixture/server.pem --key build/your-test-fixture/server.key
```

```sh
python3 tools/tls13_test_server.py \
  --bind 192.168.1.249 --port 5444 --tls 1.2 \
  --cert build/your-test-fixture/server.pem --key build/your-test-fixture/server.key
```

Keep the private key host-only with restricted file permissions. The application connects to the configured numeric address but uses the DNS identity for SNI and certificate verification. It does not require a DNS lookup for that name.

The server prints a JSON object for each successful request. Preserve those records privately; they include `probe_nonce`, `tls`, `cipher`, a server-run identifier and a timestamp. A failed trust/hostname/version test should not be accepted merely because a TCP connection appeared.

## Execution and interpreting results

Checked display setup, fresh nonce creation and exclusive report creation/synchronization precede crypto/CA/network preparation. The two exchanges run serially, releasing each TLS/socket state before the next. A normal failure of the first handshake does not suppress the independent second protocol check. A connection-cleanup, report or display failure does stop further exchanges. There is no retry, automatic downgrade or browser fallback.

Each exchange has a 15-second cooperative monotonic budget. Nonblocking waits are bounded, but synchronous crypto and cleanup are not preempted. Finishing cleanup after the budget returns a deadline error while retaining any handshake and exchange observations already obtained. The report separates handshake completion, peer verification, response/nonce completion, errors and cleanup rather than collapsing them into a single success string.

Reports are capped at 16 KiB and begin as INCOMPLETE. A final `payload_complete=1` footer establishes only that the complete report payload was submitted; it cannot prove the success of its own subsequent close or physical crash durability. The application checks close/synchronization errors and displays the resulting local status separately. A saved report must not be accepted without the matching current app result and server correlation.

Acceptance requires all of the following together: a fresh displayed run nonce and build identity; two successful, correctly negotiated strict-version results with zero verification/cleanup/report errors; and matching server records for that same nonce, one TLSv1.3 and one TLSv1.2. The two strict runs are not a negotiated-fallback test. Even complete standalone acceptance does not establish browser TLS 1.3.

The result page remains until Cross is released and pressed, or until 60 seconds of checked waits elapse. Normal exit checks framebuffer detach/release. It never requests a reboot or arms anything.

## Installation is authorized; before-state checks remain required

On 2026-10-10 the user granted standing authorization for all further primary-Vita TLS tests, including this separate application. Do not ask again for installation/test permission. Do not run `iterate.sh`, an tls_fixer installer, or the historical arming helpers for this probe. Before installation, verify that `TLSF00002` does not already exist, confirm the existing tls_fixer entry is disabled, and preserve the browser-control evidence. Refuse to replace an existing application with the same title ID. This probe's transfer/installation must stay in its app/report scope; it must not replace the kernel, provider, CA store, storage configuration or boot files.

The prepared package and its original local provenance receipt are under `build/artifacts-standalone-probe/`. That creation-time receipt records `hardware_validated=false`, `deployment_ready=false` and the earlier permission state. The later standing grant does not itself establish that preflight, transfer, installation or execution succeeded; record those separately.
