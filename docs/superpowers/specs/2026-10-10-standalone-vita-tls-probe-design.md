# Standalone Vita TLS probe

Status: approved for local implementation in CHAT.md on 2026-10-10. The core, correlated server, native adapters, report and ordinary application target are implemented, host-tested and packaged locally. The package is a build fixture; native instruction review was unavailable and there is no installation or Vita result. See TLS13_PROGRESS.md sections 23.167-23.170 and docs/tls13-standalone-probe.md. This is the missing native-client gate from the original TLS 1.3 plan, not an alternative explanation of the browser crash.

## Question and acceptance boundary

Can the pinned TLS engine perform a certificate-verified TLS 1.3 handshake and a small request/response exchange on the primary Vita, without any browser object, taiHEN hook, native continuation or boot plugin? A separate TLS 1.2-only connection checks the same engine's older-protocol path. These are independent strict-version checks, not proof of negotiated fallback from a mixed-version offer.

A successful probe would establish a native compiler/crypto/entropy/time/socket path. It would not establish the Sony-libc allocation environment of the injected provider, the browser's thread stack, its object layout, its module lifecycle or hook correctness. An ordinary VitaSDK application uses a different process and C-runtime startup from the injected user module. That limitation must be printed in its report, not hidden by calling it an end-to-end browser test.

## Alternatives

The existing passthrough control remains the most direct discriminator for the browser failure, but it currently has no completed page-load observation. Replacing it with another kernel profile before obtaining that observation would add uncertainty.

Running a self-test inside the browser provider would retain more of its native runtime, but would mix the probe with browser startup, process-specific network initialization and the same lifecycle under investigation. It should not be the first independent TLS test.

A separate ordinary application is therefore the proposed independent gate. Its installation is a new device action and requires approval; the standing kernel-test permission is not permission to install a VPK. Until that is approved, work is local only.

## Scope

Add an opt-in `TLS_FIXER_BUILD_VITA_PROBE` target, disabled by default. It links the existing pinned Mbed TLS/TF-PSA configuration and Vita crypto/time/thread shims, without browser/provider hooks, kernel imports, installer actions, FTP writes or boot-entry management. Build it as a normal hard-float VitaSDK application with title identity `TLSF00002`; installation must refuse to replace any pre-existing application with that ID. Do not change the existing installer or deployed diagnostic selection.

Use an explicitly supplied private-LAN IPv4 address, server DNS name, two ports and a public CA certificate. Build-time configuration avoids another on-device configuration parser in this first probe. The peer address is not the verification identity: the configured DNS name must be used for both SNI and hostname verification. No certificate bypass, insecure fallback, public-internet default or private server key belongs in the application.

The existing `tools/tls13_test_server.py` supplies one strict-version server per port. Add one optional probe-correlation field to it: accept only a 32-hex-digit probe nonce from the designated query parameter, include it in the server's JSON record, and echo it in a dedicated response header. Do not log arbitrary request paths or introduce an endpoint that serves local files. Existing browser test behavior without that parameter remains unchanged. The CA certificate is packaged with the probe under `app0:`; no system CA store or original tls_fixer resource is modified. The generated build receipt must identify the public CA hash and selected endpoint/version settings.

## Execution

Initialize only application-owned networking resources, retaining ownership flags so cleanup never terminates a resource the probe did not initialize. Each connection has a 15-second monotonic deadline and nonblocking socket I/O; WANT_READ/WANT_WRITE must not become busy loops. Close the first connection and release its TLS/socket state before opening the second. Reject requests exceeding 1024 bytes or responses exceeding 4096 bytes. The response parser only needs the existing controlled server's HTTP/1.1 status line and bounded Content-Length framing; unsupported framing fails the exchange rather than being guessed.

For each requested version, configure min=max, require normal certificate and hostname verification, complete the handshake, obtain the negotiated version/cipher from the TLS engine, and exchange one bounded HTTP/1.1 request. Report handshake verification and application exchange separately. A failed exchange must not erase an already-observed handshake, but it must not count as a complete probe success. There is no automatic retry or downgrade.

Show a compact status page and save a report of at most 16 KiB under `ux0:/data/tls_fixer-probe/run-<nonce>.log`, using a fresh 128-bit run nonce and exclusive creation. If the entropy source cannot produce the nonce, fail before connecting and show the entropy error rather than inventing a reusable identifier. Display/network/allocation/file failures must be checked; logging failure cannot turn an operation into success. Do not reuse the installer screen initialization unchecked: its current framebuffer allocation path does not return errors to the caller. No URL body, certificate private material, keys, session tickets or arbitrary memory contents are recorded. The report includes build identity, endpoint identity, requested/negotiated protocol, verification status, stage/native error and elapsed time. Send the nonce in the designated request query parameter and require its exact echo in the response header; correlation with the controlled server is required for final acceptance rather than relying on a stale on-card report.

The app never edits taiHEN configuration, requests a reboot, restarts itself or installs a plugin. A normal app exit/reboot leaves it inactive. An app crash is not a boot-time failure; the existing experimental tls_fixer entry stays disabled throughout this probe.

## Local validation and device gate

Before native packaging, use a host-testable probe core with a small I/O/deadline interface. Test strict versions against controlled loopback servers, valid trust, unknown CA, mismatched hostname, timeout, partial I/O, EOF, request/response bounds and resource cleanup. Keep the protocol engine real; mock only the platform edges. Test build-profile rejection for missing/invalid endpoint or CA inputs.

Build the native application separately from all existing provider/kernel directories. Record toolchain, library/configuration hashes and dependencies. Host tests and successful packaging do not establish a Vita result.

Before any installation, obtain approval for this separate app and its exact file scope. Verify the existing tls_fixer entry is disabled and preserve the current browser-control evidence. Do not run the old arming helper, overwrite the deployed provider, or infer success merely from launching the application. Acceptance requires the probe's fresh result and matching controlled-server evidence. The browser crash investigation remains open regardless of the probe outcome.
