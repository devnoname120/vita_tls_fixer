# Standalone Vita TLS probe implementation

Approved for local implementation in CHAT.md (2026-10-10). Installation is outside this plan; the existing browser-control payload, boot configuration and iterate.sh remain unchanged.

## Acceptance

An opt-in ordinary hard-float application (TLSF00002) runs two independent, certificate-verified TLS exchanges with min=max TLS 1.3 and min=max TLS 1.2. It uses the pinned engine and existing Vita crypto/time/thread shims, a public app-local CA, explicit private-LAN IPv4/DNS identity/ports, a fresh entropy-backed nonce, and bounded I/O/report storage. No fallback, hook, kernel import, installer, reboot or system trust-store change is permitted.

Successful host tests and native packaging are not a Vita result. The report distinguishes handshake completion, certificate verification, response/nonce completion and cleanup/report failures. This gate cannot validate browser objects, Sony-libc initialization or taiHEN trampolines.

## Steps

1. Add tests for optional controlled-server nonce parsing/echo, preserving the server's ordinary browser response when the parameter is absent. Reject malformed or duplicate nonces without logging request paths. Implement only after observing the focused failure.
2. Add a bounded request/response parser and a small probe I/O interface. Test framing, exact nonce echo, strict protocol selection, deadlines, partial I/O, EOF, excess data and cleanup. Link real Mbed TLS/TF-PSA in loopback tests; substitute platform edges only.
3. Add the disabled-by-default Vita probe target. Keep application networking ownership explicit, use nonblocking sockets with a 15-second per-connection deadline, and release each connection before starting the next. Reuse crypto/time/thread adapters, not provider hooks or its libc startup.
4. Add checked framebuffer initialization and bounded text output using the existing font data, plus an exclusive-create run report under ux0:/data/tls_fixer-probe. Fail before connecting if entropy, configuration, CA loading or report setup fails. Cap request, response and report at 1024, 4096 and 16384 bytes respectively.
5. Validate build inputs before generation: canonical RFC1918 IPv4, DNS name, distinct TCP ports and certificate-only PEM. Generate an app-local build identity and receipt containing endpoint, CA, source/config/archive hashes. Package no private key or existing tls_fixer payload.
6. Run focused and aggregate host/sanitizer/Python tests. Build a separate Release Vita target; inspect native linkage/imports and package members, and record local artifact identities. Update TLS13_PROGRESS.md and CHAT.md without installing or promoting the app.

## Validation boundaries

Use the local pinned Mbed TLS archive and installed toolchain; do not alter the deployed kernel or provider. Keep malformed remote responses bounded, do not accept chunked/ambiguous framing, never infer a negotiated fallback from the two strict-version tests, and never mark logging failure or an uncorrelated response as overall success. Store the private controlled-server key only in its host fixture directory, never in the application package.
