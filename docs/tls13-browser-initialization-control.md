# Browser initialization-only control

## Question

The primary Vita's normal browser page load produced C2-12828-1 with the
passthrough provider, which initializes the backend and installs four hooks
but leaves replacement TLS disabled. An unarmed reboot subsequently rendered
the Cloudflare trace page with `tls=TLSv1`. Neither result locates the crash PC.

This control keeps the existing compatibility-module replacement, identity
checks and provider initialization, but publishes no user hooks. It is not a
TLS 1.3 implementation change or a crash fix.

## Build and checks

`TLS_FIXER_BROWSER_INITIALIZE_ONLY` defaults off and requires
`TLS_FIXER_BROWSER_PASSTHROUGH_ONLY`, which in turn requires the Vita startup
diagnostic and rejects runtime UDP. Successful initialization explicitly
sets the replacement backend to disabled and returns success before the
hook loop. Failed argument, identity, signature, CA-path or initialization
checks retain their existing diagnostic results.

The previous implementation failed the new zero-hook-attempt assertion in
`build/browser-initialize-only-red.log`. The completed normal and sanitizer
runs each pass 270 CTest targets; the Python suite passes 104 tests in
`build/browser-initialize-only-host.log`. The new module target includes 26
cases. The native Release build is separate from prior artifacts at
`build/browser-initialize-only-vita/` and has no unresolved provider symbol.

IDA session `tls_fixer-browser-initialize-only-control` verifies the full entry
range 0x81000200..0x81000348: validation at 0x810002B4, initialization at
0x810002E6, and the zero-valued enable call at 0x81000322. The native image
has no hook-installation symbol or retained hook callback. No kernel change
was required.

## Exact payloads

The provider at `ur0:tai/tls_fixer_startdiag.suprx` is 151969 bytes,
SHA-256 `e2dcc0ec602e11f6a00a0553edebb9c942a53c5a3f0cba16ad9227002004123a`.
The 256-byte fresh report hashes to
`dc49babcdd4aa0470ac9a1c63b5ec6f3553de97fcfa51ad198e74607a11ad320`.
The unchanged removable kernel is 20645 bytes, SHA-256
`429b594c59aaff7082574121d521ce1e1e5801998b858b9aa35b5ac37e98d3c7`.

`build/artifacts-initialize-only-control/receipt.json` records source and
verification-log hashes and the read-only preflight. Its diagnostic ZIP
contains only the kernel and report; the provider is a separate artifact.
Original Sony modules, trust files and storage configuration are not changed.

## Execution and interpretation

The guarded stage/arm/run sequence has already been invoked for this test.
Do not rerun its helpers, the consumed receipt or the older `iterate.sh`.
The runner verifies one self-disarming boot and stops before browser input;
CLI exit status 3 with `browser_ui_pending=true` is the expected checkpoint.

After preserving any current error, run the user's requested `quit all`,
then inspect screenshots and use the visible browser icon and Start tile.
Never substitute vitacompanion's title or URI launch. Observe against the
saved cycle with `observe-ui`; this phase sends no device commands. A
successful provider entry proves neither page rendering nor TLS negotiation.
Read the actual screen and preserve the trace, status and private crash
inventory before another action.

A successful page with this control would narrow the failure toward hook
publication/continuations or differences introduced by the larger provider.
A failure would show that active TLS and the four hooks are not required to
reproduce it. The initialization-only ELF is smaller because unreferenced
transport code is discarded, so a memory-pressure explanation is not held
constant. A screenshot can also show cached page content; retain the visible
server timestamp and request context rather than claiming a fresh handshake
at capture time. The test's current device outcome is recorded in the latest
sections of `TLS13_PROGRESS.md`, not inferred from this build document.
