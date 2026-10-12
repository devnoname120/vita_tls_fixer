# Queued recorder diagnostic

## Scope and reason

The preceding recorder-status diagnostic booted successfully, but its browser capture reported `err=8001000d`, `op=3`: the first fatal operation was `ksceIoPwrite`. The hook counted 108 calls and the recorder 27 attempts while only 22 records reached the log. This makes the absence of compatibility-module records inconclusive. It is not evidence that the new TLS engine negotiated TLS 1.2; no TLS provider is started by this diagnostic.

The queued implementation moves runtime trace writes into the existing diagnostic kernel worker. It does not change permissions, shared-module flags, Sony binaries, CA files, storage drivers or taiHEN configuration beyond the existing single-use tls_fixer entry. The previously implemented colon-root path correction remains included.

## Record ownership and bounds

`kernel/boot_trace.c` retains the non-waiting producer reservation. A producer formats into a static buffer, copies the bytes into a free queue slot and publishes that slot with release ordering. The worker acquires queued records, performs positional writes and file synchronization, and releases each slot only after successful synchronization. Paths are copied, not retained as pointers into caller memory.

There are 64 slots, with at most 512 bytes per slot. The total trace limit remains 512 records. Partial writes are completed by the worker. Queue saturation is separately reported as operation 6, and pending records can still drain after producer saturation. A worker write/synchronization failure stops further writes. The first fatal status is preserved rather than replaced by a later failure.

A successfully enqueued record is not yet durable. A crash can lose the queue tail. Reentrant producers may decline a record, and a failed or exhausted status worker may leave both the file and the status stale. The worker retains its 128-publication budget; when it exits, it no longer drains the queue. `m=2` denotes budget exhaustion, while `m=1` is not an ongoing heartbeat. Do not infer absence of a module load from incomplete, saturated or failed observation.

## Startup and lifetime

Self-disarming remains the first entry call. The gate's successful persistence checks precede logger setup, worker creation and hook installation. Startup records remain synchronous until asynchronous mode is enabled. The worker is started and asynchronous mode enabled before installing the existing gated loader hook.

The process-namespace flag `0x1000` still selects path recording. Other hook invocations only contribute to the atomic invocation counter. This selector is not a title-ID filter and does not imply that all shared-module loads are captured.

Failure cleanup joins the worker before releasing code or closing its trace descriptor. If joining or deleting the worker fails, the module stays resident and refuses unsafe unloading. The worker performs no module-list queries, TLS-provider startup, configuration re-arming or reboot.

## Native review

The reviewed ELF is `build/async-trace-observer-kernel/tls_fixer.elf`. In IDA session `tls_fixer-queued-recorder-review-20261009`, full-range instruction queries established:

- `module_start` first calls self-disarm at `0x810001A4`; worker startup at `0x81000354` precedes hook installation at `0x8100039A`.
- The thread-start helper tail-branches to asynchronous enable at `0x81002446` after native thread start succeeds.
- `trace_event` loads `deferred` at `0x81001D6C`, takes the queued path at `0x81001D76`, copies bytes at `0x81001E36`, and publishes the tail with release ordering at `0x81001E3E..0x81001E42` before returning.
- That branch bypasses the synchronous pwrite/sync calls at `0x81001DA6` and `0x81001E60`.
- The drain uses pwrite at `0x81001FF4` and sync at `0x81002074`, and releases the consumed slot afterward.

These are compiled-code findings, not evidence of execution on the Vita. The earlier partial Hex-Rays output was not used to infer function completion.

## Verification and deployment gates

The preceding run is saved in `build/async-trace-full-verification.log`. The continuation's direct rerun was tool-blocked, but the user executed the supplied local-only Docker command successfully. Its complete `build/async-trace-user-verification.log` was checked: 133 normal CTest targets, 133 sanitizer/leak-checking targets, 34 Python tests, native observer/default builds and decoded-register checks, ending `ASYNC_TRACE_USER_VERIFICATION_PASSED`.

The verified package is `build/artifacts-async-trace-observer/tls_fixer-queued-recorder-observer.zip` (12487 bytes, SHA-256 `90b06d39852202b014e0df3bb7f17eadd269caa4477637b253a01b7f4e4b8b1d`). It contains only `tls_fixer.skprx` (15910 bytes, SHA-256 `7f44196f37256425b4f680d22259ef43af6004e9383450291ea7011fdb171d79`) and the fresh 256-byte result (SHA-256 `b43c161a5c9a09b0de4d0d435461ae8b019d231518f6e18f40a7ea2b089f5815`). Both members were reread and compared. The adjacent receipt records source fingerprints, the ELF hash and the user-run verification log hash. Keep that receipt and documentation out of the two-file ZIP.

The last captured device state is the disabled 15376-byte recorder-status kernel. The user reported an ordinary unarmed reboot, and the subsequent capture preserved its error evidence. Before replacing anything, verify the current disabled config, old kernel, report, trace and protected boot/YAMT/FTP files again. Preserve all before-state bytes. A disabled disk entry does not by itself prove an in-memory worker is absent; never replace a live report without establishing that the preceding test session ended.

Stage only the removable test kernel and its diagnostic result file. Keep the entry disabled through upload/read-back verification, then deliberately arm at most once under the existing permission. Do not repeat the old full-refresh installer, replace system modules or CA files, or test the donor device.

The new helpers are `build/stage_async_trace_files_only.py` and `build/arm_async_trace_once.py`. They pin these two payloads and use distinct backup/receipt names. The stage helper checks the old kernel/report/trace plus six protected files against the preserved inactive-session hashes before any upload, and rejects a changed or alternate configuration. It retains old remote copies, checks read-back and does not write config.txt. The arm helper independently verifies the new payloads and protected files before its existing single-byte positional edit. Both helpers passed syntax checks and seven memory-only FTP scenarios, including no-write mismatch cases and rename rollback, in `build/async-trace-helper-verification.log`. This is local mock coverage, not successful remote staging.

Only after both helpers exit successfully with `ONE_BOOT_ENABLED`, perform one normal manual reboot and report the first-boot outcome. Stop without rebooting if either helper fails. An armed receipt, FTP connection or old log is not proof of a successful test boot.

## Device acceptance sequence

First verify one successful boot, a completed disarm/setup report, the expected disabled configuration and a fresh observer trace. Preserve that baseline before opening the browser. Then obtain one browser request in the same session and capture the advanced trace plus independent status. Compare actual paths and native load results with the browser matcher.

TLS 1.2 is expected from this observation-only build. The acceptance gate for this diagnostic is reliable browser-path evidence without caller-context trace writes, not a TLS 1.3 handshake. Provider activation and the actual shared/private mapping remain subsequent, separate checks. Do not bypass a certificate warning.
