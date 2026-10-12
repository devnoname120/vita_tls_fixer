# Preparation-only diagnostic with persistent startup records

## Identity and scope

This is a diagnostic of the boot failure, not a TLS 1.3 release or installer. It executes the preparation-only path that previously failed, with entered/returned stage logging. It never calls module load/start or starts a TLS provider. The existing module redirection hook is still present.

Kernel: `build/traced-setup-result-kernel/tls_fixer.skprx`

- Bytes: 14109
- SHA-256: `5ed6eac8d0b9517b654ecfa19714206bd78c9ec2e51e5bbad1619f8f745ca5a6`
- Build: `TLS_FIXER_PREPARE_ONLY=ON`, `TLS_FIXER_ENABLE_BOOT_TRACE=ON`
- Device test path: `ux0:/data/tls_fixer-one-shot/tls_fixer.skprx`
- New log: `ur0:tai/tls_fixer-startup.log`
- Preallocated 256-byte setup report: `ur0:tai/tls_fixer-disarm-result.txt`

Both earlier trace variants reached LiveArea without a log. A subsequent result-only diagnostic successfully reported `gate.complete` through an existing 256-byte file. This variant records the gate outcome and the exact trace-setup return value in that proven output file, including setup failures. The logger's original open flags and path are retained rather than changing file-opening behavior on an unproven hypothesis. It is instrumentation, not a boot-defect fix.

Do not install or refresh any previous VPK. Do not alter boot_config, YAMT, other plugins, CA files or the user TLS providers.

## Before the manual reboot

Keep the experimental entry disabled while transferring the kernel. Preserve the previous removable test kernel, setup report and any existing `ur0:tai/tls_fixer-startup.log` under distinct inactive backup names. Prepare the new 256-byte PENDING setup report before activation; the reporter refuses a missing or differently sized file. The kernel attempts to create/truncate the startup log once after successful self-disarming; the subsequent disabled boot does not truncate the evidence.

Copy the identified 14109-byte kernel to the fixed removable path. The companion PENDING report is diagnostic data only, not a boot permission token. In `ur0:tai/config.txt`, replace only the first character of the existing disabled test line:

```text
#x0:/data/tls_fixer-one-shot/tls_fixer.skprx
```

with:

```text
ux0:/data/tls_fixer-one-shot/tls_fixer.skprx
```

Do not add a duplicate entry, use a different path, replace the whole config, or simply delete the #. Leave FTP on port 1337 running, report copied/edited, and wait for the read-only identity/config check before rebooting. Every reboot is manual. Do not try to fix a stalled FTP service by rebooting an armed, unverified test.

## Test and evidence collection

After verification, reboot normally once with the removable card inserted. No L-held boot, installer or browser test is needed. Report whether it reaches LiveArea, freezes or powers off.

If the test fails after disarming, the following normal power-on is expected to skip this module, as observed with the earlier preparation probe. Never re-enable the line automatically after a crash. The limitation before module_start or before the disarming edits complete still applies; this is not a guarantee against every possible fault.

Once back in LiveArea, leave FTP accessible. Retrieve and retain the setup report, `ur0:tai/tls_fixer-startup.log` if present, both applicable taiHEN configs, and the actual test kernel before any further modification. Check that the boot entry is disabled and that the rest of the config is unchanged. No intentional crash should be introduced merely to test the logger.

The setup report retains `stage`, `outcome`, native gate code and write/verification counts from the result-only test format. The reserved 32-byte area at offset 192 adds `trace_setup=XXXXXXXX`, preserving the gate fields. A negative trace-setup value is the actual failing open/thread/write/sync result when available, not the previous generic -1. Gate/report/setup failure stops before hooks. A missing trace-setup field is not success: preserve PENDING/partial data and compare the config and kernel identity. See `tls13-disarm-result-test.md` for the base report's interpretation.

## Reading the log

Each ASCII record contains a hex sequence number, thread ID, target process ID, object/module ID, signed-result bits, stack pointer and monotonic microseconds. Stage names contain no user text. No URLs, payloads, certificates or keys are recorded.

Important stages are:

- `trace.open`, `startup.checks.enter/return`, `loader.init.enter/return`, `hook.install.enter/return`.
- `prepare.enter/return`, `reserve.enter/return`, `scan.enter/return`.
- `module.list.enter/return`, `module.info.enter/return`, `hash.enter/return`, `target.info.enter/return`.
- `cleanup.enter/return`.

The trace is limited to 512 records shorter than 192 bytes each (less than 96 KiB). Each completed record requests synchronous file flushing. Trace creation failure prevents hook installation. Missing trace capacity or a logging error prevents the next instrumented preparation operation; cleanup of an existing reservation is still attempted. The logger does not wait for another logging call and does not perform file I/O while the diagnostic reservation mutex is held.

A final entered record without its return narrows the boundary where progress stopped, but is not by itself proof that that exact API crashed: it may also reflect an interrupted or failed write, an exhausted record budget, concurrency or a fault before the following log call. Partial trailing records must be treated as incomplete. A logged return is progress evidence, not proof of successful physical power-loss durability.

A successful boot is not enough: determine whether the trace actually reached the preparation path, or whether diagnostics aborted it. File synchronization changes timing, so success with instrumentation can also mask a timing-dependent failure. Compare thread, process, sequence and stack fields rather than attributing every interleaved line to one request.

## Verification completed locally

The integrated code passed 64/64 normal CTest targets, 64/64 ASan/UBSan/leak-checking targets and 17 Python tests. The clean rebuild passed its decoded FP/SIMD instruction gate, had no unresolved symbols and no module load/start/unload symbols. Evidence: `build/traced-setup-result-verification.log`. Native-error propagation, the reserved setup field and reporting before the gate-success branch each had a failing regression before correction.

The earlier inspected logger frame was 128 bytes; its load-hook and preparation frames were 552 and 1544 bytes. These historical sizes are not a measurement of this revision's total remaining Vita stack or proof of an overflow. Recent IDA service requests returned 502; generated-code checks use the build disassembly and existing register gate. No new firmware reverse-engineering finding is claimed.

No device execution or root-cause fix is established by these checks. The earlier preparation-only crash remains unresolved until actual trace evidence is collected.
