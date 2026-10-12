# tls_fixer kernel-stack headroom control

## Purpose

The previous instrumented redirection-only control reached LiveArea by user report, and its saved 19-record trace proves that the hook redirected HTTP and SSL loads in two processes. The preparation diagnostic still crashed despite returning from its queries, rehash, printing, and a subsequent SSL load. Basic redirection is therefore a measured positive baseline; the remaining difference includes preparation operations, nested stack use, and timing.

This control adds a stack measurement to that positive baseline. It does not restore preparation, start a TLS provider, or request an HTTPS test. It is not a boot-fix claim. The separately compiled preparation-with-headroom profile stays local until this measurement path is qualified.

## What is measured

`TLS_FIXER_STACK_HEADROOM=ON` adds a hexadecimal `free=XXXXXXXX` field to each existing `tls_fixer-trace1` line. The value is a byte distance from the current kernel-stack lower bound to SP at the measurement point, not an allocation counter, high-water mark, or guarantee that a future call fits.

The probe resolves `SceKernelThreadMgr`, library NID `0xE2C40624`, function NID `0xD74F66BD`, once during trace initialization. It requires a Thumb entry matching the selected 34-byte implementation. Missing exports, wrong entry mode, or changed code reject trace setup before hooks. An uninitialized-probe sentinel (`0xFFFFFFFF`) stops logging rather than appearing to be almost 4 GiB of headroom.

Fresh IDA inspection of the existing 3.60 ThreadMgr database confirms the implementation at `0x00BA00A6..0x00BA00C8`: it reads the current CPU/thread context with MRC, loads bounds at context offsets `0x74` and `0x78`, subtracts the lower bound from SP, and returns zero when the context or range is invalid. There are no calls, allocations, locks, local stack frame, or writes in that routine. A native caller at `0x00BAC0DA` compares its result with `0x708` before choosing a path. This supports a remaining-stack interpretation; it does not establish the live stack bounds of the affected boot thread.

The decompiler rendered the stack address as a synthetic fifth argument. The raw instructions read SP directly and consume no incoming argument register. The C wrapper is a tail branch in the generated diagnostic, adding no separate frame. The recorder's own frame is 128 bytes and the redirection hook's frame remains 296 bytes, matching the corresponding frame sizes recorded for the prior control. Measurements include the already-entered recorder frame but not the additional stack needed by subsequent file writes or synchronization.

A zero value is ambiguous: no valid current context/range, or no measurable headroom. Do not treat it as a proven overflow. Positive samples do not exclude transient deeper usage between records. Logger failure, truncation, concurrency and altered timing remain interpretation limits.

## Verification

The current source passes 83 normal CTest targets, 83 ASan/UBSan/leak-checking targets, and 17 Python tests. Tests cover the export gate, signature mismatches, zero and unavailable values, bounded record size, partial/invalid writes, synchronization failures, reentry and refusing further records after failure. The new unavailable-value regression failed on the old logger before the guard was added.

Control, preparation-with-headroom and default kernels build and pass the linked executable FP/SIMD check and unresolved-symbol checks. The control contains no preparation/injection routines or module load/start/unload imports. The default profile does not enable this measurement. Fresh IDA inspection confirms self-disarming occurs before reporting, probe resolution, logger initialization, and hook installation.

These are local/static results. No device execution of this headroom control has been recorded.

## Staging

Do not run an earlier VPK or the full-refresh installer. Preserve the current kernel, result file and startup log before any replacement.

| Archive member | Device path |
| --- | --- |
| `tls_fixer.skprx` | `ux0:/data/tls_fixer-one-shot/tls_fixer.skprx` |
| `tls_fixer-disarm-result.txt` | `ur0:/tai/tls_fixer-disarm-result.txt` |

Use the fresh 256-byte PENDING report and the kernel identified by this archive's SHA256SUMS. Restore only the first character of the existing `#x0:/data/tls_fixer-one-shot/tls_fixer.skprx` entry to `u` in `ur0:tai/config.txt`. Do not duplicate the line or change another entry. Close the editor and computer FTP connection, leaving the Vita's FTP server available; report completion and wait for a read-only kernel/report/config check before rebooting.

Every reboot is manual. After verification, perform one normal reboot with the card inserted, without L, installer, or browser testing. Report whether LiveArea appears directly or the device freezes/shuts down. A subsequent recovery power-on must not re-enable the test.

## Required evidence

Preserve `ur0:tai/tls_fixer-disarm-result.txt`, `ur0:tai/tls_fixer-startup.log`, the whole config and the tested kernel before any further activation. Require gate success, `trace_setup=00000000`, returned hook installation, and actual `load.enter`, `load.return`, and `hook.return` records containing the new field. A boot without these records may have rejected initialization rather than run the control.

Group measurements by thread and compare the same stage, not absolute SP addresses across boots. Do not interpret startup-thread measurements as the budget of later loader threads. The control should contain no `prepare.enter`, `scan.enter`, or post-preparation `print.enter` records.

Self-disarming is unchanged and never re-arms the entry. It protects the next boot after successful synchronization, not failures before module_start or completion of the disarming writes. It does not roll back historical file replacements. Leave boot_config, YAMT, internal FTP plugins, certificates and Sony modules unchanged.
