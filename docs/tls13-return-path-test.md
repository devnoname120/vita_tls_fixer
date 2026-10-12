# tls_fixer post-preparation return-path diagnostic

## Purpose and scope

The preceding 15508-byte hash-workspace kernel still crashed. Its preserved log now completes workspace allocation, hashing, release, target-module inspection and cleanup, ending at `prepare.return` with result 0. The next instruction boundary is kernel printing, followed by returning from the intercepted loader.

This preparation-only diagnostic retains the same self-disarm gate, per-call hash workspace, exact-module checks and kernel print calls. It adds records around the native call for redirected modules, the post-preparation print, and the hook's final return. It does not load or start either TLS provider or the DNS helper. It is not a fixed browser release, and it must not be installed using an old VPK or full-refresh operation.

The normal and sanitizer test suites each pass all 64 targets, including production-route tests for event ordering, negative preparation/printing results, native loader failures, and every new marker-failure boundary. The native load still occurs exactly once even if entry logging fails; its arguments, selected path and return value are preserved. All 17 Python tests pass. Fresh traced and default kernel builds pass the FP/SIMD instruction and unresolved-symbol checks. The traced binary has no module load/start/unload symbols. These are host/static checks, not a new Vita boot result.

## Files and manual staging

The bundle manifest identifies the exact kernel and 256-byte PENDING report. Preserve the current kernel, report and log before replacing anything. Only these two files are new inputs:

| Bundle member | Vita destination |
| --- | --- |
| `tls_fixer.skprx` | `ux0:/data/tls_fixer-one-shot/tls_fixer.skprx` |
| `tls_fixer-disarm-result.txt` | `ur0:/tai/tls_fixer-disarm-result.txt` |

In `ur0:tai/config.txt`, replace only the initial `#` of the existing `#x0:/data/tls_fixer-one-shot/tls_fixer.skprx` line with `u`. Do not delete the character, duplicate the entry, edit another plugin or use a previous configuration backup as the active file.

Close the editor and disconnect the computer FTP client, leaving the Vita FTP server available. Report that copying/editing is complete and wait for read-only verification of the kernel, report, whole configuration and protected files. Do not reboot before that check. Every reboot is manual; no power or module-start command will be issued by the agent.

After verification and a request to test, reboot normally once with the removable card inserted. Do not hold L, open the tls_fixer installer or test the browser. Report whether LiveArea appears directly, the warning screen freezes, power is lost, or an improper-shutdown warning appears. Do not re-enable the entry after a failure. If the test shuts the device down, the subsequent ordinary power-on is expected to skip it after successful self-disarming; retain and report that sequence.

## Evidence to retrieve before any further activation

Preserve `ur0:tai/tls_fixer-disarm-result.txt`, `ur0:tai/tls_fixer-startup.log`, the full `ur0:tai/config.txt`, and the tested kernel. The setup report must show the gate and trace setup outcomes, not PENDING or a partial record. A completed boot alone does not prove that the diagnostic reached its intended stage.

The new trace boundaries are:

| Stage | Object field | Result field |
| --- | --- | --- |
| `load.enter` | Route kind | Original load flags |
| `load.return` | Native loader result/module GUID | Route kind |
| `prepare.enter` / `prepare.return` | Native module GUID | Provider selector / preparation result |
| `print.enter` | Native module GUID | Preparation result |
| `print.return` | Native module GUID | Native print return value |
| `hook.return` | Native loader result/module GUID | Route kind |

Route kinds are 1=libhttp, 2=libssl, 3=ScePsp2Compat, 4=np_commerce2. Only redirected paths get the load/return markers, so an absent later event does not prove the system stopped loading unrelated modules. Existing sequence, thread, target PID, time and stack-pointer fields remain. Interpret multiple threads and nested calls separately.

An entered print without a returned print narrows the boundary to printing or the return-marker attempt; it is not a captured fault address. A `hook.return` record is emitted BEFORE the C epilogue and does not prove the caller resumed. A returned print plus hook-return record shifts attention to the caller or subsequent work. No module-load/start call is present in this diagnostic, so those operations cannot directly be its failing instruction.

## Recovery and observation limits

Self-disarming still runs before the reporter, logger, hash checks, hook installation or preparation. It changes only its own entry character and requests file/mount synchronization. On the next disabled boot, this module is not selected and its old startup log should remain. Startup and cleanup never re-arm it. Do not modify configuration concurrently with startup.

This does not protect a fault before module_start or before durable self-disarming completes, and does not undo historical system-file replacements. The known removable-file fallback remains an emergency measure, not the routine rollback path. No boot_config, storage driver, CA file or Sony module should be replaced for this test.

The recorder is capped at 512 records of less than 192 bytes. Trace failures refuse further experimental preparation; they do not refuse Sony's underlying load. Logs can be partial and instrumentation changes timing and stack layout. The hook frame is 568 bytes in this build, 16 bytes larger than the prior 552-byte frame; the private hash workspace is retained. These sizes are not measured stack headroom. Preserve the last complete records and any partial tail instead of inferring a successful run from boot survival.
