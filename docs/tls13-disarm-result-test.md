# Self-disarm result diagnostic

This diagnostic resolves why both preparation-trace builds reached LiveArea without creating a log. A commented boot entry proves the write occurred; it does not prove that later synchronization, verification, alternate-config checks or cleanup succeeded.

## Exact scope

Build with `TLS_FIXER_DISARM_RESULT_ONLY=ON`. The entry attempts the same fail-closed self-disarm, captures its first failing stage and native result, then writes a fixed-size report. It never performs module inventory, hash checks, loader initialization, hook installation or TLS-provider startup, whether self-disarm succeeds or fails. Failure is not converted into authorization for those operations.

The reporter opens only the existing 256-byte file `ur0:tai/tls_fixer-disarm-result.txt` for read/write, verifies its size, writes through positional calls, requests synchronization, and closes it. It never creates or truncates that file. The host prepares a uniquely timestamped PENDING record before the test, retaining any prior report. This removes file creation during boot from the observation path. The report is diagnostic data, not a permission/arming file.

## Deployment and test

Preserve the current disabled taiHEN configuration, prior removable kernel, existing report, boot_config, YAMT configuration/modules and internal FTP modules. Do not substitute a pre-recovery configuration. Keep the kernel at `ux0:/data/tls_fixer-one-shot/tls_fixer.skprx` and use only its existing KERNEL entry in `ur0:tai/config.txt`.

Prepare the 256-byte report under an inactive temporary name and verify its read-back before publishing it. Stage and verify the new kernel while its entry remains disabled, retain the previous kernel under an inactive name, and only then restore the single entry character from `#` to `u`. Verify the full config and protected files. No VPK, CA-store update, stock-module replacement or storage change belongs in this test.

After the agent verifies staging, the user performs one normal manual reboot with the card inserted. Do not hold L, run an installer or begin a browser/TLS test. Report LiveArea or failure and leave FTP available. The next agent action is read-only collection of the report, config and exact kernel before any re-enable. The startup routine never re-arms itself.

## Interpretation

A complete report begins with `TLS_FIXER-DISARM-RESULT v1` and ends with `END` in the final four bytes. All numbers are eight-digit hexadecimal, including signed result bit patterns. Fields are outcome, native code, config index, completed one-byte writes, fully verified configurations, memory-cleanup result and stage.

- `stage=gate.complete` and `outcome=00000000` mean the gate returned success in this run, not that any TLS code ran.
- A nonzero outcome identifies the first observed failure. Config index 0 is ur0 and 1 is ux0; ffffffff denotes an operation outside a specific config.
- `writes` can be nonzero while `verified` is zero. The boot line can therefore be commented despite the gate refusing activation.
- An unchanged PENDING record or incomplete record does not establish a gate outcome. Reporter open/write/sync failure, failure before reporting, or failure to select this kernel remain possible.

The reporter's own synchronization failure may leave a readable record. Reading the record is evidence of its contents, not proof of power-loss durability. Compare the entire configuration separately. The successful automatic skip seen in an earlier crash remains an observation of that event, not a guarantee for faults before entry or before self-disarming finishes.

## Local verification

The report and entry regressions reproduced the missing behavior before implementation. The subsequent full run passed 63 normal CTest cases, 63 ASan/UBSan/leak-checking cases and 17 Python tests. Diagnostic and full kernel builds passed the decoded FP/SIMD gate and unresolved-symbol checks. The diagnostic has no hook, provider loader or module load/start symbols. A fresh IDA request returned HTTP 502; generated entry order was checked in the build's disassembly instead, without claiming a new successful firmware analysis.
