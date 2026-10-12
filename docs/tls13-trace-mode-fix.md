# Startup trace creation-mode correction

## Evidence from the last device run

The 14109-byte traced preparation kernel reached LiveArea by user report. Its preallocated internal report recorded successful self-disarming and `trace_setup=80010016`; `ur0:tai/tls_fixer-startup.log` did not exist. The full configuration matched the expected one-byte-disabled image. Evidence is preserved in `build/trace-setup-result-146.json` and `build/device-evidence/146-trace-setup-result-20261008T134721Z/`.

That result was not a successful preparation run. Trace setup failure stops this diagnostic before hook installation. It also does not establish the original boot-crash cause.

## Firmware analysis

The existing 3.60 databases were inspected through IDA MCP, without changing the device:

- SceIofilemgr: `ksceIoOpen` at 0xBE04A4 dispatches to the VFS open worker, directly or through the I/O scheduler. `vfsOpen` at 0xBEA704 passes its creation-mode argument to `ksceVopCreate` at 0xBEF894.
- SceExfatfs: the VOP table at 0xCDBC08 places create at 0xCCA69C. It passes the mode to `fun_ConvertExfatModeToAttribute` at 0xCC0000, which calls the SblACMgr mode conversion export (NID 0x6210D745).
- SceSblACMgr: `ksceSblACMgrConvertModeToFsAttribute2` at 0xA8A21C dispatches ordinary filesystem modes to `fun_convertModeToFsAttribute` at 0xA8B350. For access levels 0x40 and 0x80 the latter masks the mode with 0x10186 and searches ten entries at 0xA8C774. A miss returns 0x80010016. The raw instruction scan at 0xA8B35C..0xA8B3A6 confirms the branch, mask and search; the conclusion does not rely only on function names or decompiler types.

The ten `(masked mode, attribute)` pairs are:

```text
00010186 0    00000186 0
00010106 1    00000106 4
00010104 5    00000104 5
00010006 6    00000006 6
00010004 7    00000004 7
```

POSIX-style `0600` is 0x180 and does not match. Vita mode `0006` matches and selects attribute 6. The ordinary access-level table is different; applying Unix permission intuition or a userspace-only mock to the kernel caller was incorrect. No access-level override or permission-check bypass was added.

The old compiled logger passed R1=0x602 and R2=0x180 to ksceIoOpen. The corrected ELF, inspected as `tls_fixer-trace-mode-fixed-elf`, passes the same path and flags with R2=6 at 0x81001950, followed by the call at 0x8100195A.

## Correction and regression

Only the logger's creation-mode argument changes in production code, from `0600` to `0006`. Its path, open flags, synchronization, bounded records, independent setup-result reporting, startup ordering and preparation-only scope are unchanged.

The boot-trace test's mock now applies the recovered privileged-mode mask and accepted-mode set instead of asserting that the old 0600 argument was correct. Running the old logger against that fixture failed its successful-open assertion with exit 134 (`build/trace-mode-red.log`). The corrected logger passed. Full normal and ASan/UBSan/leak-checking runs each passed all 64 CTest targets; all 17 Python tests passed. The clean kernel build passes the decoded FP/SIMD instruction check and has no unresolved symbols or module load/start/unload symbols. Verification: `build/trace-mode-verification.log`.

Kernel: `build/trace-mode-kernel/tls_fixer.skprx`, 14108 bytes, SHA-256 `3e49a746c6a693c7c8ecf5485d93a5d9064ec595623010044a417aec42602ff1`.

## Next diagnostic, not a finished TLS release

Do not use any old VPK or full-refresh operation. Preserve the currently disabled kernel, internal result file and any previous startup log before another test. Stage only this kernel and the supplied 256-byte PENDING report at:

```text
ux0:/data/tls_fixer-one-shot/tls_fixer.skprx
ur0:tai/tls_fixer-disarm-result.txt
```

Restore only the existing test entry's first character, from `#x0:/data/tls_fixer-one-shot/tls_fixer.skprx` to `ux0:/data/tls_fixer-one-shot/tls_fixer.skprx`. Do not add another entry or change any other configuration. Leave FTP available and wait for a complete read-back check before the user performs a manual reboot.

A successful setup should record `trace_setup=00000000` and produce `ur0:tai/tls_fixer-startup.log`. Preserve the report, log, config and exact kernel before any re-enable, even if boot fails. Self-disarming remains first; an ordinary subsequent power-on has skipped the experiment in prior observed failures. It cannot cover faults before the disarming writes finish, and this change does not restore overwritten system files.

This fixes an invalid logger argument established by firmware inspection and regression testing. Hardware confirmation of log creation is still required. The underlying preparation crash remains unresolved; do not alter its behavior at the same time. A final entered stage without a returned record narrows the next investigation but does not alone establish a faulting instruction. Reaching LiveArea without the trace is not evidence that preparation executed.
