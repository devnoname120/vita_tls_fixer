# tls_fixer native extended-stack preparation diagnostic

## Question tested

The reduced-buffer preparation run still failed after its checks, cleanup, printing and the following SSL load returned. Its smallest recorded headroom was 2784 bytes. That is not a high-water measurement: native module/file operations and synchronization use additional stack between records. It does not prove either an overflow or adequate headroom throughout execution.

This diagnostic asks the native OS to run the same preparation work with a 16384-byte stack. It retains the per-call query/hash workspaces, actual native module checks, exact file hashes and returned-operation tracing. It does not start TLS or DNS providers, change the HTTP implementation, or declare the boot defect fixed.

## Native service and contract

The build calls `ksceKernelRunWithStack(SceSize, int (*)(void *), void *)`, as declared by the VitaSDK kernel thread interface. The existing 3.60 ThreadMgr database was inspected through IDA: the stack service at 0xBA34EC checks the available stack, allocates or reuses a stack region, updates current-thread stack metadata, invokes its callback synchronously, and restores/frees the region afterward. Its trampoline at 0xBA004A preserves the original SP, switches SP, calls the callback with its argument, and restores SP. This is a same-thread OS service, not an agent-written stack pivot or an extra worker thread.

The public declaration is documented at https://docs.vitasdk.org/group__SceThreadMgrKernel.html. A separate SDK archive-extraction inspection was blocked by tooling and was not rerun through another route; the native behavioral review above came from successful IDA queries. The actual stack-service path on this Vita must still be established from the new device records.

`TLS_FIXER_PREPARE_EXTENDED_STACK=ON` is restricted to preparation-only diagnostics with both boot trace and native headroom reporting. The default build does not call the service. The callback stores the preparation result in a caller-owned context and returns zero to the native runner; runner errors and preparation errors are handled separately. A failed runner, missing callback, or failed trace is an error. There is no fallback that repeats preparation on the original small stack.

New markers are stack.extend.enter/return on the caller stack and stack.callback.enter/return around work on the native-managed stack. Existing thread IDs, free= samples, query/hash events, cleanup and hook return remain. The native runner is synchronous, so the small caller-owned context remains live until the callback finishes. It is not retained or queued.

## Verification

All 84 normal and 84 ASan/UBSan/leak-checking CTest targets pass, plus 17 Python tests. The new regression failed before the dispatch wrapper. Tests cover runner failure before the callback, success without invoking it, an error after callback completion, preparation failure, no small-stack retry, resource cleanup and trace failures. Host mocks verify the call contract, not a physical stack switch.

The diagnostic and default kernels build and pass the decoded FP/SIMD and unresolved-symbol checks. The diagnostic imports no module load/start/unload or thread-creation function. The default build has no RunWithStack symbol. An invalid extended-stack CMake configuration is rejected as expected.

Fresh IDA inspection confirms the compiled wrapper passes 0x4000 in R0, the Thumb callback in R1 and its context in R2, then checks the native return and callback status without a fallback path. The callback contains the same preparation operations. These are static/build results, not a successful device boot.

## Manual staging and test

Keep the present disabled configuration and preserve the previous kernel/report/log before copying. Do not use any old VPK or full-refresh installer.

| Archive member | Destination |
| --- | --- |
| tls_fixer.skprx | ux0:/data/tls_fixer-one-shot/tls_fixer.skprx |
| tls_fixer-disarm-result.txt | ur0:/tai/tls_fixer-disarm-result.txt |

Use this archive's fresh 256-byte PENDING report. Restore only the first character of the existing `#x0:/data/tls_fixer-one-shot/tls_fixer.skprx` line to `u` in `ur0:tai/config.txt`. Close the editor and computer FTP client, leave the Vita FTP server available, and report completion. Wait for read-only verification before the requested manual reboot.

After verification, perform one normal manual reboot with the card inserted, no L, no installer and no browser test. Report the real sequence, including any freeze/shutdown and recovery power-on. Do not re-enable a failed experiment.

## Evidence required

Retrieve the tested kernel, full config, gate/report and complete startup log before another activation. A successful stack-service return without callback records is not successful preparation. Require actual callback entry, substantially increased free= values in the same thread, completed preparation and cleanup, callback return, native-runner return, and subsequent native loads. A clean boot caused by rejecting the operation is not evidence that larger-stack preparation works.

A failure with ample measured headroom would weaken the simple stack-budget explanation and shift the investigation toward other native-call effects, calling context or timing. A success would support the change but would not identify the previous fault instruction or justify enabling full provider loading immediately. Logger I/O still changes timing and samples are not high-water marks.

Self-disarming remains first and unchanged, before this optional diagnostic service. It disables the following boot after successful synchronization, not a fault before module_start/disarming or a rollback of historical file replacements. Leave boot_config, YAMT, other plugins, certificates and Sony modules untouched. Every reboot is manual.
