# tls_fixer traced redirection-only control

## Why this control is needed

The preceding return-path diagnostic crashed even though its log recorded successful preparation, a returned kernel print, the HTTP hook's exit, and a subsequent successful SSL load and hook exit. That result does not implicate the last logged operation as the faulting instruction.

Earlier redirection-only boots lacked reliable telemetry. They could have reached LiveArea because startup refused to install the hook. This control uses the now-working gate report and logger, but removes all post-load preparation from the runtime hook. It preserves startup self-disarming, initial file checks and loader initialization, the path-redirection hook, and the native-load entry/return records. No provider scan, post-load rehash, target-info lookup, post-preparation printing, TLS-provider startup or DNS-helper startup occurs in the hook. Preparation/injection routines are excluded from this control's compilation, not merely left as unused code.

This is a baseline measurement, not a fixed TLS build. Removing preparation also changes stack usage and timing, so a successful control would localize the difference without identifying an exact defective instruction. The compiled hook frame is 296 bytes, compared with 568 bytes in the failed preparation diagnostic.

## Verification performed locally

All 65 normal and 65 ASan/UBSan/leak-checking CTest targets pass, as do 17 Python tests. The production-route tests assert native-call ordering, load/return trace fields, no preparation/printing, preservation of native errors and arguments, and marker-failure behavior. Logging failure must never skip the underlying Sony load or change its result.

The kernel builds and passes the decoded FP/SIMD and unresolved-symbol checks. Its symbol inventory has no preparation/injection function or module load/start/unload import. The ordinary non-control kernel also builds. These are host/static results; the device outcome is still unknown.

## Manual preparation

Do not use an earlier VPK or refresh the installed tls_fixer application. Preserve the current kernel, report and startup log first. Copy only the two inputs in this archive:

| Archive member | Device destination |
| --- | --- |
| `tls_fixer.skprx` | `ux0:/data/tls_fixer-one-shot/tls_fixer.skprx` |
| `tls_fixer-disarm-result.txt` | `ur0:/tai/tls_fixer-disarm-result.txt` |

The manifest and SHA256SUMS identify the exact files. The report must be the fresh 256-byte PENDING record, not the previous successful setup report.

In `ur0:tai/config.txt`, restore only the initial character of the existing line from `#x0:/data/tls_fixer-one-shot/tls_fixer.skprx` to `ux0:/data/tls_fixer-one-shot/tls_fixer.skprx`. Do not delete the character, duplicate the line or change another entry.

Close the editor, disconnect the computer FTP client and leave the Vita FTP server available. Report completion and wait for read-only verification of the files and complete configuration before any reboot. Every reboot remains manual.

## Test and evidence

After verification and a request to test, reboot normally once with the card inserted, without L and without launching the installer or browser. Report whether LiveArea appears directly or the warning screen freezes/power is lost. Do not re-enable the control after a failure. Preserve the sequence if a following ordinary power-on recovers.

Retrieve `ur0:tai/tls_fixer-disarm-result.txt`, `ur0:tai/tls_fixer-startup.log`, the whole config and the tested kernel before any further activation. A valid control needs successful gate/logger results, a returned hook-installation record and actual redirected-load events. Merely reaching LiveArea is insufficient.

Expected hook records are `load.enter`, `load.return` and `hook.return`. Route kinds are 1=HTTP, 2=SSL, 3=browser compatibility, 4=commerce. There should be no runtime `prepare.enter`, `scan.enter` or `print.enter` events. Initial startup checks and loader initialization remain. `hook.return` precedes the C epilogue and does not prove the caller resumed; unrelated loads are not logged. Trace bounds/failure and partial records must be considered.

Self-disabling remains first and never re-arms the module. It protects the following boot after its config edits synchronize successfully, not faults before module_start or before synchronization. It does not undo historical system-file changes. Leave boot_config, YAMT, internal FTP plugins, CA files and Sony modules untouched.
