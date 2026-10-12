# Hash workspace diagnostic

## Change being tested

The previous hash-substage run ended abnormally after `hash.stat.return` with result 0. It produced no `hash.open.enter` record from the hash worker. That worker used a 1200-byte stack frame. This makes stack pressure a specific hypothesis, not a captured fault address or a proven stack overflow.

The new kernel keeps the preparation-only scope and moves the 1024-byte file buffer plus SHA-256 context into a private, per-call 4096-byte kernel memory block. It validates allocation and base retrieval, closes the file and frees the workspace on every applicable return path. Errors refuse acceptance of the file. No shared workspace or extra mutex was introduced. The file format, expected hashes, SHA-256 algorithm and read-buffer size are unchanged.

The checked diagnostic ELF now uses a 48-byte hash-worker frame: nine saved registers (36 bytes) plus 12 bytes of local storage. IDA confirmed this at 0x81001A38..0x81001A3E. Other caller frames remain; this is not a complete kernel-stack budget proof.

Self-disarming remains the first startup operation. The build contains no provider module load/start/unload calls. It is not a TLS functionality test or a replacement installer.

## Manual staging

The archive manifest identifies the exact kernel and report. Do not use an earlier similarly named ZIP. Preserve the currently disabled kernel, `ur0:tai/tls_fixer-disarm-result.txt`, and `ur0:tai/tls_fixer-startup.log` before overwriting them.

Copy only:

- `tls_fixer.skprx` to `ux0:/data/tls_fixer-one-shot/tls_fixer.skprx`.
- `tls_fixer-disarm-result.txt` to `ur0:tai/tls_fixer-disarm-result.txt`.

In `ur0:tai/config.txt`, restore only the first character of the existing test line from `#` to `u`:

```text
#x0:/data/tls_fixer-one-shot/tls_fixer.skprx
```

becomes:

```text
ux0:/data/tls_fixer-one-shot/tls_fixer.skprx
```

Do not add another entry, edit any other plugin, run an installer, or change boot_config, YAMT, CA files or Sony modules. Do not hot-load the kernel.

Stop before rebooting, keep FTP available on .146:1337, and report that copying/editing is done. Read-only verification must confirm both new file hashes, the exact single-character config change, and unchanged protected files before the manual reboot request.

## One manual boot

After verification, reboot normally once with the card inserted and without holding L. Report a freeze, shutdown, improper-power-off warning or any uncertainty about the outcome exactly; reaching LiveArea on a later power-on is not a clean first-boot result. Do not run the browser test or re-enable the entry again.

Leave FTP available so the complete report, config, kernel and startup log can be retrieved before further changes. The entry should again start with `#x0:`. If a failure occurs after successful disarming, the subsequent ordinary power-on should skip this diagnostic, as already observed in earlier failures. Faults before self-disarming finishes remain outside that protection.

## Interpreting the trace

New records bracket `hash.alloc`, `hash.base` and `hash.free`. The desired path reaches `hash.open`, `hash.stream`, `hash.finish`, `hash.close`, `hash.free`, `hash.compare` and `hash.return`, followed by the target module-info and cleanup records. Match thread, PID and module identifiers rather than combining concurrent traces. Native allocation/file IDs need not be zero; a successful comparison is zero and the outer `hash.return` match flag is one.

The independent 256-byte result must show gate completion and `trace_setup=00000000`. A missing/incomplete trace, logger refusal or failed hash does not count as successful preparation. Even a complete preparation path does not establish full TLS-provider startup or browser TLS 1.3.

## Local verification

The source passed 64/64 normal and 64/64 ASan/UBSan/leak-checking CTest targets and 17 Python tests. Traced and default kernels cross-build with no decoded FP/SIMD instructions; the diagnostic has no unresolved or module load/start/unload symbols. Tests exercise workspace ownership, allocation failure, failed/null base retrieval, failed cleanup, descriptor cleanup and bounded trace volume. These are host/static results, not the outcome of this hardware test.
