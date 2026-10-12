# Preparation hash-substage diagnostic

## What the preceding run established

The corrected logger ran on the primary Vita. The result report recorded `stage=gate.complete` and `trace_setup=00000000`. The 9374-byte startup log contains 71 complete records: startup, hook installation, reservation, module listing and all 28 module-information queries returned; the final record is `hash.enter`, without `hash.return`.

The user reported another warning-screen freeze/crash and a subsequent power-on. FTP confirmed the exact self-disabled configuration and unchanged boot_config/YAMT configuration. Evidence is preserved under `build/device-evidence/146-trace-mode-crash-20261008T150053Z/` and `build/trace-mode-result-146.json`. This establishes working diagnostics, not a repaired preparation path.

## Scope of this build

This is still a self-disarming, preparation-only kernel. It adds entered/returned markers around the provider-file stat, target-file open, SHA initialization, first read and update, streaming as a whole, finalization, close and digest comparison. It does not start either TLS provider or the DNS helper. The SHA implementation, expected hashes, 1024-byte buffer, filesystem paths and read flags are unchanged.

The markers are confined to post-load rechecks. Initialization-time hashes do not consume separate trace records. Only the first read/update pair receives per-block records, so a large file does not exhaust the 512-record budget merely because it needs many reads. If an entered/returned marker cannot be written, further preparation is refused and an already-open descriptor is still closed.

A hash substage ordering regression failed against the previous implementation before these markers were added. The corrected tests cover every new trace-failure boundary and descriptor cleanup. A 4096-block mock stream verifies bounded marker count. Full normal and sanitizer suites pass all 64 targets, and all 17 Python tests pass. Separate traced and default kernel builds pass the generated-instruction gate and have no unresolved symbols; the traced diagnostic has no module load/start/unload symbols. Logs: `build/hash-stages-verification.log`, `build/hash-stages-binary-review.log`.

Kernel: **14943 bytes**, SHA-256:

```text
0e20d35c90b643dbca30d948ee39bbf8f990b662d24e1ee43104dbd715b40279
```

## Manual staging

Do not use any VPK or the full-refresh installer. Preserve the current kernel, `tls_fixer-disarm-result.txt`, and especially the existing `tls_fixer-startup.log` under inactive backup names before staging. Their previous copies have also been retained on the computer.

Copy only these files from this ZIP:

```text
tls_fixer.skprx -> ux0:/data/tls_fixer-one-shot/tls_fixer.skprx
tls_fixer-disarm-result.txt -> ur0:tai/tls_fixer-disarm-result.txt
```

The supplied report is 256 bytes and starts with PENDING. It is output storage, not an arming token. In `ur0:tai/config.txt`, restore only the existing test entry's first character, changing `#x0:/data/tls_fixer-one-shot/tls_fixer.skprx` to `ux0:/data/tls_fixer-one-shot/tls_fixer.skprx`. Do not add another entry or edit unrelated settings.

Stop before rebooting, leave FTP available and report that copying/editing is complete. A read-only full-file verification must precede the requested manual reboot. Keep the card inserted. Do not hold L, run the installer or begin browser/TLS testing for this diagnostic.

## Evidence to collect after the user-operated boot

Retrieve and preserve:

```text
ur0:tai/tls_fixer-disarm-result.txt
ur0:tai/tls_fixer-startup.log
ur0:tai/config.txt
ux0:/data/tls_fixer-one-shot/tls_fixer.skprx
```

Do not re-enable in response to a failure. The self-disabling entry is expected to allow an ordinary subsequent power-on to skip the experiment once its writes have synchronized; that behavior was observed in preceding failures. It does not protect faults before disarming finishes or restore overwritten system files.

The final entered operation without a matching return narrows the next investigation. It does not necessarily identify the faulting instruction: logging itself adds calls and changes compiler layout/timing. The previous generated recheck frame was 1224 bytes; this diagnostic's hash worker frame is 1200 bytes. Neither number establishes the actual thread stack limit. No stack-overflow diagnosis, successful hash recheck or TLS support is claimed before hardware evidence.
