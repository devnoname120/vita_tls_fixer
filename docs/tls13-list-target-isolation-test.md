# Enumeration plus target-query diagnostic

This continues the target-only repeat whose first boot reached LiveArea and whose fresh trace proves two target-info queries succeeded (TLS13_PROGRESS.md section 23.73).

## Question being tested

Does adding the native module-ID enumeration reproduce the failure without retrieving metadata for every enumerated module?

`TLS_FIXER_PREPARE_LIST_TARGET_ONLY=ON` retains the preparation reservation, 4096-byte query workspace, file/hash checks, target PUID/name validation, same-thread native 16384-byte stack, trace and self-disarming. It calls `ksceKernelGetModuleList(pid, 0xff, 1, ids, &count)` once per preparation, validates the returned count, and does not inspect the returned module objects. It still queries only the just-loaded target through `ksceKernelGetModuleInfo`.

The option is restricted in both CMake and source to traced native-stack preparation-only diagnostics. It cannot be combined with the no-query or target-only modes. No TLS provider or DNS helper can be started in this profile. Returning from the diagnostic's omitted presence scan does not establish that no provider is loaded, and must not become a production fallback.

## Comparison limits

This is a newly built diagnostic, not a modified frozen ZIP. Relative to the old frozen target-only payload it also incorporates the previously reviewed startup hook guard and build-time native ABI assertions. The latter contribute no runtime code. The main runtime DNS-helper correction is outside this preparation-only profile. The new startup guard may refuse activation and must be distinguished from a completed enumeration test. Compiler layout, stack frames and time spent logging can change too.

The production build with this option off is byte-identical to the preceding guarded default kernel. Normal presence checking has not been removed.

## Deployment and rollback

Only the exact removable test kernel, its existing one-shot entry, and the pre-existing 256-byte diagnostic result file participate. Preserve a current before-state snapshot, including the parallel yield section. Stage while the entry is disabled, read back each payload, and re-enable only the existing initial path character after verification. Do not replace the full configuration. Leave stock modules, providers, certificates, boot_config, storage and other plugins alone.

Paths:

- `ux0:/data/tls_fixer-one-shot/tls_fixer.skprx`
- `ur0:tai/tls_fixer-disarm-result.txt`
- `ur0:tai/tls_fixer-startup.log` (read after the boot)

The kernel first disables its own future boot entry and synchronizes that change. The normal self-disabled spelling is `#x0:/data/tls_fixer-one-shot/tls_fixer.skprx`; restoring only `u` deliberately arms a subsequent test. This safeguard has worked in prior observed failures. It cannot protect faults before module_start or before the synchronization succeeds, and does not roll back other persistent files. No installer or automatic re-arm is involved.

The user authorized staging. The earlier remote reboot tool call was blocked and is not retried through another route. Once this payload is verified on the device, request one manual reboot and a first-boot observation. Do not count recovery on a second power-on as a successful first boot.

## Required evidence

Preserve the current config, kernel, report and complete log twice through read-only FTP. Require a new log rather than the previous target-only trace.

A completed comparison contains `module.list.enter` / `module.list.return` with result zero and a bounded count, then `module.inspect.skipped`. There must be no `module.info.enter` / `module.info.return` records. The final `target.info` pair and preparation should return successfully. Subsequent SSL loading indicates further progress, not by itself a LiveArea result. Require the user's first-boot observation separately.

If the boot succeeds with this profile, the removed per-module inspection or its interaction/timing becomes the remaining difference from the earlier full scan. If it fails, enumeration or its interaction/timing is implicated; do not call the API intrinsically defective from this test alone. An absent hook/install or query record can instead indicate a rejected startup guard, logger failure or skipped selection.

Do not re-enable automatically after a failure. Keep the next boot disabled and retain all evidence before another decision. Browser TLS acceptance remains separate.
