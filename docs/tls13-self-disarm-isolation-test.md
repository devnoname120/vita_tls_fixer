# Self-disarm-only boot isolation diagnostic

## Purpose

The full experimental kernel froze the primary Vita at the warning screen on 2026-10-08. Its config edit survived, and the following power-on reached LiveArea with tls_fixer disabled. This verifies the next-boot safeguard for that failure, not that module_start finished or that the TLS loader is safe.

This alternative build of the same tls_fixer kernel plugin calls the unchanged self-disarm routine and returns immediately. It performs no logging, replacement-file queries, module hooks or TLS-provider injection. The loader and path-adapter translation units and their stub libraries are excluded from the diagnostic link. No separate loader, launcher or permission file is introduced.

Build only in a separate directory:

```sh
cmake -S kernel -B build/self-disarm-probe-kernel -G Ninja -DTLS_FIXER_SELF_DISARM_ONLY=ON
cmake --build build/self-disarm-probe-kernel
```

Use the corresponding manifest to identify the kernel. Do not substitute the full kernel, a prior timestamped staging copy, or any TLS13 VPK. The minimal probe cannot provide TLS 1.3.

## Approval and deployment boundary

At preparation time the probe exists only on the computer. No replacement of the Vita's staged file, re-enabling, module loading or reboot is authorized by building it.

Before any later approved test, retrieve the current primary configuration and confirm that the former test entry is still disabled. Preserve that exact current file and the staged kernel on the computer and in inactive device backups. Leave boot_config, storage drivers/settings, FTP plugins, CA files and user modules untouched.

With explicit approval, place only the diagnostic kernel at the same fixed removable path `ux0:/data/tls_fixer-one-shot/tls_fixer.skprx`, verify the transferred hash, and restore its single boot line to that exact full path. The self-disarm result is `#x0:/data/tls_fixer-one-shot/tls_fixer.skprx`; removing only the '#' is not a correct way to re-enable it. Do not add a duplicate entry.

The user, not the deployment script, performs the approved normal reboot. If LiveArea returns, check FTP and the entire configuration against the expected one-byte self-comment. Do not start website tests: this diagnostic has no TLS transport hooks.

## Interpret the result

- A completed boot with the expected comment is evidence that the self-disarm-only path can complete in that tested environment. It shifts investigation to initialization, hook installation and injection present only in the full build; it does not identify which of those fails.
- Another freeze means later TLS routing/injection is not required for that failure. Preserve evidence and investigate the shared loading/self-disarm/return path rather than adding more TLS changes.
- A missing or unexpected config edit is not a successful test, even if the device boots.

No outcome automatically re-enables the plugin. Any further attempt, including a post-crash boot, remains a deliberate user action. The established safeguard cannot cover failure before module_start or before its disarming edit completes. Do not replace that limitation with a claim of guaranteed recovery.
