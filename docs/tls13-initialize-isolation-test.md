# Initialization-only boot diagnostic

This is a startup isolation build, not a TLS test or a demonstrated crash fix.

The preceding self-disarm-only diagnostic reportedly reached LiveArea. Post-boot configuration verification is still required before the next activation. A successful boot by itself does not prove that module_start returned success rather than refusing activation; preserve that distinction.

Build in its own directory:

```sh
cmake -S kernel -B build/initialize-only-probe-kernel -G Ninja -DTLS_FIXER_INITIALIZE_ONLY=ON
cmake --build build/initialize-only-probe-kernel
```

This profile retains the unchanged self-disarm-first entry. It then performs the original startup logging, replacement-file checks, exact module-file hashing and loader mutex initialization, and returns before module lookup/hook installation. No module-loader hook is installed and no TLS provider is started. The shared loader translation unit remains linked; do not describe this as a binary without any injection-related code. The path/redirection translation unit is not linked and the unreferenced static load hook is eliminated in the checked build.

The SELF_DISARM_ONLY and INITIALIZE_ONLY options are mutually exclusive. Neither option changes the default full kernel behavior or makes that full build safe to deploy.

## Controlled comparison

Only proceed after retrieving the current disabled configuration and verifying the previous result. The standing user permission covers staging this diagnostic at `ux0:/data/tls_fixer-one-shot/tls_fixer.skprx` and deliberately enabling its single entry; every reboot is manual. Preserve the current kernel and configuration in inactive backups, retain the exact current boot/storage/FTP state, verify the new file against its manifest, and restore only the existing comment's initial character from `#` to `u`.

The expected post-start line is again `#x0:/data/tls_fixer-one-shot/tls_fixer.skprx`. Do not run a VPK, modify the CA store, restore an old whole configuration, or begin browser tests. After the user's approved boot, retrieve the whole config and record the kernel identity and outcome before deciding on another diagnostic.

A completed boot shifts attention toward hook installation and runtime injection in the full build; it does not prove which later operation fails or exclude layout/timing-dependent effects. A failure means module-loader hooks are not required for this failure and calls for examining the retained initialization path. Both outcomes leave the entry disabled if self-disarming succeeded. The safeguard cannot cover faults before module_start or before the persisted edit completes.
