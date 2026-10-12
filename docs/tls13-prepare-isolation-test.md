# Provider-preparation-only diagnostic

This build tests post-load preparation without calling module load/start. It is an isolation diagnostic, not TLS 1.3 functionality or a demonstrated fix.

The preceding redirection-only build reached LiveArea by user report and its exact self-disabled config was retrieved. The full build still fails during boot. This profile adds back the in-flight reservation, module-list scan, file hash recheck and target module-info/PUID validation, then releases the reservation without loading a provider. The DNS helper startup is also skipped. The generated kernel has no ksceKernelLoadStartModuleForPid or ksceKernelUnloadModuleForPid symbol.

Build separately:

```sh
cmake -S kernel -B build/prepare-only-probe-kernel -G Ninja -DTLS_FIXER_PREPARE_ONLY=ON
cmake --build build/prepare-only-probe-kernel
```

The same self-disarm-first routine remains mandatory and the path hook stays active. Only one diagnostic profile may be selected. Default full-mode behavior is not repaired by adding this diagnostic.

Preserve the previous 9030-byte redirection-only kernel in an inactive backup. Use the new kernel identified by this archive's manifest at `ux0:/data/tls_fixer-one-shot/tls_fixer.skprx`. Re-enable only the existing line in `ur0:tai/config.txt` by replacing its initial `#` with `u`, then leave FTP running for a read-only verification of the complete configuration and transferred binary. Do not reboot until that verification passes and the agent requests the user's manual reboot. Do not use a VPK, installer, new plugin entry, changed CA bundle, boot_config or storage configuration.

After the manual reboot, report LiveArea versus failure and make FTP available. The expected self-disabled line is `#x0:/data/tls_fixer-one-shot/tls_fixer.skprx`. A successful boot shifts attention toward the omitted load/start call and provider initialization, but does not prove that every prerequisite succeeded or exclude layout/timing effects. A failure before any provider start directs attention to the retained preparation, locking, module query and hash path instead. Preserve exact identities and read-back results before another test.

This profile must not be used for browser TLS tests: it intentionally does not start either TLS provider or the shell DNS helper. Rebooting never re-arms it. The agent never issues a reboot command; all reboots remain manual. The self-disarm safeguard still cannot cover a fault before module_start or before its persistent edit completes.
