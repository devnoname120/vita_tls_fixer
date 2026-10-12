# tls_fixer startup self-disarm: first device test

## Scope

This bundle contains the revised **kernel plugin only**, its checksums, and local verification evidence. It is not a full-refresh installer. Do not run any earlier TLS13 VPK or use its SQUARE refresh instructions for this test.

The first test checks that the plugin disables its own next startup and that an ordinary subsequent reboot reaches LiveArea with storage and applications available. Browser TLS testing comes after that check. The kernel still contains the existing routing/injection code; this is not a harmless simulation of that code. Self-disarming runs before it.

No new device configuration is provided in this bundle. The recovered Vita's actual current state must be read and preserved instead of restoring a stale pre-recovery configuration. Receiving or unpacking this archive does not install or enable anything.

## Before activation

Use the usual FTP server to inspect the recovered primary Vita after explicit approval for this operation. Record and back up the current `ur0:tai/config.txt`, any `ux0:tai/config.txt`, and any existing `ur0:tai/tls_fixer.skprx`. Preserve their contents on the computer and on the Vita under distinct backup names. Do not use the earlier pre-crash snapshot as a substitute for this new snapshot.

Check whether the active tls_fixer kernel entry exists and where it points. The revised test path is `ux0:/data/tls_fixer-one-shot/tls_fixer.skprx`, referenced by `ur0:tai/config.txt`. Verify that ux0 is the intended removable storage before activation. The build recognizes this exact path (with or without the slash following the colon) as well as the legacy `ur0:tai/tls_fixer.skprx` and `ur0:/tai/tls_fixer.skprx` entries. An alternate enabled path or a different active configuration must be resolved before proceeding; do not add duplicate entries or replace the full taiHEN configuration.

Leave `boot_config.txt`, YAMT, all other plugins, the CA store, Sony HTTP/SSL/compatibility modules and both existing user TLS providers unchanged. Missing or mismatched optional TLS resources can disable provider activation without preventing the self-disarm check. Do not deploy those resources merely to make the first boot-safety check pass.

Stage the revised `tls_fixer.skprx` at the exact ux0 test path and verify its SHA-256 after download/read-back. Do not put it in ur0:tai. Only after separate one-boot activation approval should its own exact KERNEL entry be deliberately enabled in the internal config. The earlier timestamped staging directory contains the older ur0-only self-disarm build; do not enable that copy through an ux0 path. Do not hot-load or hot-unload the plugin. There must be no automated re-enabling process running during the test.

## Boot 1: consume the boot entry

Reboot normally once after approved activation. Do not launch the tls_fixer installer or begin browser testing immediately.

If LiveArea appears, restart FTP and retrieve both applicable taiHEN configurations. The enabled line should now be commented. The implementation intentionally changes only one byte:

```text
ux0:/data/tls_fixer-one-shot/tls_fixer.skprx
```

becomes:

```text
#x0:/data/tls_fixer-one-shot/tls_fixer.skprx
```

The no-slash variant becomes `#x0:data/tls_fixer-one-shot/tls_fixer.skprx`. Legacy ur0 paths, if present, are disabled too. The unusual comment spelling is deliberate: no line insertion, file truncation or whole-config replacement is required. All duplicate matching entries are commented. A later explicit re-enable must restore the original path, not simply delete the `#`.

Compare the entire file against the pre-test snapshot: only the intended tls_fixer path-character replacements are allowed. Verify the current kernel file against the bundle checksum too. A normal boot alone is not evidence that the tested kernel was selected or that disarming occurred.

If the expected disabled entries are absent, or unrelated bytes changed, stop and preserve the observed files. Do not re-enable or reinstall in response to missing evidence.

## Boot 2: verify ordinary reboot recovery

Without enabling tls_fixer again or running its installer, reboot normally a second time. Confirm that LiveArea, applications and SD2Vita are available. Retrieve the configuration again and confirm that the tls_fixer entries remain disabled. This is the acceptance check for normal two-boot selection behavior; it does not prove physical crash durability under every possible fault.

If Boot 1 crashes after successful disarming, an ordinary power cycle is expected to skip the plugin. No intentional hard crash should be introduced before ordinary disarming has been observed. Report an unexpected crash rather than repeatedly re-enabling the plugin or installing a different package.

## Only then: a separate TLS attempt

The two-boot check ends with the experimental plugin disabled. TLS testing therefore requires a separately approved one-boot re-enable, validation of the existing user providers and module identities, and protocol evidence from the browser/server. A page loading during the disabled second boot does not demonstrate the new TLS backend.

The second boot does not automatically restore or enable the previous tls_fixer kernel. Its backed-up file remains available. This test intentionally disables the experiment rather than rewriting other system resources.

## Verification and limits

Local verification passes 30/30 native CTest targets, 30/30 ASan/UBSan/leak-checking targets and 17 Python tests. The final linked kernel passes its FP/SIMD instruction check and has no unresolved ELF symbols. IDA confirmed that the compiled entry calls self-disarm before logging, module queries, hooks and injection. These are host/static results, not device acceptance results.

The startup gate aborts on allocation, configuration access, positional write, synchronization, close or read-back failure. It never re-enables its own entry. Configuration absence is not permission to activate. An inaccessible alternate configuration also prevents activation rather than assuming it is safe.

Self-removal cannot protect a failure while the module is being loaded or before the disarming writes finish. A successful read-back alone is not proof of power-loss durability; the implementation also requests file and mount synchronization, whose physical crash behavior still requires device evidence. This does not repair the original boot-crash diagnosis, undo already overwritten system files, or make the older test packages safe.

Keeping the active test file on the removable card provides a separate fallback for a failure before self-disarming. With the Vita powered off, deleting or renaming only `data/tls_fixer-one-shot/tls_fixer.skprx` using a card reader prevents that test copy from loading. Reinsert the card afterward so its applications remain available. Booting with the entire card absent also makes this copy unavailable, but may hide applications or change mounts; do not format or reset storage in response. This fallback assumes the configured ux0 path really resides on that card and no other copy is activated elsewhere.
