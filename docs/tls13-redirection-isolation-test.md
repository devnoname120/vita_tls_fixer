# Redirection-only startup diagnostic

This build tests the module-loader hook and path replacement without starting user TLS providers or the DNS helper. It is not a TLS 1.3 functionality test and is not a confirmed fix.

The preceding self-disarm-only and initialization-only builds reached LiveArea by user report. Read-only FTP verified both corresponding kernel identities, their expected disabled entries and unchanged boot/storage configuration. Those observations do not establish all possible startup interleavings or capture individual module_start return codes.

Build separately:

```sh
cmake -S kernel -B build/redirection-only-probe-kernel -G Ninja -DTLS_FIXER_REDIRECTION_ONLY=ON
cmake --build build/redirection-only-probe-kernel
```

The same self-disarm routine runs before startup initialization. Unlike the preceding initialization-only build, this profile installs the normal kernel module-path hook and performs its path replacement. After calling the original loader continuation it returns immediately, before TLS-provider injection, DNS-helper startup or post-load diagnostics. The shared loader implementation remains linked, so the intended claim is that these later operations are not invoked, not that every related function is absent from the binary.

Use only the kernel whose byte count and SHA-256 match this bundle's manifest. Keep the previous initialization-only kernel as an inactive backup. Manually replace the currently disabled removable file at `ux0:/data/tls_fixer-one-shot/tls_fixer.skprx` and change the existing test line's first character from `#` to `u` in `ur0:tai/config.txt`. Do not add another entry or touch boot_config, YAMT, other plugins, CA files or user modules. The agent must retrieve and verify the new kernel and complete configuration before requesting the user's manual reboot. No VPK or installer is used.

After the requested reboot, report whether LiveArea appears and make FTP available. The expected disabled line remains `#x0:/data/tls_fixer-one-shot/tls_fixer.skprx`. Do not try browsers or network-account services with this probe: it deliberately omits user-provider and DNS-helper initialization. A successful boot shifts investigation toward the omitted post-load operations; another failure keeps focus on hook installation and the replacement/load path. Neither observation alone proves the exact faulty instruction or rules out layout/timing effects.

This is a single-use test. Rebooting does not re-enable it, and the agent must never issue a reboot command. Self-disarming cannot protect against failure before module_start or before the persistent edit completes.
