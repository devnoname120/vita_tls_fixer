# One-shot browser TLS activation

## Scope

This is the first browser-only activation profile after the successful name-query preparation test. It is not a full-refresh installer and is not a release validation. The old full-system VPKs remain withdrawn.

The kernel keeps the existing module path redirection but never starts the SceHttp TLS provider or DNS helper in this profile. Only loading the exact supported ScePsp2Compat can trigger user-provider startup. The named target/provider checks, native PUID validation, module hash/signature gates, native-managed 16 KiB stack and startup self-disarming remain. It uses the browser provider and CA file already on the device; neither is replaced by this test.

Self-disarming consumes and synchronizes the boot entry before trace setup, hooks or injection. It disables the next boot, not the current session. Do not reboot again between a successful first boot and the requested browser test: that would remove the experimental kernel from the session. Failures before disarming completes remain outside this protection.

## Build

```text
TLS_FIXER_BROWSER_ACTIVATION=ON
TLS_FIXER_PREPARE_ONLY=OFF
TLS_FIXER_PREPARE_NAME_QUERY=ON
TLS_FIXER_PREPARE_EXTENDED_STACK=ON
TLS_FIXER_ENABLE_BOOT_TRACE=ON
TLS_FIXER_STACK_HEADROOM=ON
```

CMake/source guards reject mixed preparation/omission profiles. The default kernel is byte-compared with its unchanged baseline. The activation regression checks the real loader's start arguments and namespace, absent/present provider results, failed lookups, failed diagnostics, native load errors and retained resident hooks after post-start logging failure. Separate route tests forbid application or DNS startup. The module-manager load/start worker was inspected in the 3.60 IDA database before use; its status is not the same thing as successful TLS-hook activation.

## Preparation

Read and preserve the current disabled config, kernel, result, trace and protected boot/YAMT/FTP files. Preserve the parallel yield section exactly. Verify the installed compatibility module, browser provider and CA bytes against the known supported artifacts. Do not overwrite those system resources or install a VPK.

Publish only the kernel at `ux0:/data/tls_fixer-one-shot/tls_fixer.skprx` and a fresh 256-byte result at `ur0:/tai/tls_fixer-disarm-result.txt`, retaining the previous successful control under an inactive filename. Restore only the existing boot entry's first character from `#` to `u`. Read the entire config, kernel and result back and check every protected file before asking for the single manual reboot. Do not race another config save.

## First boot

Ask the user for one normal manual first boot, card inserted, no L and no installer. Do not retry the previously tool-blocked remote reboot by another method. Require a first-boot observation; later FTP connectivity does not distinguish success from recovery after a crash.

After LiveArea, retrieve the config and fresh kernel trace. Confirm the exact self-disabled config, report transition and kernel identity. The browser has not yet been opened, so provider startup records may legitimately be absent. Do not interpret that as TLS success.

If boot crashes, leave the entry disabled and preserve evidence. No automatic re-enable or crash loop is allowed.

## Browser test in the same session

Once the first-boot state is verified, ask the user to open a fresh browser session and visit a protocol-reporting HTTPS diagnostic page. A normal public page loading is not proof of TLS 1.3. Do not bypass certificate warnings or disable verification. Keep the device date and time correct.

The first evidence sources are:

- `ur0:/tai/tls_fixer-startup.log`: browser route (kind 3), successful name/hash/PUID checks, `provider.start.enter`, returned positive kernel module ID, `provider.status` zero and subsequent hook return.
- `ux0:/data/tls_fixer-browser-<PID>.log`, when process permissions allow: `browser TLS active` and a handshake-completion record with the negotiated version/cipher.
- The displayed server-reported TLS version, or a controlled server restricted to TLS 1.3 with trusted certificate and a fresh response token.

User startup can return success after publishing only inert forwarding hooks. Therefore the native start result alone does not prove that all four browser hooks activated. A stale browser log, cached page, PENDING gate report or disabled-session test is insufficient.

The current provider logs may reveal namespace/permissions, trust parsing, module signatures or hook-installation failures. Preserve exact errors. Do not change multiple components to hide a failing gate.

A successful result is scoped to this Vita, provider binary, supported compatibility module and tested endpoints. The full SceHttp path and old scan root cause remain separate work. An ordinary later reboot disables this one-shot kernel; nothing automatically re-arms it or restores a different persistent plugin.
