# Provider-presence lookup through taiHEN

## Purpose and evidence

The list-plus-target diagnostic reached LiveArea on its first boot. A fresh trace independently showed two successful module lists (28 and 12 IDs), two successful target-info queries, completed preparations and subsequent SSL loads. The earlier full per-module metadata scan still has an unexplained boot failure.

This comparison replaces only provider-presence inspection in a preparation-only profile. It uses the existing `taiGetModuleInfoForKernel` API. That API internally enumerates modules and reads their internal name/identity metadata; this is not a scan-free implementation. Unlike the old loop, it does not call `ksceKernelGetModuleInfo` for each unrelated module.

The diagnostic first resolves the known `SceLibHttp` or `ScePsp2Compat` name as a positive control, then resolves `tls_fixer` or `tls_fixer`. Only explicit `TAI_ERROR_NOT_FOUND` (`0x90010002`) counts as provider absence. Other errors, nonzero success-like results, invalid IDs, malformed names and disagreement between the named target's PUID and the subsequent native target-info result stop preparation. An already-present provider skips further preparation, preserving duplicate detection.

The self-disarm gate, current-3.60 hook guard, bounded workspaces, file/hash gates, native-managed 16 KiB stack, persistent result and bounded trace remain. The profile cannot load or start either TLS provider or the DNS helper. The default kernel's behavior and binary must remain unchanged by this diagnostic option.

## Build and local validation

Use the existing hard-float VitaSDK toolchain with these CMake options:

```text
TLS_FIXER_PREPARE_ONLY=ON
TLS_FIXER_ENABLE_BOOT_TRACE=ON
TLS_FIXER_STACK_HEADROOM=ON
TLS_FIXER_PREPARE_EXTENDED_STACK=ON
TLS_FIXER_PREPARE_NAME_QUERY=ON
```

Do not combine the name-query option with a query-omission, target-only or list-plus-target profile. CMake and source guards reject unsupported combinations.

The regression compiles the production loader and fails any direct module-list call or non-target native module-info call. It exercises repeated application/browser preparations, present/absent providers, lookup failures, invalid identity, trace failures, native-stack failure and workspace cleanup. Host mocks cannot establish the runtime safety of taiHEN's own implementation.

Linked-code verification must confirm the real taiHEN ABI extent, no unresolved symbols, no decoded FP/SIMD instructions in the kernel, self-disarm before later initialization, two named lookups and only one native target-info call in the preparation callback. The release/default SELF is compared byte-for-byte with the unchanged baseline. Actual addresses and hashes belong in the adjacent build receipt and TLS13_PROGRESS.md.

## Device sequence

Use only primary Vita `192.168.1.146:1337` under the recorded diagnostic permission. Read the current disabled config, payload, result, trace and protected boot/YAMT/FTP files twice; preserve the parallel yield section and all unrelated bytes. Do not restore a stale pre-recovery config. Do not run an old VPK, update user providers or change CA/system/storage files.

The two-file diagnostic ZIP contains only `tls_fixer.skprx` and `tls_fixer-disarm-result.txt`. Stage the verified kernel at `ux0:/data/tls_fixer-one-shot/tls_fixer.skprx` while its entry is disabled, back up the old kernel/report, publish under the same path only after read-back, and provide a fresh 256-byte PENDING report at `ur0:/tai/tls_fixer-disarm-result.txt`. Re-enable only the initial path character of the existing one-shot boot entry. Verify the complete configuration and protected files again before requesting a boot. There must be no concurrent config saves.

The user granted remote-reboot permission, but the earlier actual reboot call was tool-blocked and must not be bypassed or retried through another mechanism. Request one manual first boot for this comparison. Do not automatically re-arm after any failure.

## Acceptance evidence

Record whether the first boot reaches LiveArea, not merely whether a subsequent recovery power-on does. Retrieve the full current config, payload, result and `ur0:/tai/tls_fixer-startup.log` twice after boot. The entry should be self-commented and all unrelated config/protected files unchanged.

The trace must be new, valid and specific to this profile. Require successful `name.target.return`, `name.provider.return` with explicit NOT_FOUND for the expected-absent provider, successful native `target.info.return`, completed preparations and subsequent loader activity. A PENDING result, stale trace, rejected hook guard, lookup error or negative preparation is not a successful positive comparison even if the device reaches LiveArea.

A positive result would support a narrower provider-presence design; it would not prove the old scan's root cause, successful provider injection or browser TLS 1.3. Logging changes timing and code layout. Self-disarm protects subsequent boot selection only after its writes are synchronized, not faults before that point or unrelated persistent replacements.
