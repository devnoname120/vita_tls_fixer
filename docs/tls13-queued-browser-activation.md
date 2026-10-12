# Queued browser-only activation test

## Evidence and scope

The queued observer's first boot reached LiveArea by user report. The same-session browser request produced 38 complete records, matching 38 recorder attempts with no reported error. The recorded compatibility path was `sd7d4949a9e23f:/webcore/ScePsp2Compat.suprx`; the hook selected `sd7d4949a9e23f:/tls_fixer/ScePsp2Compat.suprx` and the native load returned GUID `0x132F9`. The mount is a per-process value, not a string to hardcode. Source evidence is preserved in `build/device-evidence/146-browser-route-20261009T163921Z-c56036/`.

This test combines that queued recorder with the previously implemented browser-only provider loader. It does not enable the SceHttp provider or DNS helper. It keeps the current installed compatibility module, TLS provider and CA bundle; no VPK, system-module replacement or persistent storage change is part of this test. The provider has not yet been shown to activate or negotiate TLS 1.3 on hardware.

## Changes

The supported combination is `TLS_FIXER_BROWSER_ACTIVATION`, `TLS_FIXER_TRACE_MODULE_PATHS`, `TLS_FIXER_ENABLE_BOOT_TRACE`, `TLS_FIXER_STACK_HEADROOM`, `TLS_FIXER_PREPARE_EXTENDED_STACK`, and `TLS_FIXER_PREPARE_NAME_QUERY`, all ON. Preparation-only and redirection-only are OFF. CMake and the native entry reject incompatible profiles. The earlier observation-only profile remains supported and does not start a provider.

Self-disarm remains the first entry call. A successful diagnostic worker start enables the queue before publishing the loader hook. Runtime path records and preparation stages use the same bounded queue; the worker performs trace writes and synchronization. Name checks, exact compatibility-file hashing and GUID-to-PUID validation precede browser-provider start on the 16 KiB native-managed stack. Only the original intercepted load result is returned to its caller, including when preparation fails.

The activation path now also validates the target text pointer and queries `ksceKernelGetModuleIsSharedByAddr` before starting the user provider. A nonzero classification, missing text pointer or failed diagnostic enqueue refuses activation. This avoids intentionally placing per-process provider hooks into a shared target. It does not implement a shared-memory workaround or change sharing flags.

IDA in the 3.60 module manager shows that the sharing query locates the address under the process-module lock and tests an internal shared bit. That API also returns zero when lookup fails, so it must not be treated as an independent proof of target existence. The loader first requires successful target module-info/name/PUID checks. No stronger concurrency or module-lifetime guarantee is claimed by this diagnostic.

## Verification

`build/queued-browser-full-verification.log` records 134 normal CTest passes, 134 ASan/UBSan/leak-checking CTest passes, 34 Python tests, both native builds, decoded FP/SIMD checks and no unresolved ELF symbols. The default kernel is byte-identical to the preceding path-corrected default; the queue/status worker remains diagnostic-only. `build/queued-browser-profile-matrix.log` records 13 rejected invalid configurations.

The combined-profile test first failed on the old compile-time restriction (`build/queued-browser-profile-red.log`) and then passed. The shared-target regression first allowed an unwanted provider start (`build/queued-browser-shared-red.log`); the completed suite now verifies rejection, absent text and both trace-failure boundaries before provider startup. It also preserves the existing cleanup and no-unload-after-possible-publication tests.

IDA session `tls_fixer-queued-browser-activation-20261009` confirms self-disarm first at `0x810002BC`, worker startup at `0x8100046C` before hook publication at `0x810004B2`, target sharing classification at `0x8100315A` with a zero-result requirement, and provider start at `0x810031CC`. The SceHttp injection entry at `0x8100331C` returns failure immediately. No provider-unload symbol is linked. These are static/host checks, not device acceptance.

## Deployment and acceptance

Only `ux0:/data/tls_fixer-one-shot/tls_fixer.skprx` and its preallocated 256-byte diagnostic report are replaced. The previous observer and report must be saved locally and remotely; preserve the browser trace before resetting it. Use the exact disabled configuration and protected-file checks from the current preflight, not an old assumed device state. Stop without rebooting on any mismatch. Activate only the single existing config entry after successful payload verification.

The active queued observer must be stopped by an ordinary unarmed reboot before its report is replaced. Its disabled boot entry does not stop the worker already running in memory. The user reported completing that reboot; the current read-only preflight is `build/queued-browser-preflight-current.json`, which also verifies the installed compatibility module, provider and CA hashes.

After one deliberate test boot, first verify the user-observed boot result, fresh gate/setup/report, queued trace, exact kernel and self-disabled entry. Only then request the browser in that same session. Preserve both kernel and browser-provider logs. A successful native provider start does not establish that all four user hooks were enabled: partial publication can leave resident passthrough hooks. Require provider activation evidence and actual TLS-version evidence from the request. Do not bypass certificate warnings.

Self-disarming covers the next boot only after the gate has completed; it cannot cover a fault before entry or during the gate. Runtime queue acceptance is not durable storage: a crash can lose unflushed records. Queue saturation, dropped reentrant records and stopped reporting/draining remain limits on negative conclusions. Do not re-arm after an unexplained crash without preserving and analyzing its evidence.
