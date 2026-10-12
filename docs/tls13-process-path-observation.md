# Process-namespace module-path observation

## Why this is narrower than the preceding observer

The all-load observer was followed by a user-reported crash with uncertain timing. Its actual post-crash capture is `build/device-evidence/146-browser-route-20261009T125826Z-ae7ff1/`; the independent user capture five seconds earlier has the same file identities. The tested kernel is 14191 bytes, SHA-256 `196ec25db0e8b797727c347a4ab4c35c45bb6e512c7d18ba5c3df830bbc75bbb`.

The entry is self-disabled and the report records completed gate/logger setup. The 20277-byte trace contains 122 complete records and 37 paired load calls. No pair is open and the cap was not reached. Its final operation is a returned `np_webapi.suprx` load. All recorded inputs lack flag 0x1000. A directory-level search found no new core file matching this observer attempt. These observations do not identify a faulting PC or establish whether logger activity caused the crash.

The previous diagnostic added synchronous log writes to ordinary system startup. This revision keeps the same redirection-only profile but observes only requests carrying the process-namespace flag 0x1000. It avoids logger calls for every one of the 37 native load inputs in that captured trace. It is not a claim that all boot-time calls always lack that bit or that a boot defect is fixed.

## Native basis for the selector

The 3.60 `SceKernelModulemgr.enriched.elf.i64` database was rechecked with IDA. `fun_UserLoadModuleCore` at 0x00B91C24 calls the intercepted `fun_LoadModuleForProcess` at 0x00B91C64 with `flags | 0x1000`. The earlier WebKitProcess analysis establishes a normal `sceKernelLoadStartModule` call for its compatibility module after AppMgr path conversion. Consequently this selector should retain that ordinary browser-loading path regardless of the spelling of the converted pathname.

The bit describes a namespace, not proof of a particular caller or title. Kernel callers can also select this namespace. Conversely this diagnostic intentionally cannot prove the absence of loads through other flag combinations, pre-existing modules, or other entry points. If a browser request produces no selected load records, do not broaden matching or claim TLS negotiation has been inspected.

## What changed

`TLS_FIXER_TRACE_MODULE_PATHS` now selects `flags & 0x1000` instead of logging all module loads. No new profile option, loader, arming token, target matcher, provider-start call or device installation path was added. Startup emits `trace.path.mask` with `obj=00001000` to identify the selection policy in the saved trace.

On an excluded load, both path and scalar return records are skipped; the existing native continuation still receives the same PID, selected path, flags and options and its result is returned unchanged. On an included load, the existing bounded hex path format, replacement-path record and native-result records remain. Native load results are in `obj` for `load.return` and `hook.return`; `rc` is the route number for those stages.

Self-disarming and synchronization still run before report/log setup or hook publication. The executable-register check still applies. Runtime provider preparation, module enumeration and TLS/DNS module startup remain absent. There is no browser TLS 1.3 claim for this diagnostic.

## Verification

The production-route regression failed against the preceding implementation because an excluded request still called the recorder. It now covers absent/present namespace-bit combinations, all route cases previously tested, positive/negative native results, unchanged redirection/arguments, path and scalar logging failures, and refusal to install hooks if the new policy marker cannot be recorded. The serializer and offline parser are unchanged.

Results and artifact identities are recorded in `TLS13_PROGRESS.md` and `build/artifacts-process-path-observer/receipt.json`. The normal full-kernel SELF must match its previously verified baseline; the change must not silently affect other profiles.

## Device procedure

Preserve the current kernel, configuration, report and trace before staging. Verify the complete current disabled configuration and protected boot/YAMT/FTP files. Only the fixed removable diagnostic kernel and its preallocated result file are replaced; only the existing test entry's initial character is deliberately restored. Keep the old kernel and evidence under inactive backup names. No VPK, system module, CA or storage changes are part of this test.

Request one normal manual reboot only after full read-back verification. Confirm the user's first-boot observation, correct kernel hash, fresh completed report, expected self-disabled configuration, positive hook-install record and `trace.path.mask` marker before opening the browser. The next-boot entry must stay disabled during the current test session.

Only after that check, open the browser in the same session and collect the trace again. This run is intended to reveal incoming module paths, not to negotiate TLS 1.3. Do not reset the report or re-arm after an unexpected crash before preserving the evidence. Self-disarming cannot protect a failure before its edits complete, and this filtering does not establish universal power-loss durability.
