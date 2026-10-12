# Boot failure: offline correctness and causal review

Date: 2026-10-09. Scope: the current tls_fixer kernel integration, the archived device captures, and the native firmware interfaces used by that integration. No Vita was accessed, changed, re-enabled or rebooted during this review.

## Assessment

The implementation is **not ready for another full TLS/browser test**. The startup failure has been narrowed to work added after module loading, but its initiating instruction or violated native invariant has not been identified. Neither a completed trace nor passing host tests establishes a repaired boot.

The one-shot safeguard is a separate success: actual failed boots left the expected disabled entry on persistent storage, and the user then reached LiveArea on a normal power-on. That demonstrates the intended recovery behavior in those cases, not immunity to every fault before or during the disarming writes. [Evidence: `TLS13_PROGRESS.md` sections 23.8-23.9, 23.12-23.13, 23.59 and 23.65.]

This review found a genuine reentrant-start defect in the full kernel and a genuine mismatch in the host test environment. Both were reproduced and corrected locally. **Neither explains the failing preparation-only diagnostic**, because that profile cannot start the DNS helper or a TLS provider, and the real Vita build already used the native module-start constants.

## Findings, in priority order

### 1. The full integration starts user modules inside an unfinished native load operation

`kernel/main.c:130-162` calls provider preparation after its loader continuation returns but before returning to the continuation's caller. In the normal build, `kernel/tls13_loader.c:365-377` then calls `ksceKernelLoadStartModuleForPid`. This is not merely queuing work for later.

Native `fun_StartProcessImageEntryThread` creates/starts the target entry thread and synchronously waits for it (`0xB898DC`, wait at `0xB899E2` in the 3.60 Modulemgr IDB). The outer process/module startup can therefore remain incomplete while another user module is executing startup and resolving dependencies. The per-PID in-flight table prevents selected duplicate preparation calls, but it does not establish that the enclosing native load/start state, import initialization or all outer locks permit this operation.

The existing taiHEN reference deliberately loads application plugins after starting the default preloaded modules. Its implementation is useful evidence of a different lifecycle boundary, not proof that it can replace our current boundary unchanged. [Source: `.reverse-tmp/taihen-lifecycle/hen.c:345-380`, reference commit `309b3800bcb8ebbd5e4f5e5e920af3da3590b829`; native IDA session `tls_fixer-return-api-audit`.]

**Disposition:** an unresolved full-integration acceptance condition. Do not infer that fixing the preparation-only fault also validates synchronous provider startup. This operation is absent from the reduced crashing binary, so it is not its immediate cause.

### 2. DNS-helper startup could recursively start itself; zero was accepted as a live module ID

Previously, `g_dns_fix_state` remained ready while `ksceKernelLoadStartModuleForPid` was executing. A nested shell-side SSL load could reenter the hook, observe that same ready state and request another helper startup. The positive-path mock did not model reentry. The completion condition also accepted module ID zero.

A regression now makes the helper-start mock perform one nested invocation of the actual production hook. The previous source attempted a second helper start, failing `dns_loads == 1`. A separate failure/retry sequence exposed the zero-ID case. [Red logs: `build/offline-audit-regressions-red.log`, `build/offline-audit-zero-uid-red.log`.]

The corrected `kernel/main.c:165-182` atomically claims the ready state before loading, keeps an explicit in-progress state through the call, and publishes complete only for a positive module ID and successful start status. Failure returns the state to ready. Other callers cannot claim the same startup while it is in progress. Runtime reads used for commerce redirection are atomic too. The nested hook still performs the original native load; only duplicate helper startup is excluded.

Tests cover reentry, a second successful call, negative/zero IDs, failed start status and a subsequent successful retry. This fixes a reproducible integration defect; it is **not presented as the device crash fix**.

### 3. The host shim confused failed startup with successful non-resident startup

`tls13/tests/transport/include/psp2common/kernel/modulemgr.h` defined `SCE_KERNEL_START_FAILED` as 1. The installed VitaSDK header distinguishes success/resident 0, success/non-resident 1, and failed startup 2. Comparing code and mocks through the same incorrect macro could let tests agree for the wrong reason.

The shim now uses 2 and defines the non-resident constant separately. `tls13/tests/kernel/test_module_status.c` asserts the numeric contract independently; it failed against the old shim. A native compile-time audit also checks the real SDK values. [Evidence: the same red log, `build/offline-audit-native-abi.c` and `.log`.]

This was a **test-fidelity defect**, not evidence that the previous on-device kernel returned 1 for failure: the actual kernel was compiled against the real SDK header, not this shim. The host structure definitions are still test doubles and are not relied on to prove ARM binary layouts.

### 4. The kernel hook's missing target guard is now corrected locally

The earlier kernel found `SceKernelModulemgr` by name and patched segment 0 at offset `0x21EC` without validating the native code. `kernel/hook_guard.c` now checks the known module ID/name/attributes/version, text segment size/permissions/bounds, startup-entry offset, and four instruction signatures before the hook is installed. Only the stack-cookie address immediates in the entry's MOVW/MOVT pair are masked for relocation; the opcodes, register operands and additional branch sequences remain checked.

The startup regression reproduced hook installation despite rejected target validation. The guard test's initial stub also failed before implementation. Tests now check rejection, cleanup before hook publication, malformed metadata and every bit at each checked instruction location, including acceptance of only the masked relocation bits. The four source byte arrays were independently compared with the dumped 3.60 image; `build/hook-guard-profile-verification.json` records that comparison.

**Disposition:** this closes a demonstrated activation-safety gap in local source. It is a bounded known-profile check, not a whole-module cryptographic identity proof, a guarantee against a concurrent third-party patch, or evidence of the boot crash's cause. Unknown/differently patched profiles are refused. It runs after self-disarming and before hook installation. Frozen diagnostic ZIPs and the Vita have not been updated, so this is not a mid-experiment change to the device.

### 5. Native layout checks are now required by every kernel build

The earlier real-header assertions lived only under `build/offline-audit-native-abi.c`, so a future normal build could omit them. The verified assertions are now in `kernel/native_contract.c`, included in every kernel profile. They check ARM32 widths, the native module-info extent/offsets, segment stride, startup constants and the module-query prototypes against the actual VitaSDK headers, independently of host shims.

Fresh default, initialization-only and target-query-only builds pass. The assertion object has zero text, data and BSS bytes in each build: this adds a build-time guard, not another operation on the boot path. Deliberately incorrect expected startup status and structure extent were rejected with the intended static-assertion diagnostics. Evidence: `build/native-contract-verification.log`.

## What the device comparisons actually establish

| Captured profile | Observation | Defensible conclusion |
| --- | --- | --- |
| Self-disarm only | User reached LiveArea; exact disabled config retrieved | The gate can execute and return on this device. |
| Initialization only | User reached LiveArea; exact disabled config retrieved | The startup checks and initialization are not by themselves sufficient to reproduce the observed failure. |
| Traced redirection plus headroom control | User explicitly reported LiveArea; 19 records include HTTP and SSL loading in two processes | This was an executed hook/measurement control, not merely a skipped plugin. |
| Private query buffers, full preparation | Explicit warning-screen crash; queries/hash/cleanup and a following SSL load returned in the trace | Large local query buffers were not the sole explanation; completion markers do not establish boot success. |
| Native-managed 16 KiB stack, full preparation, failed repeat | Explicit warning-screen crash; 116 records complete through HTTP hook return | Increasing the stack did not repair the failure. |
| Runtime module queries omitted, controlled repeat | User confirmed first-boot LiveArea; fresh 111-record trace and self-disabled config retrieved | A positive control with runtime hashing and native stack switching, but without enumeration or info queries. |
| Target-info-only repeat | User confirmed first-boot LiveArea; fresh 113-record trace contains two successful target-info calls and subsequent SSL loads | The target lookup alone is not sufficient to reproduce the full-scan failure in this observation. |

The strongest positive control is the explicitly confirmed headroom-control run, not the earlier "I think" observation. The first native-stack attempt also had an uncertain visual outcome; its later explicit failed repeat is a separate run. [Evidence: `TLS13_PROGRESS.md` sections 23.47, 23.50, 23.53, 23.56, 23.59 and 23.65.]

The complete module load/start and DNS-helper operations are compiled out of the failed preparation-only profiles. TLS handshakes, browser certificate callbacks, Mbed TLS heap consumption and DNS-helper reentry consequently are not necessary to trigger that reduced failure. This is a meaningful localization, but it does not distinguish a query's side effect from its interaction with the caller, timing or another plugin.

The native-stack repeat and original no-query capture were reanalyzed from the archived bytes. The failed repeat's preparation interval is 1,384,654 microseconds; the original no-query capture's two intervals are 497,150 and 2,120,698 microseconds. That original no-query boot outcome remains unknown. Later controlled repeats establish successful first boots for no-query and target-only profiles separately. All durations include synchronous logging and do not establish a timeout threshold. [Reproducible output: `build/resume-query-capture-comparison.json`; later evidence: TLS13_PROGRESS.md sections 23.70 and 23.73.]

## Native query contract: checked beyond C prototypes

### Export identity and calling convention

The linked kernel imports module info from library NID `0xC445FA63`, function NID `0xD269F915`. In the actual 3.60 export descriptor at `0xB93A4C`, the NID table starts at `0xB93EA0` and function table at `0xB93F80`. The entry at NID address `0xB93F38` pairs with function address slot `0xB94018`, containing Thumb address `0xB9046D`. This reaches the wrapper analyzed as `ksceKernelGetModuleInfo` at `0xB9046C`.

The list import is the same library with function NID `0x97CF7B4E`. Its NID slot at `0xB93F1C` pairs with function slot `0xB93FFC`, containing Thumb address `0xB90325`. **The actual list entry is `0xB90324`**; earlier notes citing `0xB90334` refer to an instruction within that function, not its prologue. The raw prologue saves R4-R11/LR, reserves 12 bytes, and reads the fifth argument from the incoming stack area. This is not an extra-argument or different-export mismatch.

These associations were checked against the linked stub words and IDA's native export-table bytes, rather than trusting an enriched function name alone. [Sources: `build/target-query-only-kernel/tls_fixer.elf`, `build/offline-audit-default-kernel/tls_fixer.elf`, 3.60 Modulemgr IDB.]

### Enumeration and object lifetime

The list routine treats the supplied count as entry capacity and returns the number copied. The selected flags `0xFF, 1` include the shared/private categories and request GUIDs, not user-visible PUIDs. Shared/private branches are mutually exclusive. The current 256-entry allocation matches that convention; saturation is conservatively rejected.

The info wrapper accepts `(pid, GUID, output)`. Its helper references the module object, fills output and releases the reference. The final output `modid` is a PUID for a user process and a GUID for the kernel process. Thus obtaining the target PUID through this API is consistent with the native implementation.

Both query paths acquire the per-process Modulemgr lock and pass its saved state to unlock. This second argument is easy to miss in decompilation. Raw instructions explicitly load R1 before `ksceKernelSpinlockLowUnl`: `0xB90384` for enumeration and `0xB8F7DE` for info. The info helper preserves R4-R11, checks its stack guard and restores its frame at exit. The process-lock and module-reference wrappers inspected here do not themselves start modules or explicitly switch the process MMU context.

That evidence argues against the specific claims "wrong UID namespace", "forgotten unlock-state argument" and "the public info wrapper fails to preserve the ordinary callee-saved GP registers". It does not prove that every query is valid at every stage of an enclosing process startup.

### Output extent and initialization

The real ARM build was checked independently with compile-time assertions:

| Item | Native value |
| --- | ---: |
| Pointer / SceSize width | 4 bytes |
| SceKernelModuleInfo size | `0x1B8` |
| modid / module_name offsets | `0x04` / `0x0C` |
| path / segments / state offsets | `0x54` / `0x154` / `0x1B4` |
| SceKernelSegmentInfo stride | `0x18` |

The native producer writes that layout. It copies only 26 of the 28 name bytes and leaves some reserved fields unchanged. Our caller clears the info buffer before every query, providing name termination. The 256-byte path copy does not promise termination at maximum length, but this preparation path does not parse that returned path.

The query allocation contains 1024 bytes of IDs plus the 440-byte native info object, comfortably below its fixed 4096-byte bound. There is no demonstrated output-size mismatch in the audited call. [Sources: `kernel/tls13_loader.c:172-213,347-359`; `build/offline-audit-native-abi.c`; native helper `0xB8F790`.]

The taiHEN reference also uses `GetModuleList(pid,0xFF,1)` and uses this public info API for module-offset lookup. Its presence-search implementation, however, uses internal metadata after enumeration. It is a comparator, not a drop-in proof of the safety of our full per-module scan at this particular loader boundary. [Source: `.reverse-tmp/taihen-lifecycle/module.c:237-315`.]

## Stack, SIMD and diagnostics: what not to conclude

The positive control measured roughly 3.3 KiB of remaining runtime-loader stack. Moving the large buffers off that stack was therefore justified. The failed native-stack run nevertheless recorded about 16 KiB of positive callback headroom, exact sampled SP restoration, completed preparation and then the reported crash. Samples are not a high-water bound, but another arbitrary stack increase is not the next evidence-driven change.

The linked-kernel register gate now rejects compiler-generated VFP/NEON instructions. It does not inspect every native import. Earlier IDA review found SIMD inside native SHA-256, memcpy and memset. Native hashing is retained in the no-query profile, and memory primitives also run in positive controls. An assertion that "any native SIMD is the cause" would therefore be unjustified. Establishing an actual VFP ownership violation would require its execution-context contract and affected state, not merely seeing a vector mnemonic. [Evidence: `TLS13_PROGRESS.md` sections 23.54-23.56 and 23.63.]

The recorder is not behavior-neutral. It serializes a shared buffer, performs positional writes and synchronizes records. Busy/error returns can cause the diagnostic caller to skip later preparation. Trace presence confirms observed execution; absence alone does not establish that a native operation hung. Neither relevant capture reached the 512-record cap or ended with a partial record. The last `hook.return` is emitted before the hook's actual epilogue and native caller resume. It is not an exception PC, nor a guarantee that the next instruction executed successfully. [Sources: `kernel/boot_trace.c:37-90`; `kernel/main.c:114-134,186-190`; `tools/analyze_boot_trace.py`.]

## Revised investigation decision

There should not be another sequence of small, undocumented toggles based only on whether LiveArea eventually appears.

1. **No-query and target-only positive controls are now established.** Each has an explicit first-boot LiveArea observation and fresh profile-specific trace evidence. An earlier target-only boot with an untouched PENDING report and stale trace was not counted.
2. **Separate enumeration from per-module inspection.** The list-and-target diagnostic adds one module-ID enumeration while retaining the target lookup; it does not inspect metadata for any enumerated non-target module or start providers. Source/build guards forbid using the omitted presence scan in a loading profile.
3. **Keep the changed startup guard explicit.** The new diagnostic also incorporates the locally reviewed hook-profile guard, unlike the old frozen target-only control. This is a bounded comparison of runtime preparation work, not a byte-identical single-variable experiment. A rejected guard or absent query trace does not constitute a tested enumeration path.
4. **If a discriminating run ends with all operations returned but a boot failure**, do not treat the last successful marker as the culprit. Exception PC/LR/CPSR, fault status, relevant stack and module map would be more discriminating than another returned marker. The existing file logger cannot manufacture that information; any additional crash-capture integration needs separate design and approval.

The successful target-only repeat points toward enumeration/per-module inspection or its interaction/timing. A successful list-and-target comparison would narrow this further to the per-module inspection, but neither observation alone proves that a native API is intrinsically broken. Production identity validation remains intact; the guarded default kernel is byte-identical with the new diagnostic option disabled.

## Alternative deployment framing

The requested product is **browser TLS 1.3**, not automatic TLS replacement in every system process. The current SceHttp integration increases exposure by participating in shell startup before a browser test begins. Once the native preparation issue is understood, a separately qualified browser-only activation path is a more contained first acceptance target; general SceHttp injection can remain a later opt-in milestone.

This is a proposed scope/lifecycle separation, not a silent change already made. Simply removing the shell branch could hide rather than fix a kernel defect, and the browser's own process/module lifecycle still has to be validated. It does not require or justify rewriting the TLS engine, emulating all private SSL exports or changing storage recovery arrangements.

## Verification and disposition

The new reentry/status regressions failed before their corrections, then passed. The final run after the last test edit passed **87 normal CTest targets, 87 ASan/UBSan/leak-checking targets and 27 Python tests**. Default and target-only native kernels build, contain no decoded FP/SIMD instructions in their own executable code and have no unresolved ELF symbols. Independent real-header ABI assertions pass. The target-only ELF still has no provider load/start/unload or runtime enumeration import. [Logs: `build/offline-audit-final-verification.log`, `build/offline-audit-final-python.log`, `build/offline-audit-native-abi.log`; complete earlier fresh-build output: `build/offline-audit-native-verification.log`.]

New local-only kernel identities:

- Default build: `build/offline-audit-default-kernel/tls_fixer.skprx`, 10923 bytes, SHA-256 `0dbe8880793ead0fa6f2e2ca236fa83560e4722d2bcb53831fcf9384bb15b495`.
- Target-only build: `build/offline-audit-target-kernel/tls_fixer.skprx`, 16274 bytes, SHA-256 `a0df0e957e3d8dd02a4418ecd467f3ad1811b56939e56b93c7caaefa8f055cef`.

The earlier 16271-byte candidate and its ZIP remain an immutable historical snapshot; their source receipt is not a receipt for these new local changes. No updated diagnostic ZIP was delivered. No device file, boot entry, user provider, certificate, system module or storage setting was altered. No commit, push or reboot was performed.

**Bottom line:** the offline review has repaired demonstrated defects and strengthened the ABI evidence, but the warning-screen failure remains unresolved. The next decision must be based on the existing no-query outcome and then a bounded, discriminating observation, not on another claim that passing host tests makes the Vita safe.
