# Browser hook installation after native module start

## Evidence and scope

The connect-only, TLS-disabled provider reproduced C2-12828-1. Its saved core faults on an instruction fetch at 0x91D40000. The compatibility module has imported-variable MOVW/MOVT fixups at offsets 0xA5ED4 and 0xA5ED8 inside the replaced connect prologue. The firmware's MOVW field rewrite transforms the recorded callback literal 0x81280001 into 0x91D40001 using imported address 0xE00111D4. The dump omits the patched page: this is an exact arithmetic/timing correlation, not a direct observation of the corrupt literal.

Previously, the provider was started after module load but before native start linked the compatibility module's imports. This control defers provider injection until native start returns. The separate provider is unchanged: connect-only mask 8, replacement TLS disabled, SHA-256 d09284a4f9b02117faaa3a5ab013e5abd5a8e15a2f72530b22dd5c954810dc5a. It tests the ordering hypothesis without changing cryptography, certificates, native module files or taiHEN.

## Implementation

`TLS_FIXER_BROWSER_POST_START` is now required for normal provider activation. The earlier diagnostic-only restriction was incorrectly retained in the published VPK, which omitted this ordering and reproduced the branch-target corruption. Normal builds enable post-start ordering, retain application-provider activation, and reject explicit early injection. Isolation profiles that never install browser transport hooks omit the pending manager. The recorder remains optional.

Startup persistently self-disarms first, verifies both native hook sites, initializes a bounded pending table, then installs the start hook before publishing the load hook. Normal activation also uses the previously hardware-qualified name lookup and same-thread 16 KiB native stack; those controls were also omitted from the former default build. The common load/start offsets remain 0x21EC/0x286C across the identity-selected firmware profiles; the guarded instruction families are checked against each available image.

A successful recognized compatibility load adds an owned pathname keyed by process ID and module GUID. HTTP loads use the same pending table with an explicit HTTP target kind and no process-private pathname. Native start forwards its seven arguments exactly once and completes this pending record only after returning. Only an exact zero native result permits injection. The pending record is removed before calling the provider, with no table mutex held over native startup, file access, logging or injection. Native return values and the caller's status output are never overwritten by the diagnostic result.

Failures after publication keep the kernel and its resources resident; cleanup cannot release code behind a potentially executing continuation. A failed first hook permits normal cleanup. Stop refuses while either kernel hook is published. A load abandoned without a corresponding start can occupy one of eight bounded entries until reboot/teardown. Exhaustion refuses additional activation; it does not evict another process's pending entry. Historical option-off images are preserved only for comparison. The normal build rejects early provider injection.

## Generated-code review

IDA session `tls_fixer-post-start-final-review` opened `build/browser-post-start-kernel/tls_fixer.elf` in place. Scoped instruction queries show:

- First entry call: self-disarm at 0x810002F0, before trace open at 0x81000312.
- Pending-table initialization at 0x810004B2; start-hook installation at 0x810004F8 before load-hook installation at 0x8100054A.
- Native start continuation at 0x810002A4, followed by completion at 0x810002AE; the saved native result is restored before return.
- Pending mutex unlock at 0x81002BDE precedes the native-result marker, zero-result gate, and provider injection at 0x81002CB4.
- The load callback calls `tls_fixer_post_start_defer`, not browser injection.

The kernel register gate finds no decoded FP/SIMD instructions, and there are no unresolved symbols. These observations establish static control flow, not successful device execution.

## Verification and artifacts

`build/browser-post-start-final-host.log` records 321 normal tests, 321 ASan/UBSan/leak-checking tests, 108 Python tests and three rejected incompatible profiles. Tests include exact native argument forwarding, delayed injection, failed/nonzero starts, duplicate/reentrant completion, table bounds, source-path ownership, trace failures and partial hook-publication cleanup. The ordering fixture models the observed MOVW corruption and verifies that post-link installation retains the intended pointer; it is not ARM emulation.

`build/browser-post-start-native-final.log` records successful native builds. Disabling post-start and snapshots produces a kernel byte-identical to the preceding control. The new kernel is 22613 bytes, SHA-256 3ccfa163d12a7f43eb4bea9affe23b1723a43f597520059de1d46fafe2a09247. The package is `build/artifacts-post-start-control/`, with receipt-pinned sources, logs, ELF and unchanged provider. Its ZIP contains only `tls_fixer.skprx` and `tls_fixer-disarm-result.txt`.

New helpers are `build/stage_post_start_control_files_only.py` and `build/arm_post_start_control_once.py`. They select only the new kernel and fresh report; the provider and original resources are checked, not rewritten. Do not reuse the consumed connect-only cycle.

## Device acceptance

Preserve the preceding crash evidence, verify recovery and complete one unarmed reboot before replacing the diagnostic report. A disabled file does not unload an active kernel. After announcing this specific control, use the guarded runner with the new helper/receipt paths. A verified boot returns expected status 3 with a pending normal-UI phase; never rerun the helpers because of that status.

Use `quit all`, review the current screen, then open Browser through its normal icon and Start tile. Preserve the rendered page or crash dialog and collect the same-boot trace. Required ordering is compatibility load, defer, native start return, preparation/provider startup, then hook entry snapshots. A rendered TLS 1.2 page is the expected passthrough result, not proof of TLS 1.3. Successful provider entry alone does not prove a page load or stability. The earlier whole-system freeze remains separately unresolved.
