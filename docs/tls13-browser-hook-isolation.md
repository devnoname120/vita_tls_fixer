# Browser hook isolation

## Evidence motivating this control

The four-hook passthrough provider crashed during a normal browser page load even though replacement TLS was disabled. The smaller initialization-only provider then returned a successful start status and rendered the Cloudflare page with TLS 1.2. Evidence and exact identities are in TLS13_PROGRESS.md sections 23.174-23.178.

That does not isolate a specific callback. The smaller image removed callback/backend code through section garbage collection, so memory footprint and hook installation/execution are still competing explanations.

## Explicit selection without removing callback code

`TLS_FIXER_BROWSER_HOOK_MASK` is an optional decimal CMake value from 0 through 15. Leaving it empty retains the ordinary build behavior. An explicit value requires the Vita startup diagnostic with passthrough enabled, initialization-only disabled, and no runtime UDP or standalone probe.

| Bit | Hook |
| --- | --- |
| 1 | close |
| 2 | pending data |
| 4 | connection health |
| 8 | connect |

The selector is a read-only volatile four-byte object. Every callback and its dependencies therefore remain reachable to the linker, including when the value is zero. The selected value is read once before the installation loop. No selected profile enables replacement TLS. The ordinary non-control build still enables it after all required hooks succeed.

The zero selection tests initialization and the retained provider footprint without publishing any user hooks. Selection 8 tests only connect; selection 15 tests all four. These are independent diagnostic images, not an automatic iteration sequence. Only one selected image may be deliberately activated in each verified self-disarming boot.

First selected-hook failure destroys the unexposed backend even when that hook is not close. Failure after any successful publication retains the disabled backend and its continuations until process exit. The existing encoded diagnostic status identifies the actual failing hook index. There is no automatic unload or retry after publication.

## Verification

`tls13/tests/browser/test_hook_selection.c` exercises masks 0, 1, 2, 3, 4, 8, 12 and 15 with no failure and failure at each of four installation ordinals. It verifies the selected offsets, attempt count, cleanup distinction, diagnostic status, disabled transport, retained callbacks and original-call argument/result forwarding. The zero-selection test failed before implementation because four hooks were still installed.

`tools/tests/test_browser_hook_profile.py` rejects malformed masks and incompatible profiles. Its missing-guard test failed because an explicit mask silently configured the ordinary build.

Native snapshots are separate from the deployment artifacts:

- `build/browser-hook-selection-images/mask-0/`
- `build/browser-hook-selection-images/mask-8/`
- `build/browser-hook-selection-images/mask-15/`

`build/compare_browser_hook_images.py` checks ELF32 program-header geometry, all loadable bytes, the selection symbol and its actual value. It requires a four-byte STT_OBJECT in allocated read-only data without the section instruction flag, and rejects differences outside that object. The ELF may legitimately place this data section in the same RX load segment as code; segment execute permission alone does not make the object an instruction. The comparison passes for these snapshots: only the selector value at 0x81040314 differs. This establishes equal instruction bytes and loadable segment extents across the three snapshots, not across the historical smaller initialization-only image or actual runtime allocator placement. SELF containers can differ because they include different payload data and derived metadata.

The native entry review must additionally establish that zero selection skips every installer call, that all callbacks remain linked, that failure cleanup depends on successful publication rather than the loop index, and that successful startup explicitly stores zero to the backend enable flag.

## Device sequence

Preserve the current page, trace and report first. Stop the previous in-memory diagnostic with the guarded unarmed reboot after exact disabled-state checks. Re-read the inactive payloads, configuration, protected files and original browser resources. Stage only the separately selected ur0 provider and a fresh report, retaining the previous diagnostic under a backup name. The removable kernel remains unchanged.

After the one-byte arming step and a single verified self-disarming boot, issue the user-requested `quit all`. Use the visible browser icon and Start tile, not a title/URI launch. Capture the page/error and boot-correlated provider status before further actions. Never automatically advance the selection after a crash or reuse a consumed arming receipt.

A rendered page and successful startup are necessary observations, not a TLS 1.3 result. If the zero-selection full-footprint control fails, isolate resource/loading effects before trying individual hooks. If it succeeds, select a subsequent hook control explicitly and preserve the exact image comparison. Hook masks do not bypass module identity, certificate validation, sharing restrictions or the self-disarm requirement.

The zero-selection run rendered a page before a later system-wide freeze (worklog sections 23.183-23.186). Treat initial rendering and subsequent stability as different outcomes; recovery does not establish the freeze's cause. The connect-only control targets the earlier immediate content-process crash, not a presumed fix for the later hang.

Disabled replacement TLS is not a direct-continuation-only hook. The connect callback still enters `tls_fixer_browser_connect`, clears the caller's `done` byte and performs the attachment/registry lookup before forwarding an unhandled connection. A selected-hook failure therefore implicates a wider path than instruction relocation alone. A later direct-continuation control would separate backend dispatch/locking from hook installation and the native continuation, but would need a separately qualified image; do not silently substitute it for the byte-compared mask-eight test.
