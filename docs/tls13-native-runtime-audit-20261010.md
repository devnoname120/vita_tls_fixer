# Native browser/runtime audit, 2026-10-10

## Scope and interpretation

This is a local audit following the unsuccessful passthrough-control launch. It is not a successful browser request, a repaired runtime crash, or proof of TLS 1.3 negotiation. No device payload, configuration, permissions or storage driver was changed during this audit.

The latest direct screenshots show C2-12570-5 before browser content, followed by the browser LiveArea after dismissing the dialog. A subsequent Start tap was tool-blocked and was not retried or rerouted. The previously installed control therefore still lacks a page-load result. Separately, the earlier enabled-provider session had successful provider entries and a user-reported content-process crash; these are different observations.

## Exact compatibility boundary

The existing normalized bundled-module database was used in place, not duplicated:

`<workspace>/.reverse-tmp/fwcompare/373/ScePsp2Compat.exec.elf.i64`

IDA session: `tls_fixer-exact-compat-runtime-remaining`. The artifact provenance and segment identities are recorded in `docs/tls13-browser-path.md`.

The re-read connect driver at 0x810A5ECE agrees with the existing four-argument wrapper: connection, socket index, nonblocking byte and output-done pointer. Its connection-local socket, 24-byte SSL-state stride, connecting-state values, read/write callback locations and deadline callback agree with the adapter. This is confirmation of the inspected boundary, not a guarantee that every curl feature is supported.

The close implementation at 0x810A36BA tests the native SSL pointer at connection + 24*index + 368 and the native context at +364 before freeing those native objects. However, the callers do not require those pointers to be non-NULL before invoking the close wrapper:

- 0x810A079E and 0x810A07A6 call the generic close wrapper for socket indices 0 and 1 in connection cleanup, before socket closure.
- 0x810A0AD2 calls the same wrapper for index 0 in another disconnect path.

Consequently, leaving the native SSL/context pointers NULL does not itself establish that these cleanup paths skip our side-table connection. No workaround for that unproven hypothesis was added.

The health caller at 0x81094D0C checks the native SSL-use byte, invokes the generic health wrapper at 0x81094D18, treats zero as dead and nonzero as usable. This agrees with the adapter's 0/1/-1 convention. The pending-data wrapper still reaches the recorded pending hook. A superficially similar +0x170 load at 0x810A2520 belongs to URL/port option processing, not an additional SSL-pointer consumer.

Cross-references to the embedded SSL read/write/peek routines show the expected curl transport functions and additional exported wrappers. Absence of a direct xref to an exported wrapper does not establish that it is unreachable through an import or function pointer. The broader certificate/metadata-consumer question is not closed by this scan.

## taiHEN continuation layout

The saved taiHEN reference header defines the user hook record as `next`, `func`, `old`. Its continuation macro selects `next->func` when a next hook exists, otherwise the current record's `old`. The provider performs the same selection. No field-order or continuation-selection discrepancy was established.

The saved source is a reference, not a verified byte-identical copy of the installed taiHEN binary. No shared-mapping patch or hook-framework change was made.

## SceNet error results

The existing 3.60 SceNet database was read through IDA (`tls_fixer-bio-net-return-audit`). `sceNetSend` forwards to 0x8115BE6C. On a successful syscall it returns the byte count. On an errno-style negative syscall result, it writes the positive errno to the network error slot and returns that value combined with 0x80410100. Other encoded errors are returned separately.

This supports the browser BIO's use of encoded `SCE_NET_ERROR_*` results. Replacing it with an unconditional POSIX -1/errno convention would not be justified by the inspected native function. This audit does not prove that a failing real-device connection reached the BIO.

The UDP recorder also obtains the libc and SceNet error pointers per invocation and restores their values before returning. No cached cross-thread errno pointer was found in the current source.

## WebKit request configuration and worker stack

The 3.60 `SceWebKit.enriched.elf.i64` contains the resource-handle logic; the small `SceWebKitProcess` module is a bootstrap, not a substitute for that code. The separate normalized 3.65 WebKitModule database had incorrect ARM-mode decoding in the inspected Thumb range and was not used to infer behavior or patched speculatively.

In the correctly decoded 3.60 database, request configuration at 0x83368F22 calls the compatibility setopt import with the recognizable curl selectors for TLS version, peer/hostname verification, cipher selection, callbacks and HTTP version. The inspected function does not install an SSL-context callback. This is a narrow statement about one setup function; other request/customization paths remain possible. Its hostname-exception behavior was not modified.

Resource-manager initialization at 0x8336782C creates `RscHdlMan:Worker` and `RscHdlMan:verifySslThread`. The verification worker drains a queue and invokes client/UI-facing callbacks; that limited chain did not expose an unconditional native SSL-pointer dereference.

The thread-creation chain is 0x836FFC2C -> 0x83700156 -> compatibility NID 0x7FA4513E. The bundled compatibility export table resolves that NID to 0x81156CB8. Its attribute initializer at 0x81156E38 stores a 0x10000-byte stack request, while the name setter at 0x81156E60 changes only the name. The create wrapper has a separate 0x100000-byte special case for the exact name `WebThread`; `RscHdlMan:Worker` does not match that name.

Thus the inspected worker creation path requests 64 KiB. Actual runtime stack headroom, an alternate thread path, and maximum nested library usage are not established by that nominal request.

## Separate compiler stack-usage build

A new local-only directory, `build/runtime-stack-audit/`, was configured with the established Release hard-float runtime-provider profile and `-fstack-usage`. The existing deployment artifacts were not rebuilt in place. The build completed with no unresolved provider ELF symbols; log: `build/runtime-stack-audit-build.log`, ending `LOCAL_STACK_AUDIT_BUILD_COMPLETE`.

`build/runtime-stack-frames.json` contains 137 compiler reports / 1376 function entries, including translation-unit functions that may subsequently be discarded by linking. Selected individual frames are:

| Function | Compiler-reported bytes |
| --- | ---: |
| module_start | 528 |
| hook_connect | 48 |
| tls_fixer_browser_connect | 120 |
| tls_fixer_runtime_mark | 104 |
| tls_fixer_browser_recv | 72 |
| tls_fixer_browser_send | 64 |
| tls_fixer_browser_check | 56 |
| tls_fixer_browser_close | 48 |
| mbedtls_rsa_rsassa_pss_verify_ext | 1144 |
| psa_key_agreement_internal | 1088 |
| mbedtls_ssl_decrypt_buf | 1064 |

These are individual static compiler frames, not a maximum call-chain bound. Imported Sony routines, indirect callbacks, recursion and existing caller frames must be included before making a total-stack claim. The initial bounded IDA callgraph included intra-function edges and hit its edge limit, so it was not used as a peak-stack calculation.

The new audit ELF is 497324 bytes, SHA-256 `b7d53c3526c4d7ccb856c2b9003e63e74c29505e89d75b4877c517712885fe40`. The preserved runtime ELF is 497292 bytes, SHA-256 `af346ba9b71878b30b4704531a588efc0527bc0cc8cfa32d34caa3e27244421d`. A proposed loadable-segment comparison was tool-blocked and did not produce a comparison result; do not assert that these two ELF instruction images are identical. The preserved device-test kernel retains SHA-256 `429b594c59aaff7082574121d521ce1e1e5801998b858b9aa35b5ac37e98d3c7`.

## Launch-error reference

The SwitchView UI author's original release page independently describes C2-12570-5 when its launcher opens system applications, followed by successful manual reopening. This is a primary historical report of a similar launcher symptom, not evidence that its root cause or fix is identical to this device:

https://vitahex.weebly.com/games/switchview-ui (2017-10-20; accessed 2026-10-10).

The local vitacompanion source sends `psgm:play?titleid=...` and reports `Launched.` from the URI API return. Its built local artifacts have not been shown byte-identical to the installed companion. Native AppMgr analysis confirms additional request processing after the URI entry point; neither that source nor a nonnegative URI return proves page loading. No alternative launch URI or new companion build was sent to bypass the blocked Start action.

## Remaining discriminator

An actual page load with the already installed passthrough control is still the highest-value missing result. It would separate a generic hook/continuation or browser-launch problem from the enabled TLS backend. Until that result or a matching crash artifact/runtime trace exists, the inspected ABI, error convention and stack figures do not justify a speculative TLS or kernel patch.

## Further prologue and metadata review

The exact compatibility database was reopened as `tls_fixer-continuation-prologue-audit`, later `tls_fixer-compat-getinfo-wrapper` after the first worker expired. Scoped instruction reads confirm that close and pending begin with PUSH plus two register-only address calculations. The health and connect prologues use MOVW/MOVT pairs for their relocated stack-guard address. This inspection does not establish a bad relocation, nor does it validate the installed taiHEN trampoline bytes. No detour or framework change was made.

The native getinfo implementation at 0x810A6C8C has a separate metadata path for selector 0x40002B. It returns a structure at easy + 34604, checks the two native SSL-use bytes (connection + 356, stride 24), and, when one is set, publishes backend value 1 and the native context pointer from connection + 364. The context load is at 0x810A7222 and its output store at 0x810A7226. The replacement transport deliberately does not populate that native context. Therefore the four transport hooks alone are not a demonstration of complete TLS-metadata compatibility. No actual caller dereferencing a NULL context was established, and this observation must not be described as the cause of the content-process crash.

The exported getinfo wrapper is 0x81093C10/Thumb entry 0x81093C11, NID 0x70C6F106, verified against the saved bundled ELF export table. The 3.60 WebKit import lookup resolves that NID to 0x83A5E914. Its caller query was tool-blocked and not rerouted. A separate already-identified internal compatibility caller at 0x81007584 uses selector 0x100001 (the URL path), not the TLS-context selector; it does not establish the missing metadata consumer.

Numeric `insn_query` operand filters did not match the visible memory-displacement operands in this database. The complete scoped rendered-listing search was used instead; its 45 hits must not be substituted with the earlier empty numeric-filter result. Several neighboring SSL routines are merged in Hex-Rays output after stack-check failure paths, so function-level pseudocode alone also overstates which routine owns each access.

## Integrated passthrough coverage

Added `tls13/tests/browser/test_passthrough_integration.c` because the existing module test substitutes the backend, while the backend loopback test does not invoke the module wrappers. The new executable links the real module, backend, registry, crypto initialization, CA parser and Vita platform shims. Only platform operations, module identity and hook installation use host fixtures.

Seven scenarios cover terminal continuations, a next-hook chain, four concurrent callers and failure at each of the four hook-installation positions. The native connection fixture contains deliberately invalid embedded pointers. The disabled backend must neither parse those pointers nor mutate the connection; every installed callback must forward the original arguments, result and completion byte, leave the connection registry empty, and avoid TLS network I/O. Network calls are guarded by link-time wrappers, and the test checks that entropy consumption does not advance during passthrough. Partial publication is exercised with the real retained backend rather than a successful-init stub.

The first seven sanitizer scenarios passed. The first full normal build then correctly rejected a test-fixture thread-local pointer left referring to a returned stack object; the fixture now clears that reference before its thread returns. No production behavior was changed. The final complete run, `build/passthrough-integration-full-final.log`, passed **221 normal CTest targets, 221 sanitizer/leak-checking CTest targets and 85 Python tests**, ending `PASSTHROUGH_INTEGRATION_FULL_VERIFIED`. This is additional coverage, not a reproduced or repaired Vita crash. The host hook fixture does not relocate ARM instructions or execute the actual Sony TLS continuation.

## Latest preserved device state

A single read-only collector invocation saved `build/device-evidence/146-log-capture-20261010T103453Z-639fe3c7/files/`. Its command-output poll was tool-blocked; the completed saved log was read without repeating the poll or collector. The exact disabled configuration and the 20645-byte kernel remain unchanged, as do all six protected files. The trace is 6041 bytes, SHA-256 `87f5e82fec48f70fa300eabbd679a834088d94fd6a042dabcdf5c333d6a54600`, with 37 complete records and no provider-start interval. Its extra records are media metadata/PNG-promoter loads. The independent report agrees on 37 attempts, 108 loader calls and no recorded logger error. The capture contains no browser log; its historical core inventory still does not identify the crash PC.

No device payload, configuration byte, browser launch, Start tap, reboot or re-arm was performed during this continuation. A later local timing-correlation command over a saved runtime cycle was also tool-blocked and produced no correlation result. The current control still requires a genuine page-load observation before it can discriminate the backend from the hook/launch path.
