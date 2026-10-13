# sceHttp activation evidence and diagnostics

The logged Vita TLS Check run on the primary retail 3.60 console reaches the replacement Sony HTTP/SSL modules without the user TLS provider loaded. This is a provider activation problem before testing its TLS engine or certificate handling.

## Evidence from the existing boot

The first instrumented checker launch produced 265 sequential records, including five complete request lifetimes and five complete module inventories. The raw trace is retained under `build/logging-20261013/api-003C258F-18452729518.log`; the parsed inventory and request results are in `analysis.json`. Runtime process ID: `003C258F`.

| Observation | Result |
| --- | --- |
| Before network loading | 12 modules, all module-info queries successful |
| After HTTPS loading | 16 modules, all module-info queries successful |
| After HTTP initialization and requests | Same 16 modules |
| Sony HTTP module | `SceLibHttp`, UID `40010107`, text size 119120 bytes |
| HTTP source path | `vs0:/data/external/tls_fixer/libhttp.suprx` |
| Sony SSL source path | `vs0:/data/external/tls_fixer/libssl.suprx` |
| `tls_fixer_http` | Absent from every complete inventory |
| `SceLibc` | Absent from every complete inventory |
| NET/HTTPS load, SSL/HTTP init, verification options | Return success |
| Template, connection and request creation | Return valid handles |
| Failure boundary | `sceHttpSendRequest`, for all five endpoints |
| Request result | `0x80431075` |
| Report and TLS 1.3 endpoint SSL result | `0x80435061`, detail zero |
| TLS 1.0-1.2 endpoint SSL result | `0x804351FE`, detail zero |
| HTTP response/body | No status or body received |
| Cleanup | Request, connection and template deletion return success |

The newlib homebrew does not preload Sony libc. `kernel/CMakeLists.txt` forces `TLS_FIXER_PREPARE_NAME_QUERY=ON` in the normal coordinator, confirmed by the normal cache and compile configuration. `kernel/tls13_loader.c` checks for `SceLibc` before loading the HTTP provider. The provider links `SceLibc_stub` for its C runtime imports, so the missing module is a real unmet prerequisite. The existing production-context host test also asserts that a missing or invalid libc prevents provider loading and start-argument allocation.

The current untraced coordinator does not provide a persisted record of which kernel branch returned first. The exact skip branch is therefore inferred from the source, compiled profile and absent runtime prerequisite. The directly observed conclusions are narrower: redirection works, Sony HTTPS initializes, the HTTP provider is absent, Sony libc is absent, and requests fail in SendRequest. No provider handshake ran in this process. Do not attribute these failures to the provider's CA bundle, ciphers or Mbed TLS verification.

The prior Browser TLS 1.3 successes belong to a different process and activation path. They do not establish that a newlib homebrew satisfies the generic provider's import requirements. Adding explicit plugin loading or a TLS backend to this checker would defeat its purpose; keep its ordinary Sony API path.

## Added visibility

| Layer | Diagnostics |
| --- | --- |
| Checker | Per-launch file; PID, TID, monotonic time, sequence, run and request IDs |
| Sony API calls | Entry, return, native error, call duration, handles, timeouts and cleanup |
| Module loading | Generic inventories around network loading, HTTP initialization and requests |
| Coordinator | Existing activation recorder gets a distinct `prereq.libc.missing` reason |
| HTTP provider startup | Start arguments, mapped module identity/extent, signature failure index/byte, crypto setup and hook install results |
| Trust store | File open result/size, parser result and root count |
| Backend choice | Provider-owned versus Sony continuation, setup skip/failure reason |
| Transport | Connection state/options, registry/lock results, handshake entry/return, native socket result and byte counts |
| Verification | Raw verification flags, filtered policy flags, callback decision and peer presence |
| Error propagation | TLS/net/provider outcome and resulting Sony HTTP/SSL errors |

The HTTP provider now uses the existing bounded file trace infrastructure instead of console-only diagnostics. Its file is `ux0:/data/tls_fixer-http-<PID>.log`, with the existing savedata fallback if the primary open fails. HTTP diagnostics are limited to 4096 records per process; Browser retains 512. The final record identifies exhaustion explicitly. Partial writes are handled and a failed sink does not change transport results. Every provider record includes component, PID, TID, time and sequence. Payloads, private keys, cookies and certificates are not dumped.

Logging adds file I/O and can affect timing. No additional kernel memory/allocation probe, hook mode, provider activation, reboot, certificate change or verification bypass was used to collect this evidence. The normal coordinator's boot recorder remains disabled. The added prerequisite event is compiled out in that profile.

## Device scope and validation

Only the checker executable, its VPK and its own data folder were updated. Prior executable/VPK bytes were preserved with per-file backups and readback hashes. The disabled taiHEN configuration and protected kernel, provider, certificate, storage and companion resources were checked before the run. The fresh API file, contiguous records and completed run are execution proof; the companion launch acknowledgment alone is not used as proof.

The ordinary tls_fixer installer package and the currently active kernel/providers remain unchanged. The richer provider logging is cross-built for the next prerequisite-qualified test; it has not been activated on the console in this pass. Host tests cover both Browser and HTTP file sinks, bounded/truncated records, explicit exhaustion, primary/fallback/unavailable storage, short writes and write failures. Build/test and final checker artifact identities are retained in `build/logging-20261013/`.

The final checker build produced 270 contiguous records in process `009D2105`, with the same complete inventories and SendRequest failures. Its VPK SHA-256 is `0c5590618908094b927e7f7e1f23d0695f588ba234bbc1f5b6ad6f624f2ac390`; installed executable is `355f04af4a2e798a93c875b0dbf625e36d5c3bbf3272498c9cc40be23972e38a`. The final trace and readback receipts are under `build/logging-20261013/final/`. There were two checker launches and zero reboots. Native checker/HTTP/Browser builds and the kernel register gate pass; the normal kernel is byte-identical. Host tests pass 349/349 normally and with sanitizers.

No successful generic-provider HTTPS handshake or fix for the earlier Browser freezes is claimed here. The next transport change must address the proven missing runtime prerequisite, preserve the backend-independent checker and explain its activation result before attempting Browser again.
