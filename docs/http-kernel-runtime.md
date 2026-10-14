# HTTP provider native runtime and mapping safety

The HTTP provider uses SceLibKernel/SceSysmem instead of importing Sony's full SceLibc or Paf. On retail 3.60, the normal combined coordinator has passed Browser TLS 1.3 plus strict sceHttp TLS 1.2/1.3 in three distinct checker processes, including two normal exits/relaunches. The exact self-disarming VPK kernel/providers subsequently passed the same Browser control and nine modern requests across three fresh processes at the final native provider paths. Chronological failed/successful test identities and receipts are in TLS13_PROGRESS.md sections 23.315–23.331.

## Runtime

`tls13/provider/user_runtime.c` supplies linker wrappers for the C functions referenced by the HTTP provider and unchanged static dependencies. Allocation uses a process-private 2 MiB memory block, sceClibMspace functions and a native mutex. It rejects calloc overflow, preserves allocations on failed realloc, accounts for outstanding allocations and refuses live-heap destruction. Module startup validates ownership before allocating the runtime; startup failure cleans up, and hot unloading remains rejected.

Memory/string operations and formatting use sceClib functions. Native testing showed sceClibVsnprintf can omit NUL termination on truncation while returning the required length. The wrapper supplies the C99 termination contract expected by the unmodified dependencies. Native hexadecimal, 64-bit, size_t, truncation and size-only formatting were exercised.

The HTTP target removes SceLibc_stub and redirects calls with linker --wrap options. All 943 pinned Mbed TLS/TF-PSA C/header files compare byte-for-byte with the source archive; OpenSSL's installer sources are unchanged. No dependency source patches or libk implementation are needed. `tools/check_http_runtime.py` validates the actual SELF imports, including variable-only libraries.

## Activation and ownership

Both native shared-request bits 0x08000001 must be cleared for eligible HTTP/SSL replacements. The native module-manager sharing classifier can still return shared for physically private library allocations. The user provider therefore checks complete allocation bounds/types and permissions with Sysmem before heap or hook publication. HTTP executable text must be private type0x0C20D050 and data private type0x0C20D060. Retail3.60 sometimes reports RX access4, accepted only for that exact executable type with no write permission. Unknown/shared types, failed queries, overflow, truncated allocations and writable text fail closed. SSL getter hooks require a private SSL text mapping as well.

Shared Sony consumers cannot import exports from a private HTTP library: native startup returned MODULEMGR_CANNOT_EXPORT_LIB_TO_SHARED (8002D018), followed by OLD_LIB (8002D013) on retries, before provider entry. The normal coordinator now inspects actual HTTP/SSL importers through existing native module APIs. Shared or unclassified importers preserve Sony load flags and transport; Shell is excluded immediately, and ScePaf was independently identified in the failed startup trace. The paired HTTP/SSL modules and provider have separate exact/private ownership gates. Browser controller/helper processes are excluded from generic HTTP activation and continue through the dedicated Browser provider.

This conservative gate is a coverage boundary: shared/unclassified consumers retain Sony TLS, and native classification can exclude some physically private libraries. It does not promise universal SceSsl replacement. Private process mappings disappear at exit, preventing hook code from surviving after taiHEN frees process hook records.

## Other corrected integration defects

Relocated MOVW/MOVT immediates are accepted while the validator checks instruction opcode/register and surrounding fixed code. The authoritative installer-owned CA path is converted through AppMgr's process namespace. SSL getter hooks are deferred until HTTPS module loading is complete, installed under the registry mutex, and rolled back if the complete set cannot be installed. Post-handshake ticket/WANT_READ transitions retry within a fixed budget when no socket error is present; real socket timeouts retain their error behavior.

## Evidence and limits

The native smoke test found and corrected the formatter mismatch, then returned failures0 with zero outstanding allocations. Scoped HTTP runs and the normal broad boot each passed three strict modern requests in three separate checker processes. Normal broad kernel2a8b1e67 used HTTP8716ce3a and Browser6d035203; user reported a fresh Cloudflare TLSv1.3 response. Exact packaged kernel61960ee6, HTTP8716ce3a and Browserb6e04edd repeated the Browser result and three application lifetimes000332A5,00132AE5,00152CD1 at the final native paths. Per-process API/provider/server reports are in build/runtime-fix-20261014/normal-qualification/ and package/qualification/.

Legacy TLS1.0/1.1 requests still reject after the provider starts. The repaired modern transport does not cover these versions or retry through Sony after handshake bytes are sent. The TLS acceptance build's355 ordinary/sanitizer host cases and 31available firmware cells pass; five corpus cells are absent. Device evidence is retail3.60 only.

Synchronous/queued kernel recorders can change activation through failure-return gates; one inventory run overflowed its queue and failed to start the Browser provider. Normal VPK packaging explicitly disables every kernel recorder/probe. The final provider destinations are additive native subdirectories, preserving prior provider copies during qualification. Standalone diagnostic builds default to self-disarming before hooks; they never re-arm automatically and cannot cover a fault before module_start or before durable edits complete. The normal VPK explicitly disables self-disarming for the user-requested persistent test, leaving its taiHEN entry configured across reboots. Full installer system-file writes remain distinct from one-shot package execution.
