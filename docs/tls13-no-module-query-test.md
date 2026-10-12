# Runtime module-query isolation diagnostic

This is a preparation-only diagnostic, not a TLS-enabled build or a crash fix.
The preceding native 16 KiB preparation test still crashed by user report.
Its post-boot retrieval confirms the exact kernel and persisted self-disarming.

## Experimental difference

The new profile keeps the existing one-shot entry, independent disarm report,
synchronous boot trace, native 16384-byte stack, private hash/query allocations,
file reads, SHA-256 validation, reservation cleanup, redirection and hook return.
It omits only the runtime preparation module enumeration and module-information
queries, including the target PUID/name query. The trace records `scan.skipped`
and `target.skipped` instead of pretending those checks ran. Startup export
lookup and module search used by the measurement/hook setup are unchanged.

The omission is guarded by `TLS_FIXER_PREPARE_NO_MODULE_QUERIES` and requires the
traced native-stack preparation-only profile. There is no user TLS provider or
DNS-helper startup in this binary. Normal builds retain all module queries and
validation. A zero preparation return in this diagnostic does not establish
that a provider was loaded, that all prerequisites were validated, or that TLS
1.3 is usable. Generic existing printk messages are not stronger evidence than
the explicit skipped-stage trace records.

Host tests reject any runtime call to either module-query API in this profile.
They require both workspaces and their cleanup, repeated reservation reuse,
both HTTP and browser routes, retained hash rejection and propagated trace,
allocation and native-stack failures. The generated callback is checked in
IDA as well as in the executable disassembly. Its frame changes from 216 to
184 bytes, while the native stack request remains 16384; removing queries also
changes timing and the number of synchronous log writes.

## Handoff

The download contains only `tls_fixer.skprx` and `tls_fixer-disarm-result.txt`.
Hashes, source identities, test evidence and this document stay in the worktree.
Preserve the previous kernel, result TXT and startup log before another attempt.
The fixed device paths remain:

```
ux0:/data/tls_fixer-one-shot/tls_fixer.skprx
ur0:/tai/tls_fixer-disarm-result.txt
ur0:/tai/tls_fixer-startup.log
```

Only the existing tls_fixer line in `ur0:tai/config.txt` is deliberately re-enabled
by replacing its initial `#` with `u`; do not add duplicate entries, change other
plugins, copy a whole configuration, or run the old VPK/installer. Verify the
selected payload and current configuration before requesting a manual reboot.
All reboots are performed by the user, never through a tool. Do not re-arm in
response to a crash without reviewing the observation.

## Required result

Record whether the first boot reaches LiveArea directly or crashes/shuts down.
Afterward preserve the new report/log, confirm the exact disabled config, and
check that stack callback, both skipped-query markers, hashing, allocation
cleanup and hook return actually executed. An early refusal or skipped hook is
not a successful control. A successful boot would implicate the removed work
or its timing, not prove that a particular module API is defective. A continued
failure would show those runtime queries are not required for this fault.

The unchanged self-disarm gate acts before instrumentation and experimental
initialization, but cannot cover faults before its durable edits complete.
The removable payload remains an additional fallback. No system-module, CA,
storage-driver, boot_config or firmware change is part of this test.
