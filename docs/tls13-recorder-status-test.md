# Recorder-status diagnostic and original-tls_fixer comparison

## Evidence motivating the change

The process-namespace observer's first boot reached LiveArea and was independently verified. Loading the browser's Cloudflare trace page returned TLS 1.2, as expected for an observation-only build. The log advanced from 19 to 22 records, adding only `vs0:sys/external/libpaf_web_map_view.suprx`. After closing the browser and opening Settings, the saved log remained byte-identical. The captures are:

- `build/device-evidence/146-browser-route-20261009T132553Z-5b2e46/`
- `build/device-evidence/146-browser-route-20261009T133346Z-ef49c4/`

Both logs have 3495 bytes and SHA-256 `a15169c233422c06adf9a4fb41f9352aad899197758eb1890511253f842b2175`. The kernel is still the 14200-byte process observer; its boot entry remains disabled and its startup report completed. No browser-provider log was found. Missing trace records are not proof that no module was loaded: a failed recorder or inactive hook has not been excluded.

## Comparison with original tls_fixer

The repository's original `kernel/main.c` uses the same internal Modulemgr hook at offset 0x21EC. It redirects the compatibility-module filename in the incoming kernel buffer, but does not install user-space TLS transport hooks.

Its suffix has no leading slash: `webcore/ScePsp2Compat.suprx`. Our newer helper required `/webcore/`, rejecting a valid colon-root spelling such as `mount:webcore/ScePsp2Compat.suprx`. The helper now accepts both colon-root and slash-root forms, preserves the mount and preceding separator, and requires a real component boundary. It retains bounded reads/capacity checks and uses separate output storage rather than restoring the original underflow-prone in-place logic. Provider and CA path derivation are corrected consistently. A regression failed before the fix and passed afterward.

This is a confirmed source compatibility gap, not proof that the live browser used that spelling. No captured browser compatibility path yet exists. The default kernel consequently differs from the preceding baseline intentionally; do not describe it as byte-identical. The user provider must eventually be rebuilt with the corrected path helper too, but that is not part of this kernel-only diagnostic deployment.

IDA also shows `fun_LoadStartSharedModuleForProcess` calling the same intercepted loader with flag 1 added. Sharing by itself does not bypass that common function, although the process-namespace observer can omit calls lacking 0x1000. The cached taiHEN user-hook API documents rejection of shared-memory targets. Actual mapping and the installed implementation must be verified before installing the browser hooks; this work does not patch shared memory globally or bypass that limitation.

## Independent recorder status

The observer now counts every invocation of its loader hook using a 32-bit atomic increment, including requests omitted by the path filter. The recorder separately counts attempted records and retains its first fatal native error and operation. Busy/reentrant attempts increase the attempt counter but do not overwrite a fatal error. These counters wrap after 2^32 operations; they are diagnostic per-boot samples, not durable global totals.

A 16 KiB kernel worker samples the counters every 100 ms outside the loader hook. It publishes only when values change, at most 128 times, using reserved spans of the existing preallocated 256-byte `ur0:tai/tls_fixer-disarm-result.txt`:

| Field | Meaning |
| --- | --- |
| `err` | First fatal recorder result, hexadecimal; zero means none recorded. |
| `op` | 1 = thread-ID query; 2 = stack-headroom query; 3 = positional write; 4 = file synchronization; 5 = record cap. |
| `a` | Number of record attempts, including refused attempts. |
| `h` | All loader-hook invocations, including filtered-out requests. |
| `m` | 1 = normal publication; 2 = publication budget reached, worker stopped updating. |

The publisher writes only bytes 160-191 and 224-251. Gate fields, `trace_setup` at 192-223, file length and `END` at 252-255 are preserved. Each span is synchronized separately; the two spans and atomic counters are not an all-or-nothing snapshot. Failed/partial publications must not be interpreted as a complete diagnostic state.

The worker uses its own open/write/sync/close cycle. It does not reuse the retained trace descriptor and does not enumerate modules or start TLS. If it cannot publish, the report may remain absent/stale; this mechanism does not guarantee evidence from every fault. `m=1` is the last publication's mode, not an independent liveness heartbeat.

Self-disarming still runs before report/trace/worker initialization. The worker starts before hook installation. Failed startup cleanup must join the worker before releasing its code; inability to join or delete it retains the module inert rather than claiming it is safe to unload. Active hook residency rules are unchanged.

## Device test

Keep the preceding kernel and both evidence captures. Stage only the new kernel at the fixed removable path and its fresh result file. Preserve and verify the current disabled configuration, boot_config, YAMT and internal FTP files. Deliberately restore only the own entry's first character after staging passes. No VPK, user-provider, Sony module, CA, storage-driver or firmware replacement is part of this test.

Request one manual normal reboot after full verification. First confirm the correct kernel, a fresh completed gate/setup report, the namespace marker, successful hook installation, and the result-file status fields. If the reporter has already failed or reached its budget, preserve that evidence rather than blindly continuing.

Only then request a browser load in the same session and capture again. Increased `h` with increased `a` but a stopped trace and nonzero `err/op` identifies lost recorder evidence. Unchanged `h` does not by itself prove that the browser uses shared modules: the control action, module lifetime and hook chain still require checking. A successful path capture can identify the actual mount spelling and native result before selecting another change.

This remains an observation-only kernel. TLS 1.2 on the test page is expected; no browser TLS 1.3 result or repaired full boot is asserted.
