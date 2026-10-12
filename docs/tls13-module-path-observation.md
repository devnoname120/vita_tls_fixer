# Browser module-path observation

## Purpose and limits

The browser-only activation test reached LiveArea but the user's Cloudflare response reported TLSv1.2. The saved trace contains HTTP/SSL paths and no browser-provider startup. That trace records only paths the old matcher recognizes; it cannot distinguish an unrecognized compatibility-module path from a module loaded outside that path or before the observed interval.

This diagnostic preserves the existing path redirection and observes every call into the already-gated loader hook. It does not start the TLS providers or DNS helper. It is a routing observation, not a TLS 1.3 attempt or a boot-crash fix. It deliberately retains the last successful redirection-only boundary rather than enabling a new guessed path.

The first operation remains self-disarming. The build uses general registers only, and the actual linked instructions are checked. Neither characteristic guarantees safety before module_start or before the disarming writes complete. A successful previous one-shot recovery is evidence for that observed failure, not every possible power-loss condition.

## Files and placement

The downloadable ZIP contains only these two files:

- `tls_fixer.skprx`: place at `ux0:/data/tls_fixer-one-shot/tls_fixer.skprx` only while its boot entry is disabled, preserving the old copy under an inactive name.
- `tls_fixer-disarm-result.txt`: place at `ur0:tai/tls_fixer-disarm-result.txt`; it starts with PENDING and identifies the new kernel hash.

Save the current result and `ur0:tai/tls_fixer-startup.log` before replacing the report or starting another test. Never use an earlier VPK/full refresh. Do not change boot_config, YAMT, other plugins, CA files or the Sony modules.

The established internal config entry is `ux0:/data/tls_fixer-one-shot/tls_fixer.skprx`. Self-disarming replaces its initial `u` with `#`, yielding `#x0:/data/tls_fixer-one-shot/tls_fixer.skprx`. Re-enabling is an explicit one-character change back to `u`, not deletion of the comment character. Verify the full configuration after the change. All other bytes must remain unchanged. A concurrent config editor must not save during startup.

## Test sequence

After exact kernel/report and single-entry read-back verification, perform one normal manual reboot with the removable card present. Do not hold L, run the installer or change the configuration again.

Report whether that first boot reaches LiveArea. Save the fresh result and trace before further testing. A failed first boot should leave the experiment disabled for the following normal power-on once disarming completed; do not automatically re-enable after a crash.

During the same successful first-boot session, open the browser once and request the previously used diagnostic page. This is to trigger browser module loading, not to require TLS 1.3 in this observation-only build. Keep FTP available and capture the result/trace again. Do not reboot or rerun staging helpers before capture. Because paths are recorded synchronously, this run may add loader latency.

## Reading the evidence

`startup.replacements` uses object bits 0..4 for compatibility, HTTP, SSL, DNS helper and commerce file presence. `startup.providers` uses bits 0/1 for HTTP/browser identity-and-resource readiness. These record conditions, not proof of hook activation.

Every `load.enter` now includes route kind in `obj`, incoming flags in `rc`, and the original path. A changed destination adds `load.selected` with that path. Route kind 0 is deliberately recorded, not discarded; 1/2/3/4 denote the known HTTP/SSL/browser/commerce selections. `load.return` and `hook.return` place the native result or module ID in `obj`, and route kind in `rc`. Do not interpret a positive route code as the native return value.

Paths are hexadecimal byte strings, never raw injected log text. `pathlen` records the bounded source length; `ffffffff` means NULL, zero means empty, and 1024 is a lower bound for a nonterminated input. Only the first 128 bytes are stored. The log allows at most 512 records, each at most 512 bytes. A saturated log, truncated path, partial last record or logging failure cannot establish that the browser path was absent. The record buffer is static, not a new 512-byte stack frame.

Analyze a saved file locally with `python3 tools/analyze_boot_trace.py <saved-trace>`. `module_paths` decodes the captured bytes and marks truncation. The analyzer intentionally does not infer a successful boot or TLS negotiation from a trace alone.

The analyzer's completed intervals and negative-return records identify `result_field` explicitly. For `load.return` and `hook.return` the decoded native result comes from `obj`; their raw `rc` remains the route kind. Other operation returns retain `rc` semantics. A failed load can appear in both loader-return and hook-return records: those are two observations of one result, not evidence of two failed native calls. Earlier analyzer output incorrectly used the route kind for these return values; reanalyze saved logs with the corrected script before interpreting their errors.

## Verification

The fresh verification log is `build/module-path-full-verification.log`: 103 normal and 103 sanitizer CTest targets, 30 Python tests, observer/default native builds and decoded-register checks pass. Four invalid profile combinations are rejected. The default kernel remains byte-identical to the previously checked baseline. Raw native entry and hook disassemblies are saved beside the verification log; the package receipt holds hashes and source identities.

No hardware result for this diagnostic is established by those tests. The user's last read-only capture of the earlier browser-only build is preserved under `build/device-evidence/146-browser-route-20261009T112400Z-882d46/`.
