# Target-module query isolation

This is a local diagnostic candidate, not a TLS release or a confirmed boot fix.
Do not request another boot until the preceding no-module-query test's actual
first-boot outcome has been obtained and its trace/configuration preserved.

## One changed operation

The no-module-query profile records `scan.skipped` and `target.skipped` while
retaining module redirection, reservation locking, private workspaces, runtime
SHA-256 validation, a native-managed 16 KiB preparation stack and cleanup.

The target-query-only profile keeps enumeration disabled (`scan.skipped`) but
restores the single `ksceKernelGetModuleInfo(pid, loaded_guid, info)` call for the
just-loaded HTTP/browser target. Its expected records are `target.info.enter`
and `target.info.return`, not `target.skipped`. It checks the returned PUID and
module name. It does not enumerate or inspect other process modules and cannot
load, start or unload a TLS provider or the DNS helper. The stack-probe's earlier
startup metadata lookup is unchanged; this isolation concerns runtime queries.

A failed target query returns an error and releases the diagnostic resources;
it must not cause fallback to provider loading. CMake and source guards restrict
this option to traced preparation-only native-stack diagnostics. It is mutually
exclusive with the no-module-query option. Normal builds retain all validation.

## Device procedure, once this candidate is selected

Use only the two files from the matching diagnostic ZIP. Preserve the currently
disabled removable test kernel and captured log/report first. Replace the test
kernel at `ux0:/data/tls_fixer-one-shot/tls_fixer.skprx`, and put the fresh 256-byte report
at `ur0:tai/tls_fixer-disarm-result.txt`. Do not use a VPK or change user TLS modules,
certificates, storage drivers, boot_config or any other plugin entry.

Restore only the initial `u` in the existing test entry:

```text
#x0:/data/tls_fixer-one-shot/tls_fixer.skprx
```

The resulting line is `ux0:/data/tls_fixer-one-shot/tls_fixer.skprx`. Do not merely remove
the `#`, and do not add a duplicate. Leave FTP running for read-only verification
of the exact kernel, fresh report, single config-byte edit and protected files.
The user must perform the reboot manually after that check; no tool reboot or
hot-load is permitted.

The self-disarm operation still runs first and leaves the next boot disabled.
It does not protect failures before module_start or before persistent disarming
finishes. A prior observed successful recovery does not guarantee every future
fault is recoverable. No other persistent system change is part of this test.

## Evidence and interpretation

Record the user's first-boot observation separately from any subsequent
power-on. Retrieve `ur0:tai/tls_fixer-startup.log`, the report and the actual config.
Verify the exact self-commented configuration and identify the executed profile
from both the staged binary and its trace. A generic completed report alone does
not establish the identity or final boot outcome.

A positive target-only result after a positive no-query result points toward
enumeration/per-module inspection rather than the target lookup. A failure
narrows investigation to the restored target query or its interaction with the
loader context. Neither result alone proves a root cause: timing and native
execution context still matter. Do not remove production validation merely to
make a diagnostic boot. Keep tls_fixer disabled until the next deliberate test.
