# Browser prerequisite verification in the target namespace

## Observed failure

The 19589-byte queued browser-activation kernel reached LiveArea. The browser
loaded its replacement compatibility module, but preparation stopped at
`hash.stat.return=0x80010002`. No provider-start attempt occurred. The full
66-record trace is preserved under
`build/device-evidence/146-browser-route-20261009T170615Z-2af998/`.

The user subsequently reported an ordinary reboot without re-arming. The fresh
13-file before-state is `build/browser-namespace-preflight-current.json` and
`build/device-backups/146-before-browser-namespace-20261009T172316Z-ea9475/`.
A stable file is not itself evidence that a worker is inactive; that reboot
report is part of the test precondition.

## Correction

Startup verification still uses the global installed paths. Browser runtime
verification instead preserves the process-specific mount from the actual
provider path. The corresponding compatibility artifact is derived with the
bounded inverse path helper; its buffer is inside the existing query allocation.

Both runtime opens use `ksceIoOpenForPid` with the target PID and read-only flags.
The provider existence/metadata check uses `ksceIoGetstatByFd` and closes its
handle before proceeding. The compatibility artifact is streamed through the
unchanged SHA-256 implementation and compared against the same exact expected
hash. Failed opens, metadata, reads, close or hash comparison refuse activation.
No global-path fallback is used for a failed browser-namespace lookup.

The installed VitaSDK database provides OpenForPid's import stub at NID
`0xC3D34965` but its I/O header lacks the prototype. The local declaration
matches the inspected four-register ABI. In the 3.60 Iofilemgr IDB,
`ksceIoOpenForPid` at `0xBE4890` resolves FIOS overlays for the supplied PID and
returns a kernel file GUID. `ksceIoGetstatByFd` is at `0xBE143C`.

The actual source-built kernel was inspected through IDA session
`tls_fixer-browser-namespace-fix-20261009`. Its first entry call remains self-disarm
at `0x810002BC`. The browser branch derives the path at `0x81003044`, opens the
provider at `0x81003084`, gets metadata at `0x810032B4` and closes at `0x810032BC`.
The stream's process-aware open is at `0x810026AC`. Exact hash and shared-target
checks still precede the provider-start call at `0x8100325C`.

## Verification and artifact identity

`build/browser-namespace-red.log` records the production-route regression
failing before the fix. The corrected normal and sanitizer suites each passed
134 targets; Python passed 34 tests. Activation, default and initialization-only
native kernels built, passed decoded-register checks, and had no unresolved
symbols. See `build/browser-namespace-full-verification.log`.

Tests cover random-mount and colon-root names, malformed paths, insufficient
output capacity, failed process-aware opens, metadata and close errors, wrong
hashes, and the existing shared-target/start-result/lifetime failure cases.
Seven memory-only staging/arming-helper scenarios passed in
`build/browser-namespace-helper-verification.log`, including mismatch refusals
without writes and restoration after a failed publication rename.

New kernel: `build/browser-namespace-activation-kernel/tls_fixer.skprx`, 19858 bytes,
SHA-256 `0afc0bd0d2f83ad34d4a5deedc1184e5f10524dfa530edcb7058147999da0ad0`.

Fresh 256-byte PENDING report SHA-256:
`88a0c2ddadc3540a20c9fd795e502464fc941d5405d9739369fbd8ce7ba7fd65`.

ZIP: `build/artifacts-browser-namespace-activation/tls_fixer-browser-namespace-activation.zip`,
16442 bytes, SHA-256
`d35910b3825f7c15202c1ff1b0a19967ee88f245e2e9556e59bcb82e8e5f55e5`.
Only `tls_fixer.skprx` and `tls_fixer-disarm-result.txt` are in the archive. The adjacent
receipt pins source hashes and the full verification log.

## Device procedure and limits

Use only the separately pinned `build/stage_browser_namespace_files_only.py`
and `build/arm_browser_namespace_once.py`. The first verifies the inactive
before-state and installed resources, preserves prior files/trace, and publishes
only the two inactive diagnostic files. The second separately verifies all
identities and changes only the existing configuration byte 689. Both refuse
mismatches; neither reboots or installs a VPK.

After successful arming and complete read-back, perform one normal manual boot,
report its outcome, and verify the self-disabled entry and fresh report before
opening the browser. Then request the same diagnostic page once and preserve
all kernel/provider logs. Never reset a failed attempt's evidence first.

Self-disarming remains the first entry action and is never reversed by success
or cleanup. It cannot cover a fault before entry or completion of the durable
configuration edit. The active test remains on removable ux0 storage. The
existing kernel worker and bounded queue are unchanged; enqueue success is not
crash durability. No permissions, shared mappings, system modules, certificates,
storage files, or user-space TLS providers are modified by this correction.
The default kernel intentionally changes for this bug fix; byte identity with
the older default is not asserted. Browser TLS 1.3 and the cause of earlier boot
crashes remain unproven until actual device evidence establishes them.
