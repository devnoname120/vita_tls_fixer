# First browser TLS 1.3 hardware test

**Testing suspended:** a user-reported crash at the boot epilepsy warning is under investigation. Do not install or refresh either exported test build. The immediate recovery action is L-held plugin-bypass boot, then disabling only the tls_fixer kernel entry in the active taiHEN configuration. Preserve backups and do not format or restore the system. The procedure below is historical until the boot failure is understood and corrected.

This package contains the browser backend, not just the earlier SceHttp adapter. It is an experimental hardware-test build. Host TLS tests and cross-compilation have passed; no Vita browser result has yet been recorded.

Use the **revision-2** VPK (`tls_fixer-TLS13-browser-test-r2.vpk`). It corrects provider loading when Sony's native loader receives PID zero for the current process. The earlier VPK with SHA-256 `4f289628815da2f568e02f8aed2a83709efa3a83bf5e8eb860fdb88d88cb4464` can miss that injection path and is superseded. A previously downloaded or FTP-staged copy does not update automatically.

## Install or refresh

Keep a copy of the existing taiHEN configuration and installed tls_fixer files before testing. The package changes files in `vs0:/data/external/tls_fixer/`, the CA bundle, and the tls_fixer kernel plugin. Do not interrupt installation or reboot while files are being copied.

Install the new VPK, open its installer and press **SQUARE** to refresh the full package. This explicitly updates the kernel loader even when an older tls_fixer installation is already present. The existing original CA backup is preserved. Let the installer reboot only after it reports success. Do not attempt to hot-unload either provider.

The refreshed directory should contain:

```text
vs0:/data/external/tls_fixer/ScePsp2Compat.suprx
vs0:/data/external/tls_fixer/tls_fixer.suprx
vs0:/data/external/tls_fixer/libhttp.suprx
vs0:/data/external/tls_fixer/libssl.suprx
vs0:/data/external/tls_fixer/tls_fixer_http.suprx
```

The kernel plugin remains `ur0:tai/tls_fixer.skprx`. Additional firmware-3.60 compatibility modules are installed by the existing firmware-specific path.

## Prove TLS 1.3 rather than a cached page

Use an endpoint restricted to TLS 1.3 and a certificate whose hostname and chain the installed Vita CA bundle trusts. Check the Vita's date/time. Do not disable certificate verification to make a failing test pass.

The repository includes a minimal diagnostic server:

```sh
python3 tools/tls13_test_server.py \
  --cert /path/to/server-fullchain.pem \
  --key /path/to/server-private-key.pem \
  --port 8443 --tls 1.3
```

Run it on an isolated test network, not as a production web service. The certificate's DNS name must resolve from the Vita to this server and the port must be reachable. A local test CA can instead be added to a dedicated test bundle, but that is a deliberate trust-store change; do not replace normal certificate validation with an accept-all callback.

Open `https://<certificate-hostname>:8443/` in the Vita browser. The page reports the server-selected TLS version, cipher, fresh response token, UTC time and test-run ID. The server prints the same record. A matching **TLSv1.3** record and visible page are the first success criterion. The fresh response token prevents a previously cached page from being mistaken for a new request.

Restart the diagnostic server with `--tls 1.2` on a separate port and repeat. Both versions should work through the new backend. A public website that supports both TLS versions is useful for compatibility testing, but a loaded page alone does not prove which version was selected.

## Collect diagnostics

When permitted by the browser process's filesystem policy, the provider writes:

```text
ux0:/data/tls_fixer-browser-<PID>.log
```

The same records are sent through `sceClibPrintf`. Each provider instance emits at most 512 bounded records; restart the browser before a fresh diagnostic run. Old per-PID files may remain and should not be confused with the latest run. File logging failure does not disable or weaken TLS.

Look for:

```text
browser TLS active: compat=... text=...
browser handshake complete: socket=... version=TLSv1.3 cipher=...
```

If a page fails, retain the browser error, firmware/model, VPK hash, the latest provider log, kernel debug output when available, and the server's TLS/HTTP logs. The kernel's provider-load record is not itself proof that the browser TLS backend activated. A partially failed hook installation deliberately leaves a disabled forwarding module resident and logs that fact.

Interpretation:

| Observation | Meaning |
| --- | --- |
| No activation record | Investigate provider loading, namespace access, module-ID conversion, identity checks, CA parsing, or logging permissions. |
| `browser TLS inactive` | Hook installation did not complete; the original backend remains selected. |
| `browser connection uses legacy TLS` | This request selected an unsupported custom TLS configuration and was left on embedded OpenSSL before any provider handshake. |
| Activation followed by a handshake error | Loading succeeded; examine the error, trust/hostname/date, and server negotiation. |
| Provider and server both show TLSv1.3 and matching page token | Browser TLS 1.3 succeeded for this device/configuration/endpoint. |

Do not infer that one success validates every firmware, proxy, custom-certificate configuration or lifecycle path. The larger matrix in `tls13-hardware-validation.md` remains necessary for a release.

## Recovery

Do not hot-unload the kernel plugin or user providers. Reboot to remove active hooks. Use the installer to remove or refresh the package; a full uninstall removes both providers and the replacement modules, removes its own configuration block, and restores the original CA bundle when its backup exists. If no original CA backup exists, the installer leaves the current CA file unchanged rather than pretending to restore stock data.

As with other kernel-plugin testing, retain access to the device's existing plugin-recovery method and a known-good tls_fixer package. A crash, freeze or missing activation log is a failed test, not a reason to assume TLS 1.3 negotiated.
