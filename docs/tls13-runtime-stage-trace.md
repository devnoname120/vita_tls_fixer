# Browser runtime stage trace

## Purpose and current boundary

The captured user-argument test reaches `provider.status=0` and completes kernel-side cleanup in both WebKit processes, followed by two user-reported browser crashes. There is no matching fault PC or core dump. The existing provider log path produced no collected user-runtime logs. Successful module entry is not evidence of a completed TLS handshake.

The optional runtime recorder observes the first connection operations without adding another kernel hook or changing certificate policy. This is a diagnostic, not a crash correction.

## Native provider

`tls13/browser/runtime_udp.c` is linked only when `TLS_FIXER_ENABLE_RUNTIME_UDP=ON`. Configuration additionally requires the explicit browser startup-diagnostic profile, a private IPv4 receiver, an unprivileged UDP port, and a 128-bit hexadecimal nonce. Ordinary builds compile the marker calls away.

The recorder initializes its one UDP socket lazily at `connect.enter`, not during module startup. Concurrent calls do not wait for initialization; events may be dropped while initialization is in progress. Initialization failure is not retried. Sends use `SCE_NET_MSG_DONTWAIT`, and at most 128 sends are attempted per provider instance. The socket remains owned by the resident provider until process exit; it is not closed underneath concurrent markers.

Each datagram is exactly 48 bytes:

| Offset | Field | Representation |
| --- | --- | --- |
| 0 | Protocol identifier | Four bytes, `ITR1` |
| 4 | Test nonce | 16 bytes |
| 20 | Sequence | Unsigned 32-bit, network order |
| 24 | Process ID | Unsigned 32-bit, network order |
| 28 | Thread ID | Unsigned 32-bit, network order |
| 32 | Stage ID | Unsigned 32-bit, network order |
| 36 | Result or numeric detail | Signed 32-bit, network order |
| 40 | Device timestamp | Unsigned 64-bit microseconds, network order |

No URL, hostname, certificate, key, page data, memory pointer, or caller-provided string is transmitted. Stages identify dispatch, option parsing, allocation, TLS setup, the native deadline/wait callbacks, handshake, verification, application I/O, native BIO I/O, and cleanup. `active` reports 0x0304 for TLS 1.3 or 0x0303 for TLS 1.2 after the provider's verification checks pass.

Appended stages preserve IDs 1 through 36. `callback.reject` (37) reports the
existing exact-validator rejection code 1 through 13. `callback.policy` (38)
reports a refusal bitmask before that validator: missing userdata 1, missing
validator 2, disabled peer verification 4, disabled hostname verification 8,
or custom CA selection 16. These records describe the existing native-fallback
decision; they do not change it or transmit addresses or CA paths.

The recorder preserves both C-library and SceNet error state. This provider links Sony libc; its native build uses `_sceLibcErrnoLoc`, while host tests use the host C-library accessor. Importing newlib's `__errno` into this native module caused the previous link failure. Null error-state pointers suppress diagnostics rather than being dereferenced. Native IDA review subsequently verified the accessor's int-pointer return, both saved/restored error values, the bounded nonblocking send, and argument/result preservation in the connect hook. This is static evidence, not a new runtime device result; the exact reviewed ranges are recorded in TLS13_PROGRESS.md section 23.143.

## Private host receiver

`tools/vita_runtime.py` accepts only fixed-size packets carrying the expected nonce from `192.168.1.146`. It bounds the observation interval, accepted process count and total record count, discards duplicates, preserves sequence gaps and writes private local JSONL plus a summary. It does not retrieve process memory or publish files.

An endpoint file contains `host`, `port`, `nonce`, and `expected_peer`. Integration with the test cycle additionally requires `provider_sha256`, matching the diagnostic provider in the new arming receipt. The receiver address must be a currently available private interface on this Mac; a historical interface address is not sufficient for a later run.

Standalone receiver syntax, after preparing and checking a new endpoint:

```sh
python3 tools/vita_runtime.py build/NEW_RUNTIME_ENDPOINT.json \
  --output build/NEW_RUNTIME_CAPTURE.jsonl --seconds 120
```

This only listens. It does not transfer files, arm a kernel, reboot, or launch the browser. Existing output files are not overwritten.

## Guarded cycle integration

`tools/vita_tls_cycle.py run` and `after-arm` accept:

```text
--runtime-endpoint build/NEW_RUNTIME_ENDPOINT.json
```

The endpoint is checked against the provider hash in the arm receipt. After a verified one-shot boot, the receiver is bound before the single browser launch and remains active during the bounded observation and log capture. A bind error prevents launch. The receiver is joined before its files are closed.

For a requested runtime trace, `runtime_observed` distinguishes receiving any accepted packet from receiving none. `runtime_complete` additionally requires a clean receiver result. `cycle_complete` must be false when runtime capture is empty or fails, even if launch and FTP collection succeed. Such a result does not request another launch or re-arm. The receiver summary and FTP evidence remain saved.

## Deployment and interpretation gates

Keep the verified self-disarming kernel unchanged for the initial runtime experiment. The diagnostic provider is separate at `ur0:tai/tls_fixer_startdiag.suprx`; the original vs0 provider, Sony compatibility module, CA bundle and protected storage/FTP files remain untouched. Replacing the diagnostic still requires a fresh inactive before-state, retained old provider bytes, verified read-back, a newly identified receipt and one deliberate activation. Do not reuse an old arm receipt to repeat the crashing test.

UDP is lossy and unauthenticated. The nonce and source filter reduce accidental cross-test mixing but do not make a packet cryptographic proof. Missing packets, initialization drops, exhausted send budgets, receiver errors and absent browser dispatch are distinct possibilities. The last observed stage is not itself the faulting instruction. A complete trace must still be correlated with the exact deployed provider and kernel capture; neither a launch acknowledgment nor `cycle_complete` proves browser survival or TLS acceptance.

The final aggregate verification subsequently completed through the ordinary tool: `build/runtime-ready-20261010T074449Z-13d9cb/receipt.json` records 202 normal and 202 sanitizer CTest targets, 79 Python tests, native linking and exact artifact identities. The preserved kernel is unchanged. The runtime provider is packaged locally under `build/artifacts-runtime-first/`; its transfer helper deliberately does not rewrite the kernel.

The preceding guarded unarmed reboot and a fresh matching read-only capture are recorded in TLS13_PROGRESS.md sections 23.145 and 23.148. The separate installed-title/provider/receiver preflight was blocked and remains pending explicit user-run `build/check_runtime_preflight.py`. The local package is marked not ready for deployment until that result is checked. No runtime provider transfer or activation has occurred, and no runtime packet or TLS 1.3 negotiation has been captured.
