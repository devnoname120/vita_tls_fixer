# Guarded primary-Vita test cycle

## Scope

The user requested reboot, browser testing and log collection as one workflow on 2026-10-10, then explicitly selected the normal browser icon/Start sequence instead of vitacompanion's `launch` command. `tools/vita_tls_cycle.py` separates the verified boot from observation of that UI-driven test on primary Vita `192.168.1.146`, FTP 1337 and command port 1338. Its command interface accepts only reboot; it never sends browser launch, touch or button commands. Screenshot review and normal UI input remain agent-operated steps. The runner does not select a new payload, edit a taiHEN entry itself, install a VPK, modify storage configuration, or loop tests. The reviewed, hash-pinned stage and arm helpers remain responsible for their narrowly authorized writes.

The last browser test reached provider startup but crashed later. Do not run historical stage/arm helpers simply to repeat that failed test. Prepare an identified, justified next test with preserved before-state first.

## Prepare one boot after selecting a new test

From the worktree, use the new test's exact helper and receipt paths:

```sh
python3 tools/vita_tls_cycle.py run \
  --stage build/STAGE_FOR_THE_NEW_TEST.py \
  --arm build/ARM_FOR_THE_NEW_TEST.py \
  --receipt build/NEW_TEST_ARM_RECEIPT.json \
  --browser-title-id VERIFIED_BROWSER_TITLE_ID
```

The uppercase values are placeholders, deliberately not an executable invocation of the previous crashing test. The browser title ID must match the title's actual `sce_sys/param.sfo`. The runner reads this before executing either helper. A restored page, a completed request and its TLS version must be observed separately.

The command runs the stage helper and then the arm helper, stopping on any failure. Both must be Python files beneath this worktree's `build` directory. Their hashes and progress are journaled, and the arm helper must publish a new receipt. Only then does the runner perform the following steps:

1. Verify the complete armed configuration, exact one-character rollback, payload and protected-file hashes, and absence of an alternate configuration. Save the before-state privately.
2. Consume this arming receipt in an exclusive host-side journal and request **one** reboot. Require an observed disconnect/reconnect, the exact self-disabled configuration, a fresh trace, a successful loader-hook record, browser readiness and clean startup/report fields. A replay or ambiguous command outcome is not retried.
3. Save the complete, stable boot checkpoint and its trace hash, leave the entry disabled and return `browser_ui_pending=true`. No browser command or input is sent. A provider already started before this checkpoint stops preparation instead of being mistaken for a fresh test.

`after-arm` exposes the final portion separately for a transfer script that already completed its own verified arming:

```sh
python3 tools/vita_tls_cycle.py after-arm build/NEW_TEST_ARM_RECEIPT.json \
  --browser-title-id VERIFIED_BROWSER_TITLE_ID
```

Append this with `&&`, not `;`, to an existing transfer command. It will not reboot a disabled configuration or use a stale successful receipt as permission to arm it.

A verified boot returns CLI status **3**, `cycle_complete=false`, and `BOOT_VERIFIED_WAITING_FOR_BROWSER_UI`. This means the UI phase is pending, not that another stage/arm attempt is required. Save `cycle_directory` from the returned JSON. Do not rerun `iterate.sh` or the stage/arm helpers to continue this boot. The selected passthrough test's existing arming receipt still prevents `iterate.sh` from replaying it.

## Observe the normal UI phase without another reboot

Use screenshots to inspect the current screen and identify the browser icon and then its Start tile. The user indicates the browser icon is on the first LiveArea page after reboot; that does not justify blind coordinates on an unverified screen. Do not replace a blocked input operation with a title launch or another input route.

For a newly saved boot checkpoint:

```sh
python3 tools/vita_tls_cycle.py observe-ui build/NEW_TEST_ARM_RECEIPT.json \
  build/device-evidence/EXACT_NEW_CYCLE_DIRECTORY --settle-seconds 60
```

This command never sends input, reboots, uploads or re-arms. It verifies the saved checkpoint's arming-receipt identity and trace hash, the current disabled configuration, unchanged payload/protected files, and that the current trace still extends the exact saved boot. It prints `BROWSER_UI_OBSERVATION_READY` only after those checks and any requested runtime receiver have succeeded. It then observes the bounded interval and saves a separate immutable capture. The normal UI interaction can be performed in that interval; for non-runtime tests, an already-completed same-session UI action can also be captured with `--settle-seconds 0`. A replaced trace, another boot or changed configuration is rejected rather than retried.

`observation.json` distinguishes readiness from a finished observation. A saved readiness marker from an already-finished run is not evidence that a receiver is still listening. Notification, bind or capture errors preserve the failed observation and do not trigger input or another boot.

Historical cycle receipts without the new UI checkpoint fields are not silently promoted. Their evidence can still be read with `collect` and analyzed separately; lack of new fields is not permission to re-arm an old test.

## Read-only collection

```sh
python3 tools/vita_tls_cycle.py collect
```

This retrieves config, diagnostic kernel, startup report/trace and the protected boot/storage/FTP files before inventorying `ux0:/data`. Reads are bounded and repeated; changed second reads are retained. Up to 64 browser logs are retrieved, prioritizing PIDs appearing in the current trace. Any omitted log names are recorded explicitly. Up to 4096 directory names are accepted. Core filenames are inventoried, **not** automatically downloaded or published. Malformed inventory entries cannot escape the local evidence directory, and a later inventory error cannot discard the already saved primary files.

Outputs are private local directories beneath `build/device-evidence`, with a `receipt.json` recording exact bytes and hashes. The collector creates a new directory for each invocation and never resets a remote trace.

## Ending the preceding loaded test

A disabled boot entry does not stop a kernel/provider already loaded in RAM. Before replacing its active report or selecting another test, preserve the evidence and perform one deliberate unarmed reboot:

```sh
python3 tools/vita_tls_cycle.py reboot-disabled build/CURRENT_TEST_ARM_RECEIPT.json
```

This requires the exact disabled configuration and unchanged kernel/protected files from that receipt. It does not arm, transfer, launch the browser or repeat the reboot. It journals the request and verifies the disabled state again after the observed reconnect. A missing or changed prerequisite stops it before the command.

## Interpretation limits

For an explicitly built runtime-stage diagnostic, `run` and `after-arm` accept `--runtime-endpoint build/NEW_RUNTIME_ENDPOINT.json` and preserve that validated endpoint in the boot checkpoint. `observe-ui` uses the saved endpoint even when the option is omitted; a different endpoint is rejected. A newly specified endpoint must identify the exact diagnostic-provider hash in the arming receipt. The receiver is bound before the observation interval; do not perform the UI action until that readiness is verified. Bind failure does not cause a launch or retry. An empty or failed requested runtime capture leaves `cycle_complete=false`. `runtime_observed` and `runtime_complete` distinguish received packets from a clean capture. See `docs/tls13-runtime-stage-trace.md` for the packet format and deployment gates.

A reboot response is only a command response; the installed vitacompanion implementation does not report the reset API's actual result. Disconnect/reconnect plus the independent fresh startup evidence is stronger than FTP connectivity alone, but is not a visual observation of LiveArea or proof against every possible recovery restart.

The command-response deadline is 20 seconds, independently of the five-second TCP-connect timeout and the default 120-second reboot-observation deadline. Reboot observation starts immediately after the command bytes have been sent and runs concurrently with receiving its reply. A slow or absent control response therefore does not postpone the disconnect observation. The observer is cancelled and joined before the runner returns on a rejected or failed request; no missing reply causes a command resend. An unconfirmed send stops the cycle rather than proceeding to launch.

A launch acknowledgment is not proof that a browser process even started. In the passthrough-control test, `Launched.` was followed by a shell error (C2-12570-5) and no provider entry. The runner no longer requests that launch. UI observation requires the saved browser trace to extend the exact boot capture and contain a correlated provider start/return/status sequence with a positive module ID and zero start status. It reports that limited result separately as `browser_provider_started`, with supporting process IDs in `browser_activity`. A boot-only trace, unrelated module activity, malformed/exhausted trace or mismatched/failed provider result leaves `cycle_complete=false`; no input or reboot is sent.

`cycle_complete` still does not establish a completed page request, process survival or TLS negotiation. It requires a complete stable collection, observed provider startup and any requested runtime capture. The runner never sets `tls13_established` to true from those events and never fabricates a launch acknowledgment for externally operated input. Actual negotiated-protocol evidence and subsequent process/crash evidence must be analyzed separately. Pending UI, incomplete collection and missing provider/runtime evidence return nonzero CLI status after preserving what was obtained.

Self-disarming retains its original limitation: it cannot protect a fault before module entry or before the persistent edit is complete. None of these host commands automatically re-arms an unexplained failure, changes certificate policy, suppresses a warning, or modifies the original Sony modules.
