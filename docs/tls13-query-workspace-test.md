# tls_fixer module-query workspace diagnostic

## Evidence and hypothesis

The headroom-enabled redirection control booted to LiveArea and produced 19 complete records. Its two loader threads had 3320 and 3312 bytes of remaining kernel stack at recorded load checkpoints, compared with 8840-8864 bytes during startup. The native measurement, logger setup and actual hook execution are therefore qualified on that device.

Earlier preparation builds failed even after their module queries, file rehash, printing and a subsequent SSL load returned. That is consistent with delayed corruption, but it is not a fault address or proof of overflow. The remaining large automatic buffers consumed much of the measured loader-thread budget. This test reduces that footprint while retaining the preparation operations, then records headroom during those operations.

## Change

The 256-entry module-ID array and reusable SceKernelModuleInfo output now live in a private 4096-byte kernel memory block for each preparation call. The allocation follows the in-flight reservation, outside the mutex. There is no shared global query buffer or additional mutex. Enumeration still requests at most 256 entries and rejects saturation; module information is zeroed before each query. The target module's information reuses the same output buffer after enumeration ends.

Allocation/base lookup failures stop preparation. All exits attempt to clear/free any acquired workspace before releasing the in-flight reservation. Free or logging failures are reported as failures; a failed free is not asserted to have released native resources. New query.alloc, query.base and query.free entered/returned records bracket the added resource operations. Existing module-list/info, exact hash recheck, target identity checks, returned printing and hook-exit markers remain.

Generated code in matching headroom-enabled profiles reduces the preparation frame from 1552 bytes (36 saved-register bytes plus 1516 locals) to 216 (36 plus 180), a reduction of 1336 bytes. The hook remains 568 bytes; the already reduced hash worker remains 48 bytes. This is a compiled-frame comparison, not the runtime high-water measurement. Native filesystem/module operations use additional transient stack between checkpoints.

The test is still preparation-only: no TLS-provider or DNS-helper module load/start/unload calls are present. Self-disarming, report format, trusted module hashes, certificates, storage configuration and user-space TLS code are unchanged. The default source build also receives the query-workspace change, but that full build is not the artifact to test here.

## Local verification

All 83 normal CTest targets, 83 ASan/UBSan/leak-checking targets and 17 Python tests pass. The ownership regression failed against the previous stack buffers, then passed. Tests require module-list and module-info pointers to lie in the query allocation, check allocation/base/null-base/free failures, preserve descriptor/reservation cleanup, and cover trace failures at every new boundary. Mock free-error coverage establishes attempted cleanup and error propagation, not a guarantee about native allocation state after an error.

The diagnostic and default kernels build without unresolved ELF symbols and pass the decoded FP/SIMD instruction gate. IDA confirms the diagnostic's 216-byte preparation frame, 568-byte hook frame and 48-byte hash-worker frame. The diagnostic symbol exclusion check finds no module load/start/unload import.

## Preparation

This is a kernel-only diagnostic, not a VPK. Do not use an old full-refresh installer. Preserve the current kernel, result file and startup log before replacing anything.

| Archive member | Destination |
| --- | --- |
| tls_fixer.skprx | ux0:/data/tls_fixer-one-shot/tls_fixer.skprx |
| tls_fixer-disarm-result.txt | ur0:/tai/tls_fixer-disarm-result.txt |

Use the archive's new 256-byte PENDING report, not the old successful result. Restore only the initial character of the existing `#x0:/data/tls_fixer-one-shot/tls_fixer.skprx` entry to `u` in `ur0:tai/config.txt`. Do not duplicate the line or change other plugins. Close the editor and computer FTP client, leave the Vita FTP server available, and report completion. Wait for read-only verification of the payload/report/config before rebooting.

Every reboot is performed manually by the user. After verification and a request to proceed, reboot once normally with the card inserted, no L, no installer and no browser test. Report the actual sequence, including any freeze, shutdown or second power-on. Do not re-enable a failed test.

## Interpret the result

Retrieve the report, complete startup log, config and tested kernel before the next change. Require successful gate/logger setup and a complete preparation sequence, including query allocation/base, module queries, rehash, target information, query free, cleanup and hook return. A successful boot caused by an early failure is not a successful preparation run.

Compare free= values by thread and stage. They are instantaneous byte distances above the lower kernel-stack bound, not a high-water mark. Zero is ambiguous, and positive samples do not exclude deeper transient consumption. A successful preparation boot with larger measured headroom would support the stack-pressure hypothesis, not prove the precise previous fault instruction. A continued failure would require investigating the remaining native-call context and delayed state effects rather than claiming the buffer move fixed boot.

The synchronized self-disable protects the following boot after it completes, not failures before module_start or before disarming finishes. It does not restore historical overwritten system files. Boot_config, YAMT, internally stored FTP plugins, CA files and Sony modules must remain unchanged.
