# HTTP provider runtime draft — integration candidate withdrawn

The provider's dependency on Sony's full `SceLibc` module can be removed without modifying Mbed TLS or OpenSSL. The implementation uses the same `SceLibKernel`/`SceSysmem` foundation imported by the bundled Sony HTTP/SSL modules. The standalone native runtime test passes, but the first combined boot integration failed with a user-reported boot-logo freeze/panic. This draft is not a qualified installer or release.

## Implementation

`tls13/provider/user_runtime.c` supplies linker wrappers for the C functions actually referenced by the HTTP provider and its unchanged static dependencies. Allocation uses a process-private 2 MiB memory block and `sceClibMspace*`, protected by a native mutex. It rejects overflowing calloc sizes, preserves allocations on failed realloc, accounts for outstanding allocations and refuses to destroy a live heap. Module startup initializes the runtime before TLS hooks; startup failure attempts cleanup, and the existing resident-provider policy rejects hot unload.

Memory/string operations and formatting use `sceClib*`. The native test found that `sceClibVsnprintf` can omit NUL termination on truncation even though it returns the required length. The wrapper explicitly terminates the final available byte to provide the C99 contract expected by the unmodified dependencies. Native hexadecimal, 64-bit, size_t, truncation and size-only formatting are verified.

The HTTP target removes `SceLibc_stub` and redirects calls through linker `--wrap` options. Neither dependency source nor configuration is patched by this change. Comparing the extracted pinned archive verifies all 943 Mbed TLS/TF-PSA C/header files byte-for-byte. The OpenSSL installer source/build is unchanged. Davee's libk was inspected at commit `1c3614287c4f3d9767080d8bfb0ca69cfefc3503`; its build includes the string routines, and it is not needed or bundled for this native shim.

`tools/check_http_runtime.py` rejects full-libc and unexpected library imports, including variable-only libraries. Native provider imports are restricted to the existing networking, RTC, kernel/thread/module/I/O services and taiHEN plus Sysmem. The provider's actual SELF has no SceLibc import. The runtime remains local to the HTTP provider; the standalone Sony-API checker is unchanged.

## Verification and failed integration

Host tests cover startup allocation/base/mutex/mspace failures, overflow, alignment, realloc failure/preservation, live-heap teardown rejection, concurrency, string operations and Sony's observed formatter behavior. The full suite passed 350/350 normally and with ASan/UBSan before adding the diagnostic title restriction. The new provider/kernel imports also pass all 31 available firmware/hardware corpus cells; five images are absent. This is offline coverage, not hardware proof beyond retail 3.60.

Two native smoke launches temporarily used the already-owned checker application slot, each preserving and restoring its original executable. The first found the formatter termination mismatch; after the shim correction the second returned `failures=0`. The process inventory confirmed no SceLibc. Native heap capacity was 2097152, peak usage 262800, allocator metadata usage after frees 640, and outstanding allocation count zero. No plugin activation or reboot belonged to these smoke tests.

The integration provider was staged separately at `ux0:/data/tls_fixer-runtime-20261013/tls_fixer_http.suprx`, SHA-256 `7b45b769878e21da66a7b686848299a8f3868743d096742c38b037219ee254fc`. Its 14887-byte kernel, SHA-256 `56bcaee960a247c21d482de9c424be08112db3a256c8eaf790519f47578fb0a0`, retained post-start injection, native 16 KiB preparation, name queries, no trace/memory probe, and automatic disarming. The actual compile definitions confirm these controls; CMake's cached OFF defaults were overridden by the normal-profile local values and are not the emitted flags.

One deliberate vitacompanion reboot was acknowledged. Reconnect was not verified within the bounded observer. The user reported a powered-off/frozen device, then a boot-logo freeze and rapid blue power-LED blinking on restarting it. No Browser or checker TLS run followed the activation. No second agent reboot or automatic re-arm was issued. This is a failed integration, not a successful provider activation.

After the user reported the Vita available, stable reads showed the exact disabled configuration `1a7c64d141a275560d5543c632543ebfe345385b2b41f94864485e44ac46a9f5`. Self-disarming therefore did complete. The failed kernel was preserved and the owned test path was restored to the prior `dcec123f` kernel; readback and protected pins pass. The installed system provider, certificates, storage configuration and main VPK were unchanged. The staged diagnostic provider remains separate and inactive. There is no new provider log in ux0 data, no savedata temp directory for SceShell, and no fresh matching crash dump; absence of a log does not identify whether user entry was reached.

The integration test had excessive scope: removing the libc prerequisite enabled HTTP injection into early system processes previously skipped. The isolated runtime test did not qualify that startup path. The exact panic cause remains unknown. Future ux0 diagnostics now require an explicit nine-character test title; nonmatching processes are excluded before preparation allocation or provider loading. Host coverage checks the system/Browser exclusions and the selected checker case. The final suite passes 351/351 normally and with ASan/UBSan. The scoped kernel cross-build and generated-instruction gate pass, but no corrected activation has been attempted.

## State for continuation

The native runtime is implemented and separately verified. Combined provider startup, generic HTTPS and Browser regression remain unverified. The candidate is withdrawn and must not be promoted to the normal VPK. Current device next-boot activation is disabled, and the original test kernel is restored. Do not re-arm merely to collect another outcome; first preserve this evidence and qualify the narrower activation path.

Receipts, native logs, dependency comparison, firmware matrix and recovery evidence are under `build/user-runtime-20261013/`. The preceding diagnostic kernel is preserved before any new scoped build. The main installer artifact remains the previously tested `a3ba3c45` package.
