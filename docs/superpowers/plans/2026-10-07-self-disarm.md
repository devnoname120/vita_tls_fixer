# tls_fixer startup self-disarm implementation plan

**Goal:** implement the user's explicitly selected simple design: the experimental kernel module disables its own future taiHEN load before doing anything else.

**Architecture:** `module_start` first calls a small self-disarm function. It disables only exact active tls_fixer entries in taiHEN configuration, synchronizes successful edits, and returns permission to continue only after verification. There is no separate guard module, arming marker, new launcher, or automatic re-enabling. The known pre-module_start failure window is explicitly accepted as outside this mechanism.

**Tech stack:** C11, existing kernel SceIo imports, native fault-injection mocks, existing CMake/CTest and GCC 15.2 VitaSDK build. Changes stay local and uncommitted; no device write or installation.

## 1. Entry ordering regression

Files: `tls13/tests/kernel/test_route.c`, `kernel/main.c`.

- Add a stub self-disarm result and counters for logging, metadata queries, loader initialization and hook publication.
- Call the actual production `module_start` with disarming failure and assert failure with zero other startup operations.
- Verify it fails against the current source before changing the entry point.
- Insert the gate ahead of the first debug print:

```c
if (tls_fixer_self_disarm() != 0) return SCE_KERNEL_START_FAILED;
```

- Verify positive startup is ordered after confirmed disarming and the existing routing regressions remain passing.

## 2. File edit and failure tests

Files: `kernel/self_disarm.c`, `kernel/self_disarm.h`, `tls13/tests/kernel/test_self_disarm.c`, kernel mock declarations and CMake target.

- Use bounded line parsing. Disable only the exact `ur0:tai/tls_fixer.skprx` and `ur0:/tai/tls_fixer.skprx` entries in `*KERNEL` sections. Preserve unrelated plugins, comments, section headers, whitespace, file length, LF/CRLF and a final unterminated line.
- Prefer a one-byte in-place comment of the first path character over truncating or replacing the configuration file. It becomes a comment such as `#r0:tai/tls_fixer.skprx`; explicit re-enabling must restore the original path. This preserves every other byte and avoids a whole-config rewrite.
- Cover all matching duplicate entries, not just the first. Protect against an enabled entry in the alternate ux0 config; do not silently edit only a shadowed file.
- Refuse activation on unreadable/malformed/oversized configuration, a short write, sync/status/close failure, or remaining enabled entries. A missing or already disabled entry does not permit activation. No routine creates a config or enables the plugin.
- Model working versus durable disk contents in the tests. Simulate failure after successful disarming, then a fresh start reading durable state; it must not activate again.
- Check exact APIs against headers and the 3.60 Iofilemgr IDB rather than assuming POSIX fsync behavior.

## 3. Kernel-safe code generation

Files: `kernel/CMakeLists.txt`, build-verification test/script as needed.

- Reject the existing generated kernel artifact's unmanaged VFP/NEON instructions in a regression check.
- Use `-mgeneral-regs-only` for all kernel translation units, retaining the existing ABI. Do not change the user-space TLS providers' FP settings.
- Independently disassemble and scan the generated kernel executable. The compiler option does not constrain assembly or linked code, so a compiler flag alone is not sufficient evidence.

## 4. Verify and document

- Run the new tests first, then the native and ASan/UBSan suites and the hard-float kernel build. Preserve actual logs and examine exit statuses.
- Record kernel generated-code evidence separately from any unverified device behavior.
- Update AGENTS.md and TLS13_PROGRESS.md: the user's simpler self-removal decision supersedes the proposed separate loader; old test packages remain withdrawn.
- Show the diff. Do not upload, install, arm, reboot, or deliver a new hardware-test package without explicit user authorization.

## Safety limits

This protects a future reboot only after the self-disarm writes are durably committed. It cannot cover relocation/import failures or a fault in the disarming code before that point. Host storage mocks test control flow, not real Vita crash durability. It disables experimental activation; it does not restore previously overwritten modules, certificates or storage settings. Keep the known-working files and recovery tools intact for future deployment.

## Local execution result

Implemented and locally verified. The fresh kernel build is under `build/self-disarm-kernel-clean`, not a new delivered VPK. `build/self-disarm-verified.log` records 30/30 normal and 30/30 sanitizer targets, 17 Python tests, successful generated-code checking and no unresolved kernel ELF symbols. The actual synchronization calls are the file and mount variants of ksceIoSync; no reliance is placed on the misleadingly named SyncByFd symbol. IDA also confirmed the compiled entry calls self-disarm before its first debug or metadata operation. Full evidence and limitations are in TLS13_PROGRESS.md section 23. Physical crash/reboot durability remains unverified. No device changes, commit or push were performed.
