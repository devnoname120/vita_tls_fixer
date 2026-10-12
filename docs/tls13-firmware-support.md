# Firmware compatibility

The requested scope is the published external 3.60-3.74 releases on retail, testkit and devkit. Current code selects loaded module identities, not a reported/spoofed firmware version. Unknown or mismatched modules fail before hook installation or remain on native browser TLS.

## Evidence matrix

This table describes compiled-guard and firmware-import validation, **not hardware execution**.

| Firmware | Retail | Testkit | Devkit |
| --- | --- | --- | --- |
| 3.60 | Static checks pass | Static checks pass | Static checks pass |
| 3.61 | Static checks pass | Static checks pass | Static checks pass |
| 3.63 | Static checks pass | Static checks pass | Static checks pass |
| 3.65 | Static checks pass | Static checks pass | Static checks pass |
| 3.67 | Static checks pass | Static checks pass | Static checks pass |
| 3.68 | Static checks pass | Static checks pass | Static checks pass |
| 3.69 | Static checks pass | Image unavailable | Static checks pass |
| 3.70 | Static checks pass | Static checks pass | Static checks pass |
| 3.71 | Static checks pass | Image unavailable | Static checks pass |
| 3.72 | Static checks pass | Static checks pass | Image unavailable |
| 3.73 | Static checks pass | Static checks pass | Static checks pass |
| 3.74 | Static checks pass | Image unavailable | Image unavailable |

The supplied external corpus has 31 of 36 requested combinations. Testkit 3.69/3.71/3.74 and devkit 3.72/3.74 are absent. No neighboring/internal/tool image is treated as a substitute. Those five cells remain unverified and their unknown WebKit identities are not guessed. The current profile changes have not been deployed on hardware; the earlier controlled 3.60 retail Browser success is separate evidence for prior artifacts.

## Implemented compatibility

- Twelve SceKernelModulemgr identities select two geometry/signature families, with the original load/start offsets and relocation masks retained. The mapped module-info NID is validated inside the native-reported RX segment; its retention was independently checked in the saved 3.60 kernel capture.
- SceModulemgrForKernel's export library/function NIDs change from 3.63. The kernel resolves four typed APIs (module info/list/unload/shared-address query) once from the identity-selected export family through taiHEN, after durable self-disarming and before hooks. Missing/unknown exports stop startup; loader callbacks do not perform export-resolution queries. A release/acquire publication gate prevents use of incomplete bindings.
- Thirty-one explicit WebKit NIDs select four callback/segment/vtable layouts. Kit module NIDs differ despite matching code and geometry, so retail identities are not silently reused for kits. The callback signature, Thumb tag, real filesz/memsz, userdata alignment/read-write range and profile-specific vtable value remain required. Every profile forwards the same original callback role through import 81405F79:7DAB2E59, checked in the binary import table.
- HTTP and browser transport providers continue to target the exact replacement modules shipped in the VPK. Firmware-native libhttp/libssl/Psp2Compat differences are not mistaken for provider targets. Existing hash/signature/ABI gates are preserved.
- The installer's 3.60-only NP hostname helper comparison ignores kit build/revision bits. This comparison does not select kernel or WebKit offsets.

## Verification

`docs/firmware-compatibility.json` records every available cell's source hashes, module NIDs, callback/vtable offsets, compiled guard results, four native export bindings and mandatory firmware imports for the cross-built kernel, providers and installer. It also reads the exact plaintext compressed SELF modules shipped in the VPK: HTTP (148 imports), SSL (42) and browser compatibility (239) resolve against every available target; the 3.60-only commerce replacement (67 imports), DNS helper and shell hook resolve on all three 3.60 hardware variants. Native exports from modules being replaced are excluded from the check. This establishes static dependency presence, not load order or runtime ABI execution.

The check exercises both normal and post-start kernel guards, real WebKit bytes, and rejection of changed metadata/signatures/geometry/vtable values.

```sh
docker run --rm -v "$PWD":/src \
  -v /Volumes/data/Downloads/vita/decrypted/external:/firmware:ro \
  -w /src vitasdk/vitasdk:latest sh -lc '
  python3 tools/firmware_matrix.py --firmware-root /firmware \
    --output build/firmware-support/matrix-complete.json \
    --plugin-elf build/kernel/tls_fixer.elf \
    --plugin-elf build/tls13-vita/browser/tls_fixer \
    --plugin-elf build/tls13-vita/provider/tls_fixer_http \
    --plugin-elf tls_fixer.elf'
```

Host regressions pass 331 normal and 331 ASan/UBSan/leak CTest cases, plus 124 Python tests. The full ARMv7/hard-float VPK cross-build passes the decoded kernel no-FP/SIMD check. ELF/FALSE-SELF output and static profile/import tests do not establish boot, network or lifecycle behavior on kits or later-firmware hardware. Compatible taiHEN is required on the target system. Existing self-disarm failure windows and persistent-installer limitations remain.
