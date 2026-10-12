# SceSsl consumer and coverage audit

Date: 2026-10-12. Static firmware/module inspection; no device operation or new provider behavior.

## Direct private-SSL consumers beyond libhttp

| Module | Private SceSslInternal imports in 3.60 | Structural coverage gap |
| --- | ---: | --- |
| SceEmailEngine | 22 | Email engine's direct SSL path is outside the browser and libhttp transport hooks. Mail server/protocol strings include IMAP and SMTP. |
| SceNpMatching2 | 24 | Matching service has private SSL APIs as well as public HTTP requests; its private path is outside the libhttp adapter. |
| SceShell | 22 | Shell has both public HTTP and a separate private SSL API surface. Individual shell services using that private path still require mapping. |

All three import the SDK-identified `sceSslInternalWrite` (NID F39A49C6); this establishes a compiled private TLS-I/O dependency, not a runtime negotiation observation. Import-only findings do not prove that every operation in those modules takes the private branch. A raw-disassembly check of the reconstructed dumps did not independently resolve direct branch-call sites; it is not treated as call-path proof.

The mail UI module SceEmailApp imports 223 SceEmailEngine functions; SceEmailBg imports 184. Those modules delegate work to the engine and should not be counted as separate TLS drivers merely because they also import SSL initialization. ScePS4Link imports 17 SceNpMatching2 functions, so the matching service is relevant outside ordinary game matchmaking too. This does not establish the SSL route used by every PS4 Link or Remote Play operation.

## Census and evidence limits

- All 242 available 3.60 enriched module ELFs parse successfully. There are 43 modules importing SceSsl and/or SceSslInternal.
- Exactly four 3.60 modules import SceSslInternal: SceLibHttp (67), SceEmailEngine (22), SceNpMatching2 (24) and SceShell (22). The former is the implemented application transport boundary.
- The 3.65 corpus contains 328 ELFs: 316 parse under the normal module ABI. The 12 excluded files are security-coprocessor images under os0/sm with a different module format. The same three additional private SSL consumers appear with the same 22/24/22 import counts.
- Selected saved 3.74 images confirm SceShell has 23 private SSL imports and SceLibHttp has 69. This is a selected cross-check, not a full 3.74 census; on-disk retail SELF files remain encrypted.
- Corpus evidence does not cover all third-party applications, games, dynamically resolved dependencies, or embedded TLS engines.

Public SceSsl exports cover initialization/termination, pool statistics and certificate inspection. They do not expose a general public SSL connect/read/write API. Most apparent SceSsl consumers import only sceSslInit/sceSslTerm, optionally pool statistics, while using SceHttp or another service for transport.

Representative HTTP clients include Settings, Store Browser/Checkout, Signup, Friends dialogs, Trophy, Calendar, Near, Online Storage and Marlin Downloader. Their compatible libhttp requests are structurally within the HTTP provider's intended coverage. That is not per-application hardware validation. Existing exact-module gates and custom-CA/client-certificate/native-fallback limits still apply. Shell has both kinds of paths and must not be classified as entirely covered or entirely uncovered.

The useful next investigation is the EmailEngine TLS driver, then Matching2's private SSL branch and the shell's specific private SSL callers. No universal private-ABI replacement is implemented by this audit.

## Saved evidence

- `build/ssl-consumers/360-imports-named.json`: full matching libraries, function NIDs, addresses and source hashes for 3.60 consumers, plus census status.
- `build/ssl-consumers/360-consumers.csv`: readable list of all 43 consumers.
- `build/ssl-consumers/365-imports.json`: 3.65 module/dependency census and excluded images.
- `build/ssl-consumers/374-selected-imports.json`: selected later-firmware check.
- `build/ssl-consumers/audit.py`: parser and inventory reproduction script.

No Vita launch, restart, configuration edit, upload or TLS experiment occurred. Hardware/runtime behavior remains separate from these static findings.
