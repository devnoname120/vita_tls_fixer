# Browser transport: correction to the libhttp-only design

## Current boundary

The application provider `tls_fixer_http.suprx` replaces six internal functions in `SceLibHttp`. The separately implemented `tls_fixer.suprx` replaces the browser libcurl transport described below. Both are built and packaged; real Vita execution is unverified. SceHttp-only test results still must not be presented as browser runtime evidence.

The earlier design generalized a correct finding about `libssl.suprx` (BSAFE MES / SSL-C lineage) to the browser's transport. That generalization was not justified. Different Vita modules can carry different TLS implementations.

The existing installer also treats the browser compatibility module and the in-app HTTP/SSL modules as separate components. This deployment distinction supports investigating a separate browser path, rather than assuming all browser traffic reaches SceLibHttp.

The WebKit route was subsequently established through import/export NIDs. `curl_easy_setopt` is exported by the exact compatibility module at `0x81093A82`, NID `0x30E7FB1B`, library `0x81405F79`. WebKit 3.65 imports it at `0x8185D844`. The enriched 3.60 WebKit IDB identifies the same import and its resource-request setup at `0x83368F22`: generic TLS selection, peer verification, hostname verification and the configured cipher list are passed to this backend. The apparent lower-address second curl cluster was graphics code, not a second TLS backend.

## Exact artifact correspondence

The repository artifact `misc/compat.suprx` was unpacked for analysis. Its two loadable payloads match the existing IDA input below byte-for-byte:

```text
IDA session: tls_fixer-compat-373
Database input:
<workspace>/.reverse-tmp/fwcompare/373/ScePsp2Compat.exec.elf

Own unpacked analysis input:
.reverse-tmp/compat-bundled.suprx.elf

Executable payload
  virtual address: 0x81000000
  file size:       0x39F508
  SHA-256: 2b54b99bdfb32f55f762f3a1730afb242400b5c237ce327728b5cb29e86b685b

Data payload
  virtual address: 0x813A0000
  file size:       0x9C28
  SHA-256: bd3ddba2888e02ccef72ee07e0252fd234ffe59b3a74c8ca1e06ee73a073af56
```

The existing IDB was inspected read-only. These hashes describe loadable payloads, not the compressed SELF file and not relocated runtime memory.

## Executable evidence, not just vendor strings

The string `SSL connection using %s` at `0x8131DBAC` is referenced by the function at `0x810A5ECE`. IDA decompilation shows that function driving an embedded OpenSSL-style handshake and installing its own application-data callbacks.

| Address | Observed role |
| --- | --- |
| `0x810A5ECE` | libcurl SSL connect driver, including nonblocking state transitions |
| `0x810A6234` | Small wrapper around the connect driver |
| `0x810A3C98` | Initial SSL setup helper |
| `0x810A58E0` | Certificate-related completion helper |
| `0x81093F18` | Timeout/deadline helper |
| `0x81097E82` | Socket-readiness helper |
| `0x81203814` | Embedded SSL-connect operation; success is 1 |
| `0x812047D8` | Embedded SSL error classifier; WANT_READ/WANT_WRITE are 2/3 |
| `0x810A6650` | **Write/send** wrapper calling embedded SSL-write at `0x812038A8` |
| `0x810A673C` | **Read/receive** wrapper calling embedded SSL-read at `0x81203836` |
| `0x810A6240` | Pending-plaintext helper calling embedded SSL-pending at `0x81203648` |
| `0x810A36BA` | Close function freeing the native SSL handle and context |
| `0x810A354C` | Connection-health check, calling embedded SSL-peek at `0x81203870` |
| `0x810A6260` | Backend-version formatter reporting OpenSSL |

The send/receive wrappers use libcurl-style results: AGAIN 81, SEND_ERROR 55 and RECV_ERROR 56. They are not interchangeable with SceHttp's negative result codes.

Some IDA functions incorrectly include subsequent functions because imported stack-check failure stubs lack no-return annotations. In particular, decompiling `0x810A643C` also exposes the inner write/read routines. Use exact instruction boundaries and call sites, not the recovered enclosing function size alone.

## Implemented connection boundary

For the connect-driver object, word indices observed in the decompilation are:

| Word index | Observed meaning |
| --- | --- |
| `0` | Pointer to the associated easy/request object |
| `80 + socket_index` | Socket descriptor |
| `85 + socket_index` | Receive callback (`0x810A673C`) |
| `87 + socket_index` | Send callback (`0x810A6650`) |
| `90 + 6 * socket_index` | SSL state |
| `92 + 6 * socket_index` | Embedded SSL object |
| `94 + 6 * socket_index` | Connecting state |

The provider uses these fields only in the exactly gated module. It keeps Mbed TLS objects outside the native connection. Native SSL context/handle fields remain NULL; only connecting state, completed state and send/receive callbacks are updated. Close restores the previous callbacks and drains provider operations before releasing its state. The socket itself remains owned by libcurl.

## Implemented browser module

The four hooks are close (`0xA36BA`), pending (`0xA6240`), connection health (`0xA354C`) and the complete connect driver (`0xA5ECE`). Connect is published last. Before the complete set exists all installed hooks forward to the original backend. A partially published set is retained as disabled passthrough until process exit; it is not freed while another thread may execute its continuation. Hot module stop is rejected.

Connection health cannot be left native: its `SSL_peek` call would dereference the intentionally NULL OpenSSL handle. The provider implements the observed alive/closed/unknown result using its own context and a one-byte lookahead. Subsequent receive returns that byte first, preserving non-consuming peek semantics. The TLS response-pattern tests check health repeatedly between reads and still require all 5000 response bytes in exact order.

The provider reuses the original deadline and readiness helpers, polls blocking operations in 50 ms slices and performs SceNet BIO operations with DONTWAIT. This permits concurrent close to cancel and drain a handshake rather than waiting indefinitely in a blocking receive. Session-ticket notifications, clean versus unclean EOF, stable write retries, buffered-data readiness and the two socket indices have executable host coverage.

`tls13/supported_browser.json` identifies compressed SELF SHA-256 `738862133819fc37bc21f714da7ca76c72d73a620afafbe6a940d87dd4e6dc58`. The kernel checks the installed artifact and rechecks before injection; the user module checks all segment file/memory dimensions plus invariant bytes at the three hooks and two helpers. Text filesz and memsz are intentionally different, `0x39F508` and `0x39F630`.

The loader preserves the original browser mount prefix for both the replacement and provider. It opens the browser provider with target-process namespace flag `0x1000`. The CA path is derived from that same prefix, for example `wb0:/cert/CA_LIST.cer`. IDA confirmed that the intercepted internal loader returns a kernel GUID; `ksceKernelGetModuleInfo(pid, guid).modid` supplies the process-visible PUID passed to the user module. This conversion is applied to both providers.

Default browser peer/hostname policy, SNI, PEM CA files and HTTP/1.1 are implemented. The exact built-in `SceWebKit` SSL-context callback is accepted only after its loaded module, fixed Thumb entry, invariant bytes and request userdata have been validated, and only for the normal clean-chain policy with peer and hostname verification enabled and no custom CA. On that path Mbed TLS must complete ordinary chain and hostname verification; the native callback is not invoked and no Sony OpenSSL certificate object is fabricated. Arbitrary callbacks, altered verification policy, client certificates/keys, CA directories, CRLs, issuer constraints, certificate-info requests, pinned legacy protocol versions and unsupported cipher expressions select native OpenSSL before any provider bytes are transmitted. These are explicit compatibility fallbacks, not ignored security settings. Cross-connection TLS session resumption and early data are outside this implementation.

Debug builds emit bounded per-process records to `sceClibPrintf`. File logging first uses `ux0:/data`; WebKit processes that cannot write that mount fall back to their `savedata0:/temp` directory. Compatibility diagnostics expose only fixed reason codes and scalar option offsets/values, never callback addresses, certificate material, hostnames, URLs or payloads. Failure to open or write either file does not change routing or TLS results.

The kernel and user modules remain resident until reboot/process exit. A libcurl or module unload/reload sequence within the same process has not been validated on hardware. Real browser runs, permissions, proxy requests and memory/performance still require the device matrix in `tls13-hardware-validation.md`.

## What the present implementation contributes

The work now provides both source-built providers, the complete default-browser transport boundary, kernel loading, installer refresh/uninstall, bounded per-process diagnostics and a VPK containing both modules. Host tests use the real TLS engine with reconstructed native layouts and Vita/taiHEN mocks. The shipped compatibility-module payload remains unchanged; runtime hooks are installed only after identity validation. See `TLS13_PROGRESS.md` section 21 for test results and artifact identities.
