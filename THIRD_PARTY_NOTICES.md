# Third-Party Notices

## Mbed TLS 4.2.0 and TF-PSA-Crypto 1.2.0

`tls_fixer_http.suprx` and `tls_fixer.suprx` statically link libraries built from the official Mbed TLS 4.2.0 source release, which bundles TF-PSA-Crypto 1.2.0:

- `libmbedtls.a`
- `libmbedx509.a`
- `libtfpsacrypto.a`

This distribution selects the Apache License 2.0 option offered by those projects. Their complete upstream license files are preserved as `licenses/Mbed-TLS-LICENSE.txt` and `licenses/TF-PSA-Crypto-LICENSE.txt`, both packaged in the VPK. This does not change the licensing of the inherited installer and module-redirection code or bundled Sony modules.

The source archive is `mbedtls-4.2.0.tar.bz2` from the `mbedtls-4.2.0` release of `Mbed-TLS/mbedtls`, SHA-256 `2bed9d713b4668f76553b097e72b8aa30bc8f112a940d7ae228d524bbde6ffea`. Upstream sources are not patched; project configuration headers and an external platform adapter select the supported client features and Vita services.

The crypto distribution includes Project Everest/HACL* Curve25519 code, copyright INRIA and Microsoft Corporation, under Apache-2.0, and p256-m code authored by Manuel Pégourié-Gonnard and The Mbed TLS Contributors, offered under Apache-2.0 OR GPL-2.0-or-later. This distribution selects Apache-2.0.

TF-PSA-Crypto also bundles mldsa-native. Its complete upstream license and attribution file is preserved as `licenses/mldsa-native-LICENSE.txt` and packaged regardless of whether the selected configuration retains that driver in the final link. The upstream test and benchmark programs are not built into the provider.

Mbed TLS and its bundled components are independent third-party works. No endorsement by their authors is implied.

## Installer certificate updater

The installer links source-built libcurl 8.17.0 under the curl license. Its unmodified source archive is `curl-8.17.0.tar.gz` from the `curl-8_17_0` release of `curl/curl`, SHA-256 `e8e74cdeefe5fb78b3ae6e90cd542babf788fa9480029cfcee6fd9ced42b7910`. Vita configuration disables unused protocols, default CA discovery and console UI. Source is available at https://github.com/curl/curl/releases/tag/curl-8_17_0; the complete license is `licenses/curl-LICENSE.txt`.

The VitaSDK build used for validation supplies OpenSSL 1.1.1t, zlib 1.3.2 and Zstandard 1.5.7. Their complete license texts are included as `licenses/OpenSSL-LICENSE.txt`, `licenses/zlib-LICENSE.txt` and `licenses/zstd-LICENSE.txt`. Zstandard's BSD option is selected. This product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit (https://www.openssl.org/). This product includes cryptographic software written by Eric Young (eay@cryptsoft.com).

## Mozilla certificate data

`mozilla-certs.pem` is the curl project's PEM conversion of Mozilla's CA data, under the Mozilla Public License 2.0. Its upstream header is retained unchanged. The complete license is included as `licenses/Mozilla-MPL-2.0.txt`. The source snapshot is available at https://curl.se/ca/cacert.pem and its upstream source is Mozilla NSS `certdata.txt`, identified in the PEM header. The packaged snapshot date, source URL and SHA-256 are recorded in `certificate-sources.json`.

The separate Sony firmware certificate bundle remains Sony-origin material. Runtime merging preserves the selected certificates and removes duplicate DER identities; it does not import the existing system trust store. All notices and license files described here are packaged in the VPK.
