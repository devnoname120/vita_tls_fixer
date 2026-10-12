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
