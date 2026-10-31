"""Apply the diagnostic-only legacy offer serializer to the pinned 3.6 source."""
import hashlib
from pathlib import Path
import sys

source = Path(sys.argv[1]) / "library/ssl_client.c"
original = source.read_bytes()
marker = b"TLS_FIXER_DIAGNOSTIC_LEGACY_OFFERS"
expected = "ef3b810d412ffa433e9d5ae100a50ee4927a6ee2b65079ae055b12ed08f17af0"
needle = b"        if (mbedtls_ssl_validate_ciphersuite(ssl, ciphersuite_info,"
addition = b"""#if defined(TLS_FIXER_DIAGNOSTIC_LEGACY_OFFERS)
        /* Only serialize these explicit legacy IDs when a caller placed them
         * in its offer. Default lists and ServerHello validation are unchanged. */
        if (ciphersuite_info == NULL &&
            (cipher_suite == 0x000a || cipher_suite == 0x0005 || cipher_suite == 0x0004)) {
            MBEDTLS_SSL_CHK_BUF_PTR(p, end, 2);
            MBEDTLS_PUT_UINT16_BE(cipher_suite, p, 0);
            p += 2;
            continue;
        }
#endif

"""
if marker in original:
    if original.count(addition) != 1 or hashlib.sha256(original.replace(addition, b"", 1)).hexdigest() != expected:
        raise SystemExit("Modified diagnostic source does not match the pinned patch")
    raise SystemExit(0)
if hashlib.sha256(original).hexdigest() != expected or original.count(needle) != 1:
    raise SystemExit("Unexpected Mbed TLS 3.6.7 serialization source")
source.write_bytes(original.replace(needle, addition + needle))
