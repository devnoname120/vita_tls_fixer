#!/usr/bin/env python3
"""Create public DER fixtures for native certificate inspection; retain no keys."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import struct
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import NameOID


def tick(date):
    delta = date.replace(tzinfo=None) - datetime(1, 1, 1)
    return (delta.days * 86400 + delta.seconds) * 1000000


def write_view(path):
    cert = x509.load_der_x509_certificate(path.read_bytes())
    serial = cert.serial_number.to_bytes((cert.serial_number.bit_length() + 7) // 8, 'big')
    if serial[0] & 128:
        serial = b'\0' + serial
    issuer, subject = cert.issuer.public_bytes(), cert.subject.public_bytes()
    before = cert.not_valid_before_utc.strftime('%Y%m%d%H%M%SZ').encode() + b'\0'
    after = cert.not_valid_after_utc.strftime('%Y%m%d%H%M%SZ').encode() + b'\0'
    path.with_suffix('.view').write_bytes(b'TCV1' + before + after +
        struct.pack('<3I', len(serial), len(issuer), len(subject)) + serial + issuer + subject)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--views-only', action='store_true')
    args = parser.parse_args()
    out = args.output
    if args.views_only:
        for path in out.glob('*.der'):
            write_view(path)
        print('Wrote inspection views from existing public DER fixtures.')
        return
    out.mkdir(parents=True, exist_ok=False)
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    specs = [('rsa-sha256', rsa_key, hashes.SHA256(), {}),
             ('ec-sha384', ec.generate_private_key(ec.SECP384R1()), hashes.SHA384(), {}),
             ('rsa-pss', rsa_key, hashes.SHA256(), {'rsa_padding': padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)}),
             ('ed25519', ed25519.Ed25519PrivateKey.generate(), None, {})]
    rows = []
    for i, (name, key, algorithm, options) in enumerate(specs):
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'tls_fixer native certificate test'),
                             x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'TLS Check'),
                             x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, 'Café')])
        begin = datetime(2020 + i, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
        end = datetime(2051 + i, 6, 7, 8, 9, 10, tzinfo=timezone.utc)
        serial = 0x102030 + i
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                .public_key(key.public_key()).serial_number(serial).not_valid_before(begin)
                .not_valid_after(end).add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .sign(key, algorithm, **options))
        der = cert.public_bytes(serialization.Encoding.DER)
        (out / (name + '.der')).write_bytes(der)
        write_view(out / (name + '.der'))
        rows.append({'file': name + '.der', 'sha256': hashlib.sha256(der).hexdigest(),
                     'serial': serial.to_bytes(3, 'big').hex(), 'not_before_tick': tick(begin),
                     'not_after_tick': tick(end), 'name_entries': [{'oid': a.oid.dotted_string,
                     'value_hex': a.value.encode().hex()} for a in subject]})
    (out / 'expected.json').write_text(json.dumps(rows, indent=2) + '\n')
    print('Created four public certificate fixtures; no private keys were written.')


if __name__ == '__main__':
    main()
