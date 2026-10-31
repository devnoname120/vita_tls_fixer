#!/usr/bin/env python3
"""Controlled TLS 1.2/1.3 endpoints for the Vita's per-process CA test."""
import argparse
import ipaddress
import json
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import threading
import time


def fixtures(root, address):
    root.mkdir(parents=True, exist_ok=False, mode=0o700)
    openssl = shutil.which('openssl')
    if not openssl:
        raise RuntimeError('OpenSSL CLI is required to create local certificates')
    (root / 'root.cnf').write_text('''[req]
distinguished_name=dn
x509_extensions=ca
prompt=no
[dn]
CN=tls_fixer controlled test root
[ca]
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
''')
    (root / 'server.cnf').write_text(f'''basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=IP:{address}
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
''')
    commands = [
        ['req', '-new', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '3650',
         '-config', 'root.cnf', '-keyout', 'root.key', '-out', 'root.pem'],
        ['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-subj', '/CN=' + address,
         '-keyout', 'server.key', '-out', 'server.csr'],
        ['x509', '-req', '-in', 'server.csr', '-CA', 'root.pem', '-CAkey', 'root.key',
         '-set_serial', '2', '-sha256', '-days', '3650', '-extfile', 'server.cnf', '-out', 'server.pem'],
        ['x509', '-in', 'root.pem', '-outform', 'DER', '-out', 'custom-root.der'],
        ['verify', '-CAfile', 'root.pem', '-verify_ip', address, 'server.pem'],
    ]
    with (root / 'fixture-build.log').open('wb') as log:
        for command in commands:
            subprocess.run([openssl, *command], cwd=root, check=True, stdout=log, stderr=log)
    for name in ('root.key', 'server.key'):
        (root / name).chmod(0o600)
    (root / 'custom-urls.txt').write_text(f'https://{address}:18443/\nhttps://{address}:18444/\n')
    (root / 'fixture.json').write_text(json.dumps({'address': address, 'ports': [18443, 18444]}))


class Endpoint:
    def __init__(self, root, bind, port, version):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = context.maximum_version = version
        context.load_cert_chain(root / 'server.pem', root / 'server.key')
        if version == ssl.TLSVersion.TLSv1_2:
            context.set_ciphers('AES128-SHA:AES256-SHA:@SECLEVEL=0')
        self.context, self.root, self.port = context, root, port
        self.socket = socket.socket()
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((bind, port))
        self.socket.listen(4)
        self.socket.settimeout(.5)
        self.stopping = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        while not self.stopping.is_set():
            try:
                peer, address = self.socket.accept()
            except socket.timeout:
                continue
            event = {'time': time.time(), 'port': self.port, 'peer': address[0]}
            try:
                peer.settimeout(10)
                with self.context.wrap_socket(peer, server_side=True) as tls:
                    event.update(protocol=tls.version(), cipher=tls.cipher()[0])
                    request = b''
                    while b'\r\n\r\n' not in request and len(request) < 8192:
                        chunk = tls.recv(1024)
                        if not chunk:
                            raise ValueError('Incomplete HTTP request')
                        request += chunk
                    if not request.startswith(b'GET / HTTP/1.') or b'\r\n\r\n' not in request:
                        raise ValueError('Unexpected request')
                    body = ('tls_fixer custom CA accepted\nprotocol=' + tls.version() + '\n').encode()
                    tls.sendall(b'HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/plain\r\n'
                                + f'Content-Length: {len(body)}\r\n\r\n'.encode() + body)
                    event['http'] = 200
            except (OSError, ValueError) as error:
                event['error'] = str(error)
                peer.close()
            with (self.root / f'server-{self.port}.jsonl').open('a') as log:
                log.write(json.dumps(event) + '\n')

    def close(self):
        self.stopping.set()
        self.thread.join(11)
        if self.thread.is_alive():
            raise RuntimeError('Server did not stop')
        self.socket.close()


def self_test(root, address):
    servers = [Endpoint(root, '127.0.0.1', port, version) for port, version in
               ((18443, ssl.TLSVersion.TLSv1_3), (18444, ssl.TLSVersion.TLSv1_2))]
    try:
        for port, expected in ((18443, 'TLSv1.3'), (18444, 'TLSv1.2')):
            context = ssl.create_default_context(cafile=str(root / 'root.pem'))
            context.set_ciphers('AES128-SHA:AES256-SHA:@SECLEVEL=0')
            with socket.create_connection(('127.0.0.1', port), timeout=5) as peer:
                with context.wrap_socket(peer, server_hostname=address) as tls:
                    assert tls.version() == expected
                    tls.sendall(b'GET / HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n')
                    response = b''
                    while chunk := tls.recv(4096):
                        response += chunk
                    assert b'200 OK' in response and ('protocol=' + expected).encode() in response
        # Prove that the negative controls fail for their intended reasons.
        untrusted = ssl.create_default_context()
        try:
            with socket.create_connection(('127.0.0.1', 18443), timeout=5) as peer:
                with untrusted.wrap_socket(peer, server_hostname=address):
                    raise AssertionError('The generated root was unexpectedly trusted')
        except ssl.SSLCertVerificationError:
            pass
        wrong_protocol = ssl.create_default_context(cafile=str(root / 'root.pem'))
        wrong_protocol.minimum_version = wrong_protocol.maximum_version = ssl.TLSVersion.TLSv1_3
        try:
            with socket.create_connection(('127.0.0.1', 18444), timeout=5) as peer:
                with wrong_protocol.wrap_socket(peer, server_hostname=address):
                    raise AssertionError('The TLS 1.2-only listener accepted TLS 1.3')
        except ssl.SSLError:
            pass
        print('Host fixture checks passed: TLS 1.2/1.3, exact response marker, untrusted CA and protocol rejection.')
    finally:
        for server in servers:
            server.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('--address', required=True, type=ipaddress.IPv4Address)
    parser.add_argument('--create', action='store_true')
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if not ssl.HAS_TLSv1_3:
        parser.error('Use a Python runtime with TLS 1.3 support')
    if not args.address.is_private:
        parser.error('Bind only to the private test network')
    address = str(args.address)
    if args.create:
        fixtures(args.root, address)
    assert json.loads((args.root / 'fixture.json').read_text())['address'] == address
    if args.self_test:
        self_test(args.root, address)
        return
    servers = [Endpoint(args.root, address, port, version) for port, version in
               ((18443, ssl.TLSVersion.TLSv1_3), (18444, ssl.TLSVersion.TLSv1_2))]
    print('Local certificate test listening on ports 18443 and 18444.', flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        for server in servers:
            server.close()


if __name__ == '__main__':
    main()
