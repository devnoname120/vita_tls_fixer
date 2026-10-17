import base64
import contextlib
import hashlib
import http.server
import json
import os
from pathlib import Path
import re
import shlex
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]


def certificates(data):
    blocks = re.findall(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", data, re.S)
    return {base64.b64decode(re.sub(rb"-----[^\n]+-----|\s+", b"", block)) for block in blocks}


class CertificateUpdateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="tls-fixer-certificate-tests-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        environment = dict(os.environ)
        paths = [str(path) for path in (Path('/opt/homebrew/opt/curl/lib/pkgconfig'),
                                        Path('/opt/homebrew/opt/openssl@3/lib/pkgconfig')) if path.exists()]
        if paths:
            environment['PKG_CONFIG_PATH'] = os.pathsep.join(paths + [environment.get('PKG_CONFIG_PATH', '')])
        try:
            flags = subprocess.check_output(['pkg-config', '--cflags', '--libs', 'libcurl', 'openssl'],
                                            env=environment, text=True, stderr=subprocess.PIPE)
        except (OSError, subprocess.CalledProcessError):
            cls.temporary.cleanup()
            raise unittest.SkipTest('Native certificate tests require libcurl/OpenSSL development libraries and pkg-config')
        cls.executable = cls.directory / 'certificates'
        command = [os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror', '-O1', '-g',
                   str(ROOT / 'installer/certificates.c'), str(ROOT / 'installer/certificates_cli.c'),
                   *shlex.split(flags), '-o', str(cls.executable)]
        if os.environ.get('TLS_FIXER_CERTIFICATE_SANITIZERS') == '1':
            command[1:1] = ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
        subprocess.run(command, check=True, capture_output=True, timeout=60)
        cls.roots = {}
        for name in ('sony', 'mozilla', 'new', 'system'):
            key, certificate = cls.directory / (name + '.key'), cls.directory / (name + '.pem')
            cls.openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '1',
                        '-keyout', key, '-out', certificate, '-subj', '/CN=' + name,
                        '-addext', 'basicConstraints=critical,CA:TRUE',
                        '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
            cls.roots[name] = certificate
        cls.servers = {}
        for name, issuer, hostname in [('good', 'mozilla', 'localhost'), ('untrusted', 'system', 'localhost'),
                                        ('sony', 'sony', 'localhost'), ('wrong-host', 'mozilla', 'wrong.invalid')]:
            key, csr, certificate = [cls.directory / ('server-' + name + suffix) for suffix in ('.key', '.csr', '.crt')]
            cls.openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', key,
                        '-out', csr, '-subj', '/CN=' + hostname)
            extensions = cls.directory / (name + '.ext')
            extensions.write_text('subjectAltName=DNS:' + hostname + '\nbasicConstraints=critical,CA:FALSE\n')
            cls.openssl('x509', '-req', '-in', csr, '-CA', cls.roots[issuer],
                        '-CAkey', cls.directory / (issuer + '.key'), '-CAcreateserial',
                        '-out', certificate, '-days', '1', '-sha256', '-extfile', extensions)
            cls.servers[name] = (certificate, key)

    @classmethod
    def openssl(cls, *arguments):
        subprocess.run(['openssl', *map(str, arguments)], check=True, capture_output=True, timeout=30)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    @contextlib.contextmanager
    def endpoint(self, body, identity='good', code=200, delay=0):
        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def handle(self):
                try:
                    super().handle()
                except (OSError, ssl.SSLError):
                    pass

            def log_message(self, *args):
                pass

            def do_GET(self):
                self.send_response(code)
                self.send_header('Content-Length', str(len(body)))
                if code == 302:
                    self.send_header('Location', '/other')
                self.end_headers()
                if delay:
                    time.sleep(delay)
                try:
                    self.wfile.write(body)
                except (OSError, ssl.SSLError):
                    pass

        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        server.daemon_threads = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(*map(str, self.servers[identity]))
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield f'https://localhost:{server.server_port}/cacert.pem'
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def prepare(self, url='offline', sony=None, mozilla=None, environment=None, timeout=2):
        output = self.directory / 'output.pem'
        output.write_bytes(b'previous output must survive failure')
        result = subprocess.run([str(self.executable), str(sony or self.roots['sony']),
                                 str(mozilla or self.roots['mozilla']), url, str(output), str(timeout)],
                                capture_output=True, text=True, timeout=10,
                                env=dict(os.environ, **(environment or {})))
        return result, output.read_bytes()

    def require_fallback(self, result, data):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('downloaded=0', result.stdout)
        self.assertTrue(data.startswith(self.roots['sony'].read_bytes()))
        self.assertEqual(certificates(data), certificates(self.roots['sony'].read_bytes()) |
                         certificates(self.roots['mozilla'].read_bytes()))

    def test_offline_uses_only_embedded_sources(self):
        self.require_fallback(*self.prepare())

    def test_success_replaces_mozilla_and_preserves_sony_without_duplicates(self):
        body = self.roots['new'].read_bytes() + self.roots['sony'].read_bytes()
        with self.endpoint(body) as url:
            result, data = self.prepare(url, environment={'https_proxy': 'http://127.0.0.1:1'})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('downloaded=1', result.stdout)
        self.assertIn('combined=2', result.stdout)
        self.assertEqual(certificates(data), certificates(body))
        self.assertNotIn(next(iter(certificates(self.roots['mozilla'].read_bytes()))), certificates(data))

    def test_sony_file_layout_survives_download_and_crlf_encoding(self):
        sony = self.directory / 'sony-native-layout.pem'
        original = (b'# Sony certificate position is part of the native ABI\r\n' +
                    self.roots['sony'].read_bytes().replace(b'\n', b'\r\n') +
                    b'\r\n# A second embedded Sony authority\r\n' +
                    self.roots['mozilla'].read_bytes().replace(b'\n', b'\r\n'))
        sony.write_bytes(original)
        with self.endpoint(self.roots['new'].read_bytes() + self.roots['sony'].read_bytes()) as url:
            result, data = self.prepare(url, sony=sony)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(data.startswith(original), 'Sony comments, offsets and CRLFs must remain exact')
        self.assertEqual(certificates(data), certificates(original) | certificates(self.roots['new'].read_bytes()))
        self.assertEqual(data.count(b'-----BEGIN CERTIFICATE-----'), 3)

    def test_connection_failure_uses_embedded(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        self.require_fallback(*self.prepare(f'https://localhost:{port}/cacert.pem'))

    def test_http_failure_and_redirect_use_embedded(self):
        for code in (503, 302):
            with self.subTest(code=code), self.endpoint(self.roots['new'].read_bytes(), code=code) as url:
                self.require_fallback(*self.prepare(url))

    def test_timeout_uses_embedded(self):
        with self.endpoint(self.roots['new'].read_bytes(), delay=2) as url:
            self.require_fallback(*self.prepare(url, timeout=1))

    def test_system_trust_is_not_imported(self):
        environment = {name: str(self.roots['system']) for name in ('SSL_CERT_FILE', 'CURL_CA_BUNDLE')}
        environment['SSL_CERT_DIR'] = str(self.directory)
        with self.endpoint(self.roots['new'].read_bytes(), identity='untrusted') as url:
            self.require_fallback(*self.prepare(url, environment=environment))

    def test_sony_roots_are_not_used_to_authenticate_the_download(self):
        with self.endpoint(self.roots['new'].read_bytes(), identity='sony') as url:
            self.require_fallback(*self.prepare(url))

    def test_hostname_verification_is_required(self):
        with self.endpoint(self.roots['new'].read_bytes(), identity='wrong-host') as url:
            self.require_fallback(*self.prepare(url))

    def test_bad_downloads_are_discarded_completely(self):
        root = self.roots['new'].read_bytes()
        for body in (b'', b'<html>not a bundle</html>', root + b'-----BEGIN CERTIFICATE-----\nbroken',
                     root + b'\0', self.servers['good'][0].read_bytes(),
                     root + b'-----BEGIN PRIVATE KEY-----\nnot allowed\n-----END PRIVATE KEY-----'):
            with self.subTest(body_bytes=len(body)), self.endpoint(body) as url:
                self.require_fallback(*self.prepare(url))

    def test_oversized_download_uses_embedded(self):
        with self.endpoint(b'x' * (4 * 1024 * 1024 + 1)) as url:
            self.require_fallback(*self.prepare(url))

    def test_missing_or_corrupt_embedded_sources_fail_without_output_changes(self):
        bad = self.directory / 'bad.pem'
        bad.write_bytes(b'not a certificate bundle')
        for sources in ({'sony': bad}, {'mozilla': bad}, {'sony': self.directory / 'missing.pem'}):
            with self.subTest(sources=sources):
                result, data = self.prepare(**sources)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(data, b'previous output must survive failure')

    def test_packaged_fallback_matches_authoritative_inputs(self):
        result, data = self.prepare(sony=ROOT / 'misc/sony-certs.pem', mozilla=ROOT / 'misc/mozilla-certs.pem')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        expected = certificates((ROOT / 'misc/sony-certs.pem').read_bytes())
        expected.update(certificates((ROOT / 'misc/mozilla-certs.pem').read_bytes()))
        self.assertEqual(certificates(data), expected)
        self.assertTrue(data.startswith((ROOT / 'misc/sony-certs.pem').read_bytes()))
        # Fixed DNAS PEM ranges and hashes from the native 3.60 SceSsl loader.
        # Preserving DER identities while rewriting these bytes is insufficient.
        native = [
            (20, 'f4ba0fc74e45c147685cacb2c2a80b481ea6e260'),
            (1452, '5af08bf76d25c39c3d5b59bfae4fad1e180029ce'),
            (2884, 'ca67864b35c5da9b291caf59e59d96dd9d654e52'),
            (4316, 'a5108fa3ca94f36fcba70c2304350bee600036f5'),
            (5748, '7121e9fc59c1f2df557f6b70022bd42c32e801c3')]
        for offset, digest in native:
            self.assertEqual(hashlib.sha1(data[offset:offset + 1410]).hexdigest(), digest)
        self.assertEqual(data, (ROOT / 'misc/certs.cer').read_bytes())
        manifest = json.loads((ROOT / 'misc/certificate-sources.json').read_text())['combined']
        self.assertEqual(manifest['bytes'], len(data))
        self.assertEqual(manifest['sha256'], hashlib.sha256(data).hexdigest())


if __name__ == '__main__':
    unittest.main()
