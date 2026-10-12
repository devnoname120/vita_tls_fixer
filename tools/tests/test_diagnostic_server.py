import json
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import time
import unittest
import importlib.util

SPEC = importlib.util.spec_from_file_location("diagnostic_server", Path(__file__).parents[1] / "tls13_test_server.py")
SERVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SERVER)


class DiagnosticServerTests(unittest.TestCase):
    def test_probe_nonce_is_optional_and_bounded(self):
        nonce = "0123456789abcdef0123456789abcdef"
        self.assertIsNone(SERVER.probe_nonce("/?tls_fixer=browser-control"))
        self.assertEqual(SERVER.probe_nonce("/?tls_fixer_probe=" + nonce), nonce)
        for path in ("/?tls_fixer_probe=", "/?tls_fixer_probe=" + "f" * 31,
                     "/?tls_fixer_probe=" + "x" * 32, "/?tls_fixer_probe=" + nonce + "0",
                     "/?tls_fixer_probe=" + nonce + "&tls_fixer_probe=" + nonce,
                     "/?tls_fixer_probe=" + nonce + "%0d%0a", "/" + "x" * 1024):
            with self.subTest(path=path), self.assertRaises(ValueError):
                SERVER.probe_nonce(path)

    def test_strict_versions_and_fresh_response(self):
        script = Path(__file__).parents[1] / "tls13_test_server.py"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            certificate, key = root / "cert.pem", root / "key.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
                            "-keyout", str(key), "-out", str(certificate)],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for protocol, version in [("1.2", ssl.TLSVersion.TLSv1_2), ("1.3", ssl.TLSVersion.TLSv1_3)]:
                with socket.socket() as reservation:
                    reservation.bind(("127.0.0.1", 0))
                    port = reservation.getsockname()[1]
                process = subprocess.Popen(["python3", str(script), "--cert", str(certificate), "--key", str(key),
                                            "--bind", "127.0.0.1", "--port", str(port), "--tls", protocol],
                                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                try:
                    context = ssl.create_default_context(cafile=str(certificate))
                    context.minimum_version = context.maximum_version = version
                    data = []
                    nonce = "0123456789abcdef0123456789abcdef"
                    for index in range(2):
                        deadline = time.monotonic() + 5
                        while True:
                            try:
                                raw = socket.create_connection(("127.0.0.1", port), timeout=2)
                                break
                            except ConnectionRefusedError:
                                if time.monotonic() >= deadline:
                                    self.fail("diagnostic server did not start")
                                time.sleep(0.02)
                        with context.wrap_socket(raw, server_hostname="localhost") as connection:
                            self.assertEqual(connection.version(), "TLSv" + protocol)
                            path = "/" if index == 0 else "/?tls_fixer_probe=" + nonce
                            connection.sendall(("GET " + path + " HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").encode())
                            response = bytearray()
                            while True:
                                chunk = connection.recv(4096)
                                if not chunk:
                                    break
                                response.extend(chunk)
                            data.append(bytes(response))
                    self.assertIn(b"HTTP/1.1 200 OK", data[0])
                    self.assertIn(b"Cache-Control: no-store", data[0])
                    self.assertIn(("TLSv" + protocol).encode(), data[0])
                    self.assertNotEqual(data[0], data[1])
                    self.assertNotIn(b"X-TLS-Fixer-Probe-Nonce:", data[0])
                    self.assertIn(("X-TLS-Fixer-Probe-Nonce: " + nonce + "\r\n").encode(), data[1])
                    self.assertIn(nonce.encode(), data[1].split(b"\r\n\r\n", 1)[1])
                finally:
                    process.terminate()
                    _, stderr = process.communicate(timeout=5)
                    self.assertNotIn(b"Traceback", stderr)


if __name__ == "__main__":
    unittest.main()
