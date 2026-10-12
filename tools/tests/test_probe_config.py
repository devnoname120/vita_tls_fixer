import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).parents[1] / "probe_config.py"


class ProbeConfigTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("probe_config", SCRIPT)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        cls.ca, cls.key = cls.root / "ca.pem", cls.root / "server.key"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=Probe CA", "-keyout", str(cls.key), "-out", str(cls.ca)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_valid_and_identity(self):
        config = self.module.validate("192.168.1.249", "probe.test", "8443", "8444", self.ca)
        self.assertEqual(config["address"], "192.168.1.249")
        self.assertEqual(config["tls13_port"], 8443)
        self.assertEqual(len(config["ca_sha256"]), 64)

    def test_invalid_endpoint_refused(self):
        values = ("8.8.8.8", "127.0.0.1", "192.168.01.2", "192.168.1.256", "::1", "", "10.0.0.1\n")
        for address in values:
            with self.subTest(address=address), self.assertRaises(ValueError):
                self.module.validate(address, "probe.test", "8443", "8444", self.ca)
        for name in ("", "-bad.test", "bad-.test", "x..test", "x\r\nInjected", "a" * 64 + ".test", "192.168.1.1"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.module.validate("10.0.0.2", name, "8443", "8444", self.ca)
        for first, second in (("0", "8444"), ("8443", "8443"), ("65536", "8444"), ("08443", "8444"), ("abc", "8444")):
            with self.subTest(ports=(first, second)), self.assertRaises(ValueError):
                self.module.validate("10.0.0.2", "probe.test", first, second, self.ca)

    def test_private_or_invalid_material_refused(self):
        for data in (self.key.read_bytes(), self.ca.read_bytes() + self.key.read_bytes(), b"garbage", b"x" * 65537):
            path = self.root / "invalid.pem"
            path.write_bytes(data)
            with self.assertRaises(ValueError):
                self.module.validate("172.16.1.1", "probe.test", "8443", "8444", path)

    def test_certificate_read_is_bounded_before_validation(self):
        class BoundedFile(io.BytesIO):
            def read(self, size=-1):
                self.last_size = size
                if size < 0 or size > 65537:
                    raise AssertionError("unbounded certificate input read")
                return super().read(size)

        content = BoundedFile(b"x" * 65537)
        with patch.object(Path, "open", return_value=content), self.assertRaises(ValueError):
            self.module.validate("10.0.0.2", "probe.test", "8443", "8444", self.ca)
        self.assertEqual(content.last_size, 65537)

    def test_cli_creates_only_public_identified_inputs(self):
        archive = self.root / "fixture-archive"
        archive.write_bytes(b"unit-test archive")
        output = self.root / "generated"
        argv = [str(SCRIPT), "--address", "10.0.0.2", "--name", "probe.test", "--tls13-port", "8443",
                "--tls12-port", "8444", "--ca", str(self.ca), "--archive", str(archive),
                "--compiler", "fixture-compiler", "--output", str(output)]
        compiler = subprocess.CompletedProcess(["fixture-compiler"], 0, "fixture compiler 1.0\n", "")
        with patch.object(sys, "argv", argv), patch.object(self.module, "ARCHIVE_SHA256", self.module.digest(archive.read_bytes())), \
                patch.object(self.module.subprocess, "run", return_value=compiler) as run:
            self.module.main()
        run.assert_called_once_with(["fixture-compiler", "--version"], capture_output=True,
                                    text=True, check=True, timeout=10)
        self.assertEqual({path.name for path in output.iterdir()}, {"probe-ca.pem", "probe-build.json", "probe_config.h"})
        receipt = json.loads((output / "probe-build.json").read_text())
        self.assertFalse(receipt["hardware_validated"])
        self.assertEqual(receipt["compiler"], "fixture compiler 1.0")
        self.assertIn("compile_flags", receipt)
        self.assertEqual(receipt["build_type"], "Release")
        self.assertEqual((output / "probe-ca.pem").read_bytes(), self.ca.read_bytes())
        identity = receipt.pop("build_id")
        self.assertEqual(identity, self.module.digest(json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()))
        self.assertIn(identity, (output / "probe_config.h").read_text())
        for path in output.iterdir():
            self.assertNotIn(b"PRIVATE KEY", path.read_bytes())


if __name__ == "__main__":
    unittest.main()
