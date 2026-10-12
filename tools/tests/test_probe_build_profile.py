import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]


class ProbeBuildProfileTests(unittest.TestCase):
    def rejected(self, flags, expected):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(["cmake", "-S", str(ROOT / "tls13"), "-B", directory,
                                     "-DTLS_FIXER_BUILD_VITA_PROBE=ON", *flags],
                                    capture_output=True, text=True, timeout=60)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(expected, result.stdout + result.stderr)

    def test_native_toolchain_required(self):
        self.rejected([], "Probe requires the VitaSDK toolchain")

    def test_probe_cannot_include_provider_or_host_tests(self):
        for flag in ("TLS_FIXER_BUILD_VITA_PROVIDER", "TLS_FIXER_BUILD_HOST_TESTS",
                     "TLS_FIXER_BUILD_TRANSPORT_TESTS", "TLS_FIXER_ENABLE_SANITIZERS",
                     "TLS_FIXER_BROWSER_START_DIAGNOSTICS", "TLS_FIXER_BROWSER_PASSTHROUGH_ONLY",
                     "TLS_FIXER_ENABLE_RUNTIME_UDP"):
            with self.subTest(flag=flag):
                self.rejected([f"-D{flag}=ON"], "Probe must be built separately")


if __name__ == "__main__":
    unittest.main()
