import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]


class BrowserHookProfileTests(unittest.TestCase):
    def rejected(self, mask, flags, expected):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                ["cmake", "-S", str(ROOT / "tls13"), "-B", directory,
                 f"-DTLS_FIXER_BROWSER_HOOK_MASK={mask}", *flags],
                capture_output=True, text=True, timeout=60)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(expected, result.stdout + result.stderr)

    def test_selection_requires_passthrough(self):
        self.rejected("0", [], "Selective hooks require the Vita passthrough diagnostic")

    def test_invalid_mask(self):
        for mask in ("16", "-1", "01", "0x1", "all", "1;2"):
            with self.subTest(mask=mask):
                self.rejected(mask, [], "Hook mask must be a decimal integer from 0 to 15")

    def test_incompatible_profiles(self):
        flags = ["-DTLS_FIXER_BUILD_VITA_PROVIDER=ON", "-DTLS_FIXER_BROWSER_START_DIAGNOSTICS=ON",
                 "-DTLS_FIXER_BROWSER_PASSTHROUGH_ONLY=ON"]
        for mode in ("TLS_FIXER_BROWSER_INITIALIZE_ONLY", "TLS_FIXER_ENABLE_RUNTIME_UDP",
                     "TLS_FIXER_BUILD_VITA_PROBE"):
            with self.subTest(mode=mode):
                self.rejected("8", flags + [f"-D{mode}=ON"],
                              "Selective hooks require the Vita passthrough diagnostic")


if __name__ == "__main__":
    unittest.main()
