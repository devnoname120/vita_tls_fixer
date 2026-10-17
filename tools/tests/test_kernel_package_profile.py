"""A recent diagnostic output must not bypass normal VPK kernel configuration."""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(shutil.which("make"), "make is required")
class KernelPackageProfileTests(unittest.TestCase):
    def test_cached_debug_provider_is_reconfigured_for_vpk(self):
        makefile = (ROOT / "Makefile").read_text()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Makefile").write_text(makefile)
            (root / "tls13").mkdir()
            (root / "build/deps").mkdir(parents=True)
            (root / "build/deps/mbedtls-4.2.0.tar.bz2").touch()
            provider = root / "build/tls13-vita/provider/tls_fixer_http.suprx"
            provider.parent.mkdir(parents=True)
            provider.write_bytes(b"recent debug provider")
            os.utime(provider, (2_000_000_000, 2_000_000_000))
            (provider.parent.parent / "CMakeCache.txt").write_text(
                "TLS_FIXER_ENABLE_DEBUG_LOG:BOOL=ON\n"
                "TLS_FIXER_ENABLE_RUNTIME_UDP:BOOL=ON\n"
            )
            result = subprocess.run(
                ["make", "-n", "build/tls13-vita/provider/tls_fixer_http.suprx"],
                cwd=root, check=True, capture_output=True, text=True,
            )
            self.assertIn("cmake -S tls13 -B build/tls13-vita", result.stdout)
            for option in ("ENABLE_DEBUG_LOG", "ENABLE_RUNTIME_UDP", "BROWSER_START_DIAGNOSTICS",
                           "BROWSER_PASSTHROUGH_ONLY", "BROWSER_INITIALIZE_ONLY"):
                self.assertIn(f"-DTLS_FIXER_{option}=OFF", result.stdout)
            self.assertIn("-DTLS_FIXER_BROWSER_HOOK_MASK=", result.stdout)

    def test_recent_cached_kernel_still_reconfigures_normal_profile(self):
        makefile = (ROOT / "Makefile").read_text()
        rule = next(line for line in makefile.splitlines() if line.startswith("$(KERNEL_MODULE):"))
        dependencies = rule.split(":", 1)[1].replace(
            "$(FIRMWARE_PROFILES)", "tls13/include/tls_fixer/firmware_profiles.h"
        ).split()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Makefile").write_text(makefile)
            for dependency in dependencies:
                self.assertNotIn("$", dependency, "Extend the fixture for new Make variables")
                path = root / dependency
                path.parent.mkdir(parents=True, exist_ok=True)
                if dependency != "Makefile":
                    path.touch()
                os.utime(path, (1_000_000_000, 1_000_000_000))
            kernel = root / "build/kernel/tls_fixer.skprx"
            kernel.parent.mkdir(parents=True, exist_ok=True)
            kernel.write_bytes(b"cached diagnostic kernel")
            os.utime(kernel, (1_000_000_010, 1_000_000_010))
            (kernel.parent / "CMakeCache.txt").write_text(
                "TLS_FIXER_REDIRECTION_ONLY:BOOL=ON\nTLS_FIXER_ALLOCATION_PROBE:BOOL=ON\n"
            )
            result = subprocess.run(
                ["make", "-n", "build/kernel/tls_fixer.skprx"], cwd=root,
                check=True, capture_output=True, text=True,
            )
            self.assertIn("cmake -S kernel -B build/kernel", result.stdout)
            self.assertIn("-DTLS_FIXER_BROWSER_POST_START=ON", result.stdout)
            self.assertIn("-DTLS_FIXER_HTTP_PROVIDER_PATH=vs0:/data/external/tls_fixer/native/tls_fixer_http.suprx", result.stdout)
            self.assertIn("-DTLS_FIXER_HTTP_TEST_TITLE_ID=", result.stdout)
            self.assertIn("-DTLS_FIXER_ENABLE_SELF_DISARM=OFF", result.stdout)
            for option in ("REDIRECTION_ONLY", "BROWSER_ACTIVATION", "ENABLE_BOOT_TRACE",
                           "MEMORY_PROBE", "ALLOCATION_PROBE", "SKIP_HTTP_START", "SKIP_DNS_START"):
                self.assertIn(f"-DTLS_FIXER_{option}=OFF", result.stdout)
            self.assertIn("cmake --build build/kernel", result.stdout)


if __name__ == "__main__":
    unittest.main()
