from pathlib import Path
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class InstallerOptionsTests(unittest.TestCase):
    def test_conflict_removal_and_interruption_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            exe = Path(directory) / 'conflicts'
            subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=address,undefined', '-I', str(ROOT / 'installer'), '-I', str(ROOT),
                            str(ROOT / 'installer/conflicts.c'), str(ROOT / 'installer/tests/test_conflicts.c'),
                            '-o', str(exe)], check=True, capture_output=True, timeout=60)
            result = subprocess.run([str(exe)], check=True, capture_output=True, text=True, timeout=20)
            self.assertIn('PASS', result.stdout)

    def test_config_edits_preserve_active_file_at_failure_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            exe = Path(directory) / 'config'
            subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=address,undefined', '-I', str(ROOT / 'installer'), '-I', str(ROOT),
                            str(ROOT / 'installer/config.c'), str(ROOT / 'installer/tests/test_config.c'),
                            '-o', str(exe)], check=True, capture_output=True, timeout=60)
            result = subprocess.run([str(exe)], check=True, capture_output=True, text=True, timeout=10)
            self.assertIn('PASS', result.stdout)
    def test_system_backend_payloads_and_failed_activation_order(self):
        with tempfile.TemporaryDirectory() as directory:
            exe = Path(directory) / 'system-payloads'
            subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=address,undefined', '-I', str(ROOT / 'installer'),
                            str(ROOT / 'installer/options.c'), str(ROOT / 'installer/system_payloads.c'),
                            str(ROOT / 'installer/tests/test_system_payloads.c'), '-o', str(exe)],
                           check=True, capture_output=True, timeout=60)
            result = subprocess.run([str(exe)], check=True, capture_output=True, text=True, timeout=10)
            self.assertIn('PASS', result.stdout)

    def test_component_operations_preserve_unselected_components(self):
        with tempfile.TemporaryDirectory() as directory:
            exe = Path(directory) / 'options'
            subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-I', str(ROOT / 'installer'), str(ROOT / 'installer/options.c'),
                            str(ROOT / 'installer/tests/test_options.c'), '-o', str(exe)],
                           check=True, capture_output=True, timeout=60)
            result = subprocess.run([str(exe)], check=True, capture_output=True, text=True, timeout=10)
            self.assertIn('PASS', result.stdout)


if __name__ == '__main__':
    unittest.main()
