from pathlib import Path
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class InstallerOptionsTests(unittest.TestCase):
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
