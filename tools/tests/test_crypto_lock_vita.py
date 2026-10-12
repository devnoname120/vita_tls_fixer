import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class CryptoLockTests(unittest.TestCase):
    def test_native_lock_adapter(self):
        environment = dict(os.environ)
        openssl = Path('/opt/homebrew/opt/openssl@3/lib/pkgconfig')
        if openssl.exists():
            environment['PKG_CONFIG_PATH'] = str(openssl) + os.pathsep + environment.get('PKG_CONFIG_PATH', '')
        try:
            flags = subprocess.check_output(['pkg-config', '--cflags', 'openssl'], env=environment, text=True)
        except (OSError, subprocess.CalledProcessError):
            self.skipTest('OpenSSL headers and pkg-config are required')
        with tempfile.TemporaryDirectory(prefix='tls-fixer-crypto-lock-') as temporary:
            executable = Path(temporary) / 'crypto-lock'
            command = [os.environ.get('CC', 'cc'), '-std=c11', '-D_POSIX_C_SOURCE=200809L',
                       '-Wall', '-Wextra', '-Werror', '-O1', '-g', '-pthread',
                       '-I' + str(ROOT / 'tools/tests/fixtures/crypto_lock'),
                       str(ROOT / 'tools/tests/fixtures/crypto_lock/test_lock.c'),
                       *shlex.split(flags), '-o', str(executable)]
            if os.environ.get('TLS_FIXER_CERTIFICATE_SANITIZERS') == '1':
                command[1:1] = ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
            subprocess.run(command, check=True, capture_output=True, timeout=60)
            result = subprocess.run([str(executable)], check=True, capture_output=True, text=True, timeout=30)
            self.assertIn('concurrent atomic/reference updates PASS', result.stdout)


if __name__ == '__main__':
    unittest.main()
