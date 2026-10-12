import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class IterateScriptTests(unittest.TestCase):
    def run_wrapper(self, exit_code=0, previous_receipt=False, locked=False):
        source = ROOT / 'iterate.sh'
        self.assertTrue(source.is_file(), 'The iteration wrapper is not implemented')
        with tempfile.TemporaryDirectory(prefix='tls_fixer iterate ') as temporary:
            root = Path(temporary)
            (root / 'build').mkdir()
            (root / 'bin').mkdir()
            shutil.copyfile(source, root / 'iterate.sh')
            capture = root / 'arguments.txt'
            python = root / 'bin/python3'
            python.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$CAPTURE"\nexit "$EXIT_CODE"\n')
            python.chmod(0o700)
            if previous_receipt:
                (root / 'build/passthrough-control-user-armed.json').write_text('{}')
            if locked:
                (root / 'build/.iterate.lock').mkdir()
            environment = dict(os.environ, PATH=str(root / 'bin') + os.pathsep + os.environ['PATH'],
                               CAPTURE=str(capture), EXIT_CODE=str(exit_code))
            result = subprocess.run(['/bin/sh', str(root / 'iterate.sh')], cwd='/', env=environment,
                                    capture_output=True, text=True, timeout=10)
            arguments = capture.read_text().splitlines() if capture.exists() else []
            self.assertEqual((root / 'build/.iterate.lock').exists(), locked)
            return result.returncode, arguments

    def test_single_guarded_cycle(self):
        code, arguments = self.run_wrapper()
        self.assertEqual(code, 0)
        self.assertEqual(arguments, ['tools/vita_tls_cycle.py', 'run', '--stage',
            'build/stage_passthrough_control_files_only.py', '--arm',
            'build/arm_passthrough_control_once.py', '--receipt',
            'build/passthrough-control-user-armed.json', '--browser-title-id', 'NPXS10003',
            '--settle-seconds', '30'])

    def test_failure_is_not_retried(self):
        code, arguments = self.run_wrapper(exit_code=7)
        self.assertEqual(code, 7)
        self.assertEqual(arguments.count('run'), 1)

    def test_previous_arm_receipt_prevents_rerun(self):
        code, arguments = self.run_wrapper(previous_receipt=True)
        self.assertNotEqual(code, 0)
        self.assertEqual(arguments, [])

    def test_concurrent_invocation_is_rejected(self):
        code, arguments = self.run_wrapper(locked=True)
        self.assertNotEqual(code, 0)
        self.assertEqual(arguments, [])


if __name__ == '__main__':
    unittest.main()
