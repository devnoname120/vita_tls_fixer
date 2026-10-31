"""Keep opt-in package builds isolated from outer make overrides."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('augmented_builder', ROOT / 'tools/build_augmented_package.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class PackageIsolationTests(unittest.TestCase):
    def test_release_rejects_cached_one_shot_or_recording_kernel(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'kernel').mkdir()
            cache = root / 'kernel/CMakeCache.txt'
            options = {'CMAKE_BUILD_TYPE': 'Release', 'TLS_FIXER_INSTALLED_AUGMENTED_HTTP': 'ON',
                       'TLS_FIXER_AUGMENTED_RELEASE': 'ON', 'TLS_FIXER_ENABLE_SELF_DISARM': 'OFF',
                       'TLS_FIXER_EMBEDDED_HTTP_PATH': '', 'TLS_FIXER_HTTP_TEST_TITLE_ID': ''}
            for option in ('ENABLE_BOOT_TRACE', 'TRACE_MODULE_PATHS', 'BROWSER_INVENTORY',
                           'TRACE_ACTIVATION_ONLY', 'MEMORY_PROBE', 'ALLOCATION_PROBE',
                           'MAPPING_PROBE', 'STACK_HEADROOM', 'PRIVATE_GUI_CLIENTS',
                           'SELF_DISARM_ONLY', 'DISARM_RESULT_ONLY', 'INITIALIZE_ONLY',
                           'REDIRECTION_ONLY', 'PREPARE_ONLY', 'BROWSER_ACTIVATION',
                           'BROWSER_START_DIAGNOSTICS', 'INSPECT_CONNECT_PATCH', 'HTTP_GLOBAL_DIAGNOSTIC'):
                options['TLS_FIXER_' + option] = 'OFF'
            def write(values):
                cache.write_text(''.join(f'{name}:STRING={value}\n' for name, value in values.items()))
            write(options)
            self.assertEqual(builder.validate_kernel_profile(root, True), options)
            for name in ('TLS_FIXER_ENABLE_SELF_DISARM', 'TLS_FIXER_ENABLE_BOOT_TRACE',
                         'TLS_FIXER_ALLOCATION_PROBE'):
                write({**options, name: 'ON'})
                with self.assertRaisesRegex(ValueError, name):
                    builder.validate_kernel_profile(root, True)
            write({**options, 'TLS_FIXER_AUGMENTED_RELEASE': 'OFF', 'TLS_FIXER_ENABLE_SELF_DISARM': 'ON'})
            builder.validate_kernel_profile(root, False)

    def test_child_make_does_not_inherit_outer_build_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            program = root / 'make'
            record = root / 'environment.json'
            program.write_text('#!' + sys.executable + '\nimport os,json\n'
                               'open(os.environ["RECORD"],"w").write(json.dumps(dict(os.environ)))\n')
            program.chmod(0o755)
            with patch.dict(os.environ, {'PATH': str(root), 'RECORD': str(record),
                                         'MAKEFLAGS': 'TARGET=/outside/release BUILD_DIR=/outside/build',
                                         'MFLAGS': '-j99', 'MAKEOVERRIDES': 'TARGET=/outside/release',
                                         'MAKELEVEL': '3', 'PRESERVED_VALUE': 'expected'}):
                builder.run(['make'], root, root / 'build.log')
            seen = json.loads(record.read_text())
            for name in ('MAKEFLAGS', 'MFLAGS', 'MAKEOVERRIDES', 'MAKELEVEL'):
                self.assertNotIn(name, seen)
            self.assertEqual(seen['PRESERVED_VALUE'], 'expected')

    def test_source_cleanup_cannot_escape_owned_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            unrelated = root / 'unrelated'
            unrelated.write_bytes(b'keep')
            record = root / 'files.json'
            record.write_text(json.dumps({'../unrelated': 'not a valid source record'}))
            with patch.object(builder.subprocess, 'check_output', return_value=b''):
                with self.assertRaisesRegex(ValueError, 'inside their source directory'):
                    builder.copy_source(root / 'source', record)
            self.assertEqual(unrelated.read_bytes(), b'keep')


if __name__ == '__main__':
    unittest.main()
