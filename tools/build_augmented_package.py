#!/usr/bin/env python3
"""Build the opt-in augmented VPK without modifying normal build artifacts."""
import argparse
import copy
import hashlib
import json
import os
import shutil
import subprocess
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIRS = {'installer', 'kernel', 'tls13', 'psn_redirect', 'store_cover', 'old_dns_fix',
               'misc', 'sce_sys', 'licenses', 'tools'}
SOURCE_FILES = {'Makefile', 'main.c', 'font.c', 'font.h', 'graphics.c', 'graphics.h',
                'THIRD_PARTY_NOTICES.md'}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(args, cwd, log):
    environment = os.environ.copy()
    if args[0] == 'make':
        # Do not propagate an outer make's TARGET/BUILD_DIR command-line overrides
        # into the isolated source tree or inherit its closed jobserver handles.
        for name in ('MAKEFLAGS', 'MFLAGS', 'MAKEOVERRIDES', 'MAKELEVEL'):
            environment.pop(name, None)
    with log.open('ab') as output:
        output.write(('COMMAND ' + repr(args) + '\n').encode())
        output.flush()
        subprocess.run(args, cwd=cwd, env=environment,
                       stdout=output, stderr=subprocess.STDOUT, check=True)


def copy_source(destination, record):
    files = subprocess.check_output(['git', 'ls-files', '-z', '--cached', '--others',
                                     '--exclude-standard'], cwd=ROOT).decode().split('\0')
    selected = {name for name in files if name and
                (name in SOURCE_FILES or Path(name).parts[0] in SOURCE_DIRS)}
    selected = {name for name in selected if (ROOT / name).is_file() and
                '__pycache__' not in Path(name).parts and (ROOT / name).suffix != '.pyc'}
    previous = set(json.loads(record.read_text())) if record.exists() else set()
    if any(Path(name).is_absolute() or '..' in Path(name).parts for name in previous | selected):
        raise ValueError('Package source records must stay inside their source directory')
    if destination.exists() and not record.exists():
        raise ValueError('Refusing an unrecognized package source directory: ' + str(destination))
    destination.mkdir(parents=True, exist_ok=True)
    for name in previous - selected:
        (destination / name).unlink(missing_ok=True)
    hashes = {}
    for name in sorted(selected):
        source, target = ROOT / name, destination / name
        if source.is_symlink():
            raise ValueError('Package source must be a regular file: ' + name)
        target.parent.mkdir(parents=True, exist_ok=True)
        data = source.read_bytes()
        target.write_bytes(data)
        shutil.copystat(source, target)
        hashes[name] = digest(data)
    record.write_text(json.dumps(hashes, indent=2) + '\n')
    deps = destination / 'build/deps'
    deps.mkdir(parents=True, exist_ok=True)
    for archive in ('mbedtls-4.2.0.tar.bz2', 'curl-8.17.0.tar.gz'):
        target = deps / archive
        original = ROOT / 'build/deps' / archive
        if not original.is_file():
            raise ValueError('Missing source archive: ' + str(original))
        if target.is_symlink():
            if target.resolve() != original.resolve():
                raise ValueError('Unexpected package dependency link: ' + str(target))
        elif target.exists():
            if digest(target.read_bytes()) != digest(original.read_bytes()):
                raise ValueError('Package dependency differs from the source archive')
        else:
            target.symlink_to(original)


def validate_kernel_profile(output, release):
    cache = {}
    for line in (output / 'kernel/CMakeCache.txt').read_text().splitlines():
        if line and not line.startswith(('#', '//')) and ':' in line and '=' in line:
            name, value = line.split('=', 1)
            cache[name.split(':', 1)[0]] = value
    expected = {'CMAKE_BUILD_TYPE': 'Release', 'TLS_FIXER_INSTALLED_AUGMENTED_HTTP': 'ON',
                'TLS_FIXER_AUGMENTED_RELEASE': 'ON' if release else 'OFF',
                'TLS_FIXER_ENABLE_SELF_DISARM': 'OFF' if release else 'ON'}
    for option in ('ENABLE_BOOT_TRACE', 'TRACE_MODULE_PATHS', 'BROWSER_INVENTORY',
                   'TRACE_ACTIVATION_ONLY', 'MEMORY_PROBE', 'ALLOCATION_PROBE',
                   'MAPPING_PROBE', 'STACK_HEADROOM', 'PRIVATE_GUI_CLIENTS',
                   'SELF_DISARM_ONLY', 'DISARM_RESULT_ONLY', 'INITIALIZE_ONLY',
                   'REDIRECTION_ONLY', 'PREPARE_ONLY', 'BROWSER_ACTIVATION',
                   'BROWSER_START_DIAGNOSTICS', 'INSPECT_CONNECT_PATCH', 'HTTP_GLOBAL_DIAGNOSTIC'):
        expected['TLS_FIXER_' + option] = 'OFF'
    expected['TLS_FIXER_EMBEDDED_HTTP_PATH'] = ''
    expected['TLS_FIXER_HTTP_TEST_TITLE_ID'] = ''
    for name, value in expected.items():
        if cache.get(name) != value:
            raise ValueError(f'Kernel profile mismatch: {name}={cache.get(name)!r}, expected {value!r}')
    return expected


def build(args):
    output = args.build_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    kernel_profile = validate_kernel_profile(output, args.release)
    source = output / 'source'
    copy_source(source, output / 'source-files.json')
    common = ['BUILD_DIR=build', 'TARGET=tls_fixer']
    run(['make', '-j4', 'INSTALLER_HTTP_BACKEND=hooked', 'INSTALLER_AUGMENTED_RELEASE=0', *common],
        source, output / 'installer-build.log')
    # Separate main.o profile: stale app0 files cannot select the HTTP backend.
    run(['make', 'eboot.bin', 'INSTALLER_HTTP_BACKEND=augmented',
         'INSTALLER_AUGMENTED_RELEASE=' + ('1' if args.release else '0'), *common],
        source, output / 'installer-build.log')
    sfo = output / 'param.sfo'
    run(['vita-mksfoex', '-s', 'APP_VER=00.22', '-s', 'TITLE_ID=TLSF00001',
         'tls_fixer' if args.release else 'tls_fixer augmented test', str(sfo)], ROOT, output / 'installer-build.log')
    kernel = output / 'kernel/tls_fixer.skprx'
    module = args.http_module.resolve()
    base = source / 'tls_fixer.vpk'
    replacement = {'tls_fixer.skprx': kernel.read_bytes(), 'sce_sys/param.sfo': sfo.read_bytes(),
                   'eboot.bin': (source / 'eboot.bin').read_bytes(),
                   'libhttp_augmented.suprx': module.read_bytes()}
    removed = {'tls_fixer_http.suprx', 'lhttp.suprx'}
    target = output / ('tls_fixer-augmented-release.vpk' if args.release else 'tls_fixer-augmented-test.vpk')
    temporary = target.with_suffix('.vpk.tmp')
    with zipfile.ZipFile(base) as original, zipfile.ZipFile(temporary, 'w') as result:
        if original.testzip() is not None:
            raise ValueError('Invalid base package')
        for info in original.infolist():
            if info.filename not in removed:
                result.writestr(info, replacement.pop(info.filename, original.read(info.filename)))
        for name, data in replacement.items():
            info = copy.copy(original.getinfo('lhttp.suprx'))
            info.filename = info.orig_filename = name
            result.writestr(info, data)
    with zipfile.ZipFile(base) as original, zipfile.ZipFile(temporary) as result:
        if result.testzip() is not None:
            raise ValueError('Invalid augmented package')
        expected = (set(original.namelist()) - removed) | {'libhttp_augmented.suprx'}
        if set(result.namelist()) != expected:
            raise ValueError('Unexpected augmented package members')
        changed = [name for name in original.namelist() if name not in removed and
                   original.read(name) != result.read(name)]
        expected_changes = ['eboot.bin', 'tls_fixer.skprx'] if args.release else [
            'eboot.bin', 'sce_sys/param.sfo', 'tls_fixer.skprx']
        if sorted(changed) != expected_changes:
            raise ValueError('Unexpected package replacements: ' + repr(changed))
        if result.read('sce_sys/param.sfo') != sfo.read_bytes():
            raise ValueError('Package metadata differs from the selected profile')
        if result.read('libhttp_augmented.suprx') != module.read_bytes():
            raise ValueError('Augmented module bytes differ')
        if result.getinfo('libhttp_augmented.suprx').external_attr != original.getinfo('lhttp.suprx').external_attr:
            raise ValueError('Augmented module permissions differ from the native module asset')
        report = {'package': str(target), 'self_disarm_required': not args.release,
                  'activation': 'persistent' if args.release else 'one-boot',
                  'installer_backend': 'augmented', 'user_backend_selector': False,
                  'system_test_only': not args.release,
                  'kernel_install_path': 'ur0:tai/tls_fixer.skprx' if args.release else 'ux0:/data/tls_fixer-one-shot/tls_fixer.skprx',
                  'runtime_directory': 'vs0:/data/external/tls_fixer/native' if args.release else 'ux0:/data/tls_fixer-runtime-installer',
                  'kernel_profile': kernel_profile,
                  'http_module_sha256': digest(result.read('libhttp_augmented.suprx')),
                  'kernel_sha256': digest(result.read('tls_fixer.skprx')),
                  'installer_sha256': digest(result.read('eboot.bin')),
                  'removed_legacy_assets': sorted(removed), 'replaced_assets': sorted(changed),
                  'source_files': str(output / 'source-files.json'), 'device_installed': False}
    temporary.replace(target)
    report['package_sha256'] = digest(target.read_bytes())
    (output / 'package.json').write_text(json.dumps(report, indent=2) + '\n')
    print(target)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, required=True)
    parser.add_argument('--http-module', type=Path, required=True)
    parser.add_argument('--release', action='store_true', help='Persistent activation and the full installer menu')
    build(parser.parse_args())
