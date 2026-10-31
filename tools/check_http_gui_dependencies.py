#!/usr/bin/env python3
"""Check the experimental HTTP/GUI classifiers against decrypted firmware."""
import argparse
import ctypes
import json
from pathlib import Path
import struct
import subprocess
import tempfile

from firmware_matrix import Firmware, VERSIONS

ROOT = Path(__file__).resolve().parents[1]
TRANSPORT_LIBRARIES = {0xE8F15CDE, 0xCAF5F2E9, 0x68D6C3FF}


def library_ids(module, export):
    """Include variable-only imports/exports, which function-NID maps omit."""
    begin, end = struct.unpack_from('<II', module.info, 0x24 if export else 0x2C)
    result = set()
    while begin < end:
        size = module.text[begin] if export else struct.unpack_from('<H', module.text, begin)[0]
        if size not in ((0x20,) if export else (0x24, 0x34)) or size > end - begin:
            raise ValueError(f'Invalid library table in {module.path}')
        offset = 16 if export or size == 0x34 else 12
        nid = struct.unpack_from('<I', module.text, begin + offset)[0]
        if nid:
            result.add(nid)
        begin += size
    if begin != end:
        raise ValueError(f'Invalid library table span in {module.path}')
    return result


def verify(firmware_root):
    records, missing = [], []
    with tempfile.TemporaryDirectory(prefix='tls-fixer-gui-') as directory:
        output = Path(directory) / 'classifiers.so'
        subprocess.run(['cc', '-shared', '-fPIC', '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-I' + str(ROOT / 'tls13/include'), str(ROOT / 'tls13/src/path.c'),
                        str(ROOT / 'tls13/src/transport_path.c'), '-o', str(output)], check=True)
        lib = ctypes.CDLL(str(output))
        lib.tls_fixer_http_client_kind.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
        lib.tls_fixer_http_client_kind.restype = ctypes.c_int
        lib.tls_fixer_library_uses_http.argtypes = [ctypes.c_uint32]
        lib.tls_fixer_library_uses_http.restype = ctypes.c_int
        for hardware in ('official', 'testkit', 'devkit'):
            for version in VERSIONS:
                revision = version if hardware == 'official' else version + '0.011'
                path = firmware_root / hardware / revision / 'fs_dec/vs0/sys/external'
                if not path.is_dir():
                    missing.append({'hardware': hardware, 'firmware': version})
                    continue
                modules = {p.stem: Firmware(p) for p in sorted(path.glob('*.elf'))}
                imports = {n: library_ids(m, False) for n, m in modules.items()}
                exports = {n: library_ids(m, True) for n, m in modules.items()}
                direct = {n for n in modules if imports[n] & TRANSPORT_LIBRARIES}
                selected = set(direct)
                while True:
                    dependencies = set().union(*(exports[n] for n in selected))
                    more = {n for n in modules if imports[n] & dependencies} - selected
                    if not more:
                        break
                    selected |= more
                expected = TRANSPORT_LIBRARIES | set().union(*(exports[n] for n in selected))
                for nid in set().union(*imports.values(), *exports.values(), {0, 0xFFFFFFFF}):
                    actual = lib.tls_fixer_library_uses_http(nid)
                    if actual != int(nid in expected):
                        raise ValueError(f'{hardware} {version}: library classifier differs for {nid:#010x}')
                # HTTP is the paired transport, not a consumer to reroute here.
                direct.discard('libhttp')
                selected.discard('libhttp')
                for name in modules:
                    wanted = 1 if name in direct else 2 if name in selected else 0
                    for prefix in ('vs0:sys/external/', 'vs0:/sys/external/'):
                        module_path = (prefix + name + '.suprx').encode()
                        if lib.tls_fixer_http_client_kind(module_path, len(module_path) + 1) != wanted:
                            raise ValueError(f'{hardware} {version}: path classifier differs for {name}')
                records.append({'hardware': hardware, 'firmware': version,
                                'direct': len(direct), 'indirect': len(selected - direct)})
    if not records:
        raise ValueError('No firmware images found')
    return {'evidence': 'Compiled classifiers against static firmware, not device execution',
            'verified': records, 'missing': missing}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('firmware_root', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = verify(args.firmware_root)
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(f"GUI dependency classifiers: {len(result['verified'])} firmware cells passed; "
          f"{len(result['missing'])} unavailable")
