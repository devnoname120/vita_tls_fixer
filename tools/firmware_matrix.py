#!/usr/bin/env python3
"""Exercise compiled compatibility guards against the external firmware corpus."""

import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import zlib

ROOT = Path(__file__).resolve().parents[1]
VERSIONS = ('3.60', '3.61', '3.63', '3.65', '3.67', '3.68', '3.69', '3.70', '3.71', '3.72', '3.73', '3.74')


class Firmware:
    def __init__(self, path, data=None):
        self.path = Path(path)
        self.data = self.path.read_bytes() if data is None else data
        if self.data[:7] != b'\x7fELF\x01\x01\x01':
            raise ValueError('Expected decrypted ELF: ' + str(path))
        offset = struct.unpack_from('<I', self.data, 28)[0]
        size, count = struct.unpack_from('<HH', self.data, 42)
        self.segments = [struct.unpack_from('<8I', self.data, offset + i * size) for i in range(count)]
        entry = struct.unpack_from('<I', self.data, 24)[0]
        self.metadata_segment, self.metadata_offset = entry >> 30, entry & 0x3fffffff
        self.info = self.segment(self.metadata_segment)[self.metadata_offset:self.metadata_offset + 0x5c]
        if len(self.info) != 0x5c:
            raise ValueError('Truncated module metadata')
        self.name = self.info[4:31].split(b'\0', 1)[0].decode('ascii')
        self.nid = struct.unpack_from('<I', self.info, 0x34)[0]
        self.text = self.segment(0)
        self.exports = self.libraries(True)
        self.imports = self.libraries(False)

    def segment(self, index):
        segment = self.segments[index]
        return self.data[segment[1]:segment[1] + segment[4]]

    def read(self, address, size):
        for kind, offset, base, _, length, *_ in self.segments:
            if kind == 1 and base <= address and address + size <= base + length:
                return self.data[offset + address - base:offset + address - base + size]
        raise ValueError('Unmapped module address')

    def libraries(self, export):
        begin, end = struct.unpack_from('<II', self.info, 0x24 if export else 0x2c)
        records = {}
        while begin < end:
            size = self.text[begin] if export else struct.unpack_from('<H', self.text, begin)[0]
            count = struct.unpack_from('<H', self.text, begin + 6)[0]
            if export and size == 0x20:
                library, _, nids, entries = struct.unpack_from('<4I', self.text, begin + 16)
            elif not export and size == 0x34:
                library = struct.unpack_from('<I', self.text, begin + 16)[0]
                nids, entries = struct.unpack_from('<2I', self.text, begin + 28)
            elif not export and size == 0x24:
                library, _, nids, entries = struct.unpack_from('<4I', self.text, begin + 12)
            else:
                raise ValueError(f'Unknown library record size {size} in {self.path}, export={export}')
            for i in range(count):
                nid = struct.unpack('<I', self.read(nids + i * 4, 4))[0]
                address = struct.unpack('<I', self.read(entries + i * 4, 4))[0]
                records[library, nid] = address
            begin += size
        if begin != end:
            raise ValueError('Library table span mismatch')
        return records


def kernel_module(kd, name):
    for candidate in (kd / (name + '.elf'), kd / 'bootimage' / (name + '.skprx.elf')):
        if candidate.is_file():
            return Firmware(candidate)
    carrier = kd / 'bootimage.elf'
    if not carrier.is_file():
        return None
    boot = Firmware(carrier)
    base = boot.segments[0][2]
    table = struct.unpack_from('<I', boot.text, 0xcc)[0] - base
    if not 0 <= table <= len(boot.text) - 8:
        raise ValueError('Bootimage table bounds')
    count = struct.unpack_from('<I', boot.text, table)[0]
    if count >= 256 or table + 8 + count * 12 > len(boot.text):
        raise ValueError('Bootimage record bounds')
    for i in range(count):
        name_va, payload_va, size = struct.unpack_from('<3I', boot.text, table + 8 + i * 12)
        name_offset, payload_offset = name_va - base, payload_va - base
        if not 0 <= name_offset < len(boot.text) or not 0 <= payload_offset <= len(boot.text) - size:
            raise ValueError('Embedded module bounds')
        filename = boot.text[name_offset:boot.text.index(b'\0', name_offset)].decode()
        if filename.rsplit('/', 1)[-1] == name + '.skprx':
            return Firmware(carrier, boot.text[payload_offset:payload_offset + size])
    return None


def bundled_module(path):
    """Read our plaintext compressed SELF, without accepting encrypted firmware."""
    data = path.read_bytes()
    if len(data) < 0x80 or data[:4] != b'SCE\0':
        raise ValueError('Expected bundled plaintext SELF: ' + str(path))
    elf_offset, phdr_offset = struct.unpack_from('<QQ', data, 0x40)
    records_offset = struct.unpack_from('<Q', data, 0x58)[0]
    header = data[elf_offset:elf_offset + 52]
    if len(header) != 52 or header[:7] != b'\x7fELF\x01\x01\x01':
        raise ValueError('Invalid bundled ELF header')
    phdr_size, count = struct.unpack_from('<HH', header, 42)
    if phdr_size != 32 or count > 16 or phdr_offset + count * 32 > len(data) or records_offset + count * 32 > len(data):
        raise ValueError('Bundled segment table bounds')
    program_headers = data[phdr_offset:phdr_offset + count * 32]
    segments = [struct.unpack_from('<8I', program_headers, i * 32) for i in range(count)]
    size = max(segment[1] + segment[4] for segment in segments)
    if size > 16 * 1024 * 1024:
        raise ValueError('Bundled ELF size limit')
    elf = bytearray(size)
    elf[:52] = header
    for i, segment in enumerate(segments):
        offset, length, compression, encryption = struct.unpack_from('<4Q', data, records_offset + i * 32)
        if encryption != 2 or compression not in (1, 2) or offset + length > len(data):
            raise ValueError('Bundled segment must be bounded plaintext')
        payload = data[offset:offset + length]
        if compression == 2:
            payload = zlib.decompress(payload)
        if len(payload) != segment[4]:
            raise ValueError('Bundled decompressed segment size')
        elf[segment[1]:segment[1] + segment[4]] = payload
    phoff = struct.unpack_from('<I', header, 28)[0]
    elf[phoff:phoff + len(program_headers)] = program_headers
    return Firmware(path, bytes(elf))


WRAPPER = r'''
#include <kernel_mock.h>
#include <psp2/kernel/sysmem.h>
#include "hook_guard.h"
#include "webkit_callback.h"
static SceKernelModuleInfo fixture;
static struct { uint32_t vtable; unsigned char rest[0x4e0-4]; } userdata;
int ksceKernelGetModuleInfo(SceUID pid, SceUID id, SceKernelModuleInfo *out) {
    (void)pid; (void)id; *out=fixture; return 0;
}
int sceKernelGetModuleInfo(SceUID id, SceKernelModuleInfo *out) {
    (void)id; *out=fixture; return 0;
}
SceUID sceKernelGetModuleIdByAddr(void *address) { (void)address; return 11; }
int sceKernelGetMemBlockInfoByAddr(void *address, SceKernelMemBlockInfo *out) {
    if(address!=&userdata) return -1;
    out->mappedBase=&userdata; out->mappedSize=sizeof(userdata);
    out->access=SCE_KERNEL_MEMORY_ACCESS_R|SCE_KERNEL_MEMORY_ACCESS_W; return 0;
}
void tls_fixer_trace(const char *format, ...) { (void)format; }
int check_kernel(const unsigned char *text,size_t size) {
    memset(&fixture,0,sizeof(fixture)); fixture.modid=11; fixture.modattr=7;
    fixture.modver[0]=fixture.modver[1]=1; strcpy(fixture.module_name,"SceKernelModulemgr");
    fixture.start_entry=(void *)((uintptr_t)text+0x378d);
    fixture.segments[0].size=sizeof(SceKernelSegmentInfo); fixture.segments[0].perms=5;
    fixture.segments[0].vaddr=(void *)text; fixture.segments[0].filesz=fixture.segments[0].memsz=size;
    return tls_fixer_validate_loader_hook(11);
}
int webkit_offsets(const unsigned char *text,size_t size,size_t data_file,size_t data_memory,size_t *callback,size_t *vtable) {
    const TlsFixerWebKitProfile *p=tls_fixer_select_webkit_profile(text,size,size,data_file,data_memory);
    if(!p) return 0; *callback=p->callback_offset; *vtable=p->vtable_offset; return 1;
}
int check_webkit(const unsigned char *text,size_t size,size_t data_file,size_t data_memory,size_t callback,size_t vtable) {
    memset(&fixture,0,sizeof(fixture)); strcpy(fixture.module_name,"SceWebKit");
    fixture.segments[0].vaddr=(void *)text; fixture.segments[0].filesz=fixture.segments[0].memsz=size;
    fixture.segments[1].vaddr=(void *)text; fixture.segments[1].filesz=data_file; fixture.segments[1].memsz=data_memory;
    userdata.vtable=(uint32_t)((uintptr_t)text+vtable);
    return tls_fixer_webkit_is_default_ctx_callback((void *)((uintptr_t)text+callback+1),&userdata);
}
'''


def compiled_guard(directory, post_start):
    source = directory / ('guard' + str(post_start) + '.c')
    source.write_text(WRAPPER)
    output = directory / ('guard' + str(post_start) + '.so')
    include = ['tls13/include', 'tls13/tests/kernel/include', 'tls13/tests/transport/include', 'kernel', 'tls13/browser']
    subprocess.run(['cc', '-shared', '-fPIC', '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-Wno-misleading-indentation', '-DTLS_FIXER_ENABLE_DEBUG_LOG=0',
                    '-DTLS_FIXER_BROWSER_POST_START=' + str(post_start),
                    *['-I' + str(ROOT / path) for path in include], str(source),
                    str(ROOT / 'kernel/hook_guard.c'), str(ROOT / 'tls13/browser/webkit_callback.c'),
                    '-o', str(output)], check=True)
    dll = ctypes.CDLL(str(output))
    dll.check_kernel.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    dll.webkit_offsets.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_size_t, ctypes.c_size_t,
                                  ctypes.POINTER(ctypes.c_size_t), ctypes.POINTER(ctypes.c_size_t)]
    dll.check_webkit.argtypes = [ctypes.c_void_p, *[ctypes.c_size_t] * 5]
    return dll


def callback_import(module, callback):
    h1, h2 = struct.unpack_from('<HH', module.text, callback + 6)
    sign = (h1 >> 10) & 1
    first, second = (~((h2 >> 13) ^ sign)) & 1, (~((h2 >> 11) ^ sign)) & 1
    value = (sign << 24) | (first << 23) | (second << 22) | ((h1 & 1023) << 12) | ((h2 & 2047) << 1)
    displacement = value - (1 << 25) if sign else value
    target = ((module.segments[0][2] + callback + 10) & ~3) + displacement
    return [key for key, address in module.imports.items() if address == target]


def linked_imports(path):
    data = path.read_bytes()
    offset = struct.unpack_from('<I', data, 32)[0]
    size, count, strings_index = struct.unpack_from('<HHH', data, 46)
    sections = [struct.unpack_from('<10I', data, offset + i * size) for i in range(count)]
    strings = sections[strings_index]
    names = data[strings[4]:strings[4] + strings[5]]
    result = []
    for section in sections:
        name = names[section[0]:].split(b'\0', 1)[0].decode()
        if name.startswith('.vitalink.fstubs.'):
            for position in range(section[4], section[4] + section[5], 16):
                _, library, function, _ = struct.unpack_from('<4I', data, position)
                if name.rsplit('.', 1)[-1] not in ('taihen', 'taihenForKernel', 'taihenModuleUtils'):
                    result.append((library, function))
    if not result:
        raise ValueError('No firmware imports in ' + str(path))
    return result


def platform_exports(tree, replaced_names):
    exports = {}
    for name in ('modulemgr', 'sysmem', 'threadmgr', 'iofilemgr', 'lowio', 'sysroot', 'sysclib',
                 'ctrl', 'display', 'power', 'vshbridge', 'sysmodule', 'processmgr', 'regmgr', 'appmgr', 'rtc'):
        module = kernel_module(tree / 'os0/kd', name)
        if module is not None:
            exports.update(module.exports)
    for directory in (tree / 'os0/us', tree / 'vs0/sys/external'):
        for path in directory.glob('*.elf'):
            module = Firmware(path)
            if module.name not in replaced_names:
                exports.update(module.exports)
    filtering = Firmware(tree / 'vs0/data/external/webcore/jx_web_filtering.elf')
    exports.update(filtering.exports)
    return exports


def run(args):
    libc = ctypes.CDLL(None)
    libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
    libc.mmap.restype = ctypes.c_void_p
    libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    # Like the production callback, the test vtable must fit an ARM32 pointer.
    memory = libc.mmap(ctypes.c_void_p(0x34000000), 0xb00000, 3, 0x22 | 0x100000, -1, 0)
    if memory is None or memory == ctypes.c_void_p(-1).value or memory + 0xb00000 > 0xffffffff:
        raise RuntimeError('Matrix requires Linux MAP_FIXED_NOREPLACE at a free ARM32 address')
    records, unavailable = [], []
    builds = {str(path): linked_imports(path) for path in args.plugin_elf}
    replacements = [bundled_module(ROOT / 'misc' / path) for path in (
        'lhttp.suprx', 'lssl.suprx', 'compat.suprx')]
    commerce = bundled_module(ROOT / 'misc/comm2.suprx')
    dns_elf = ROOT / 'build/old_dns_fix/tls_fixer_dns'
    dns_imports = linked_imports(dns_elf) if builds else []
    try:
        with tempfile.TemporaryDirectory(prefix='tls-fixer-firmware-') as temporary:
            guards = [compiled_guard(Path(temporary), mode) for mode in (0, 1)]
            for hardware in ('official', 'testkit', 'devkit'):
                for version in VERSIONS:
                    folder = version if hardware == 'official' else version + '0.011'
                    tree = args.firmware_root / hardware / folder / 'fs_dec'
                    if not tree.is_dir():
                        unavailable.append({'hardware': hardware, 'firmware': version, 'reason': 'external image absent'})
                        continue
                    manager = kernel_module(tree / 'os0/kd', 'modulemgr')
                    webkit = Firmware(tree / 'vs0/data/external/webcore/SceWebKitModule.elf')
                    kernel_memory = ctypes.create_string_buffer(manager.text)
                    for dll in guards:
                        assert dll.check_kernel(kernel_memory, len(manager.text)) == 0, (hardware, version, 'kernel guard')
                        altered = bytearray(manager.text); altered[manager.metadata_offset + 0x34] ^= 1
                        assert dll.check_kernel(ctypes.create_string_buffer(bytes(altered)), len(altered)) < 0
                        altered = bytearray(manager.text); altered[0x21ec] ^= 1
                        assert dll.check_kernel(ctypes.create_string_buffer(bytes(altered)), len(altered)) < 0
                    ctypes.memmove(memory, webkit.text, len(webkit.text))
                    callback, vtable = ctypes.c_size_t(), ctypes.c_size_t()
                    data_file, data_memory = webkit.segments[1][4:6]
                    assert guards[0].webkit_offsets(memory, len(webkit.text), data_file, data_memory,
                                                    ctypes.byref(callback), ctypes.byref(vtable)), (hardware, version, 'WebKit identity')
                    assert guards[0].check_webkit(memory, len(webkit.text), data_file, data_memory, callback.value, vtable.value)
                    for offset in [callback.value, webkit.metadata_offset + 0x34]:
                        old = ctypes.c_ubyte.from_address(memory + offset).value
                        ctypes.c_ubyte.from_address(memory + offset).value = old ^ 1
                        assert not guards[0].check_webkit(memory, len(webkit.text), data_file, data_memory, callback.value, vtable.value)
                        ctypes.c_ubyte.from_address(memory + offset).value = old
                    assert not guards[0].check_webkit(memory, len(webkit.text), data_file + 1, data_memory, callback.value, vtable.value)
                    assert not guards[0].check_webkit(memory, len(webkit.text), data_file, data_memory, callback.value, vtable.value + 4)
                    assert callback_import(webkit, callback.value) == [(0x81405f79, 0x7dab2e59)], (hardware, version, 'callback role')
                    record = {'hardware': hardware, 'firmware': version, 'device_tested': False,
                              'kernel_guard': True, 'post_start_guard': True, 'webkit_callback_guard': True,
                              'callback_import': '81405f79:7dab2e59', 'callback_offset': callback.value,
                              'vtable_offset': vtable.value, 'modules': {}}
                    family = 0 if manager.nid in (0x726c6635, 0xa5a80af8) else 1
                    library = (0xc445fa63, 0x92c9ffc2)[family]
                    functions = ((0xd269f915, 0x97cf7b4e, 0x5972e2cc, 0x99890202),
                                 (0xdaa90093, 0xb72c75a4, 0xfca9fdb1, 0xf1de6949))[family]
                    for function in functions:
                        assert (library, function) in manager.exports, (hardware, version, 'native export binding')
                    record['native_module_api_family'] = family
                    record['native_exports_verified'] = [f'{library:08x}:{function:08x}' for function in functions]
                    if builds:
                        bundled = replacements + ([commerce] if version == '3.60' else [])
                        exports = platform_exports(tree, {module.name for module in bundled})
                        # Redirected transport dependencies resolve against the VPK's paired modules.
                        for module in bundled:
                            exports.update(module.exports)
                        record['imports_verified'] = {}
                        for label, imports in builds.items():
                            missing = [f'{library:08x}:{function:08x}' for library, function in imports
                                       if (library, function) not in exports]
                            assert not missing, (hardware, version, label, 'missing firmware imports', missing)
                            record['imports_verified'][label] = len(imports)
                        record['replacement_dependencies_verified'] = {}
                        for module in bundled:
                            missing = [f'{library:08x}:{function:08x}' for library, function in module.imports
                                       if (library, function) not in exports]
                            assert not missing, (hardware, version, module.name, 'replacement imports', missing)
                            record['replacement_dependencies_verified'][module.name] = len(module.imports)
                        if version == '3.60':
                            missing = [f'{library:08x}:{function:08x}' for library, function in dns_imports
                                       if (library, function) not in exports]
                            assert not missing, (hardware, version, 'DNS helper imports', missing)
                            shell = Firmware(tree / 'vs0/vsh/shell/shell.elf')
                            assert (0xe8f15cde, 0xaeb3307e) in shell.imports, (hardware, version, 'DNS helper hook')
                            record['dns_helper_imports_verified'] = len(dns_imports)
                            record['dns_helper_hook_import'] = 'e8f15cde:aeb3307e'
                    for kind, module in [('modulemgr', manager), ('webkit', webkit)]:
                        record['modules'][kind] = {'name': module.name, 'nid': f'{module.nid:08x}',
                                                  'sha256': hashlib.sha256(module.data).hexdigest(),
                                                  'text_filesz': module.segments[0][4], 'data_filesz': module.segments[1][4],
                                                  'data_memsz': module.segments[1][5]}
                    records.append(record)
    finally:
        libc.munmap(memory, 0xb00000)
    result = {'schema_version': 1, 'evidence': 'compiled guards plus decrypted firmware; not hardware execution',
              'linked_artifacts': {str(path): {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                  'firmware_imports': len(builds[str(path)])} for path in args.plugin_elf},
              'bundled_modules': {str(module.path.relative_to(ROOT)): {
                  'name': module.name, 'nid': f'{module.nid:08x}',
                  'self_sha256': hashlib.sha256(module.path.read_bytes()).hexdigest()
              } for module in replacements + [commerce]},
              'verified': records, 'unavailable': unavailable}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print('Compiled kernel/WebKit guards passed:', len(records), 'firmware/hardware cells; unavailable:', len(unavailable))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--firmware-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, default=ROOT / 'build/firmware-support/matrix.json')
    parser.add_argument('--plugin-elf', type=Path, action='append', default=[])
    run(parser.parse_args())


if __name__ == '__main__':
    main()
