#!/usr/bin/env python3
"""Execute Sony's constructor error exits and the compiled profile wrappers.

Use the project's Unicorn/pyelftools environment. This is an offline test: the
actual native connection/request constructors, native settings copy, native
allocator dispatch and augmented metadata code execute as ARM instructions.
Only OS calls, string primitives, header-copy and allocator backends are mocked.
A post-copy semaphore/allocation failure must preserve Sony's return value,
release native allocations and forget the failed object's profile marker.
"""
from pathlib import Path
import argparse
import hashlib
import json
import struct
import sys
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_INVALID
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC
from elftools.elf.elffile import ELFFile
REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'tools'))
from augment_libhttp import Module, apply_relocations

class ConstructorFailureTest:

    def __init__(self, kind, allocator, module, merge, elf, velf):
        self.kind = kind
        self.allocator = allocator
        self.u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        self.events = []
        self.meta = {}
        self.native = {}
        self.copied = False
        self.failed = False
        self.dest = None
        self.next_meta = 0x88000000
        self.next_native = 0x87000000
        self.meta_at_object_free = None
        self.bases = [0x81000000, 0x82000000]
        self.payload = Module.read(velf)
        self.offsets = json.loads(merge.read_text())['payload_offsets']
        with elf.open('rb') as f:
            syms = ELFFile(f).get_section_by_name('.symtab')
            self.syms = {s.name: int(s['st_value']) for s in syms.iter_symbols() if s.name}
        m = Module.read(module)
        b = [bytearray(s.data) + bytes(s.memsz - len(s.data)) for s in m.segments]
        apply_relocations(b, m.relocations(), self.bases)
        for address, data in list(zip(self.bases, b)) + [(0, bytes(0x20000)), (0x84000000, bytes(0x10000)), (0x85000000, bytes(0x4000)), (0x86000000, bytes(0x10000)), (0x87000000, bytes(0x40000)), (0x88000000, bytes(0x10000)), (0x89000000, bytes(4096))]:
            self.u.mem_map(address, len(data) + 4095 & ~4095)
            self.u.mem_write(address, bytes(data))
        self.done = False
        self.hooks = {}
        self.hooks[self.sym('__wrap_malloc') & ~1] = self.malloc
        self.hooks[self.sym('__wrap_free') & ~1] = self.free_meta
        for n in ['sceKernelLockMutex', 'sceKernelUnlockMutex']:
            self.hooks[self.sym(n) & ~1] = lambda: 0
        for off in [0xc260, 0xc27c, 0x18370, 0x183b0, 0x18570, 0x133fc, 0x637e]:
            self.hooks[0x81000000 + off] = lambda: 0
        self.hooks[0x81018380] = lambda: 1
        self.hooks[0x81012718] = self.scheme
        self.hooks[0x8100c492] = self.alloc_native
        self.hooks[0x810183a0] = self.semaphore
        self.hooks[0x81018510] = self.strnlen
        self.hooks[0x81018540] = self.copy_bytes
        self.hooks[0x810183d0] = self.copy_bytes
        self.hooks[0x81018440] = self.memset
        self.hooks[0x810122f2] = self.copy_path
        self.hooks[0x810063aa] = self.copy_headers
        self.hooks[0x85000000] = self.free_native
        self.hooks[0x8100c47c] = self.free_native
        self.u.hook_add(UC_HOOK_CODE, self.code)
        self.u.hook_add(UC_HOOK_MEM_INVALID, self.invalid)
        self.w(self.sym('g_gate'), 0)
        self.call(self.sym('tls_fixer_embedded_profile_init'), [])
        self.source = 0x86001000
        self.settings = self.source + (100 if kind == 'request' else 0)
        self.w(self.settings + 180, {'native': 0x8100c47d, 'default': 0, 'custom': 0x85000001}[allocator])
        self.w(self.settings + 100, 1500)
        self.u.mem_write(0x86002000, b'example.test\x00')
        self.u.mem_write(0x86002100, b'https\x00')
        self.u.mem_write(0x86002200, b'/\x00')
        self.call(self.sym('tls_fixer_hello_policy_set'), [self.sym('g_policy'), self.settings, 1])

    def sym(self, n):
        s, o = self.payload.locate(self.syms[n])
        return self.bases[s] + self.offsets[s] + o

    def r(self, i):
        return self.u.reg_read([UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3][i])

    def w(self, a, v):
        self.u.mem_write(a, struct.pack('<I', v & 0xffffffff))

    def invalid(self, u, access, address, size, value, ctx):
        raise RuntimeError(('invalid', hex(u.reg_read(UC_ARM_REG_PC)), hex(address), access, size))

    def code(self, u, address, size, ctx):
        if address == 0x89000000:
            self.done = True
            u.emu_stop()
            return
        if address == 0x8100c4c0:
            self.free_caller = u.reg_read(UC_ARM_REG_LR)
        if address == 0x81011280:
            self.copied = True
            self.dest = self.r(1)
            self.events.append(['copy', hex(self.r(0)), hex(self.dest)])
        if address == 0x810113b8:
            self.events.append(['destroy', hex(self.r(0))])
        if address == 0x8100b990:
            raise AssertionError('failed constructor must not register a handle')
        cb = self.hooks.get(address)
        if cb is not None:
            result = cb()
            u.reg_write(UC_ARM_REG_R0, (result or 0) & 0xffffffff)
            u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))

    def malloc(self):
        n = self.r(0)
        p = self.next_meta
        self.next_meta += n + 15 & ~15
        self.meta[p] = n
        return p

    def free_meta(self):
        p = self.r(0)
        if p:
            assert self.meta.pop(p, None) is not None
        return 0

    def alloc_native(self):
        n = self.r(1)
        if self.kind == 'request' and self.copied and (n == 1500):
            self.failed = True
            self.events.append(['allocation_failure', n])
            return 0
        p = self.next_native
        self.next_native += 0x1000
        self.native[p] = n
        self.u.mem_write(p, bytes(n))
        return p

    def free_native(self):
        p = self.r(0)
        if self.dest is not None and p == self.dest - (100 if self.kind == 'connection' else 76):
            self.meta_at_object_free = len(self.meta)
        if p:
            assert self.native.pop(p, None) is not None, hex(p)
        self.events.append(['free', hex(p), 'caller=' + hex(self.free_caller)])
        return 0x55aa1234

    def scheme(self):
        self.w(self.r(1), 1)
        return 0

    def semaphore(self):
        self.failed = True
        self.events.append(['semaphore_failure'])
        return 0x80020001

    def strnlen(self):
        p, n = (self.r(0), self.r(1))
        return len(bytes(self.u.mem_read(p, n)).split(b'\x00', 1)[0])

    def copy_bytes(self):
        dst, src, n = (self.r(0), self.r(1), self.r(2))
        if n:
            self.u.mem_write(dst, bytes(self.u.mem_read(src, n)))
        return dst

    def memset(self):
        p, v, n = (self.r(0), self.r(1), self.r(2))
        self.u.mem_write(p, bytes([v & 255]) * n)
        return p

    def copy_path(self):
        dst, src, n = (self.r(0), self.r(1), self.r(2))
        b = bytes(self.u.mem_read(src, n))
        self.u.mem_write(dst, b)
        return 0

    def copy_headers(self):
        self.w(self.r(1), 0)
        return 0

    def call(self, fn, args):
        self.done = False
        sp = 0x8400f000
        for i, reg in enumerate([UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3]):
            self.u.reg_write(reg, args[i] if i < len(args) else 0)
        for i, v in enumerate(args[4:]):
            self.w(sp + i * 4, v)
        self.u.reg_write(UC_ARM_REG_SP, sp)
        self.u.reg_write(UC_ARM_REG_LR, 0x89000001)
        self.u.emu_start(fn | 1, 0, count=200000)
        assert self.done, ('did not return', hex(self.u.reg_read(UC_ARM_REG_PC)))
        return self.u.reg_read(UC_ARM_REG_R0)

    def run(self):
        if self.kind == 'connection':
            result = self.call(0x81002435, [self.source, 0x86002000, 0x86002100, 0, 0, 443, 0, 0, 0])
            expected = 0x80020001
        else:
            result = self.call(0x8100f147, [self.source, 0, 0x86002200, 0, 0, 0, 0, 0, 0, 0])
            expected = 0x80431022
        assert result == expected, (hex(result), hex(expected))
        assert self.copied and self.failed and (not self.native), (self.events, self.native)
        selected = self.call(self.sym('tls_fixer_hello_policy_get'), [self.sym('g_policy'), self.dest])
        source_profile = self.call(self.sym('tls_fixer_hello_policy_get'), [self.sym('g_policy'), self.settings])
        assert source_profile == 1
        assert not any((e[0] == 'destroy' for e in self.events)), 'normal destructor must be bypassed in this regression'
        data = {'kind': self.kind, 'allocator': self.allocator, 'source_profile_preserved': source_profile == 1, 'native_result': hex(result), 'native_allocations_released': not self.native, 'profile_after_failed_constructor': selected, 'metadata_allocations_remaining': len(self.meta), 'metadata_at_object_free': self.meta_at_object_free, 'events': self.events}
        self.call(self.sym('tls_fixer_hello_policy_clear'), [self.sym('g_policy')])
        assert not self.meta
        return data

def main():
    p = argparse.ArgumentParser(description=__doc__)
    for flag in ['module', 'merge', 'payload-elf', 'payload-velf', 'output']:
        p.add_argument('--' + flag, type=Path, required=True)
    p.add_argument('--expect-stale', action='store_true', help='Verify the preserved pre-fix regression control')
    a = p.parse_args()
    merge = json.loads(a.merge.read_text())
    assert hashlib.sha256(a.module.read_bytes()).hexdigest() == merge['sha256'], 'module/report mismatch'
    assert hashlib.sha256(a.payload_velf.read_bytes()).hexdigest() in merge['inputs'].values(), 'payload/report mismatch'
    assert '42bc7e34077964ac7edc4365abad8af9bf41793a34d2c7efd631976f7d2739c1' in merge['inputs'].values(), 'unrecognized native module'
    rows = [ConstructorFailureTest(kind, allocator, a.module, a.merge, a.payload_elf, a.payload_velf).run() for kind in ['connection', 'request'] for allocator in ['native', 'default', 'custom']]
    expected_profile = 1 if a.expect_stale else 0
    expected_allocations = 2 if a.expect_stale else 1
    passed = all((row['profile_after_failed_constructor'] == expected_profile and row['metadata_allocations_remaining'] == expected_allocations and (row['metadata_at_object_free'] == expected_allocations) for row in rows))
    result = {'passed': passed, 'regression_control': a.expect_stale, 'module_sha256': merge['sha256'], 'cases': rows}
    a.output.write_text(json.dumps(result, indent=2) + '\n')
    print(f"{len(rows)} native constructor error-exit cases: {('PASS' if passed else 'FAIL')}")
    if not passed:
        raise SystemExit(1)
if __name__ == '__main__':
    main()
