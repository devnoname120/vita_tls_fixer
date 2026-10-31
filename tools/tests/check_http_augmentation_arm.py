#!/usr/bin/env python3
"""Compare augmentation relocations with the actual retail 3.60 ARM loader.

Run with the project's Unicorn environment. No device operations are performed.
Firmware instructions are executed unchanged, with only RAM and the load-context
structures supplied by this harness. This is an independent oracle for compact
relocation decoding and for the emitted expanded records.
"""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2
from unicorn.arm_const import UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC
from unicorn.arm_const import (UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6,
                              UC_ARM_REG_R7, UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10,
                              UC_ARM_REG_R11, UC_ARM_REG_R12, UC_ARM_REG_CPSR)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from augment_libhttp import Module, apply_relocations
from firmware_matrix import Firmware

CONTEXT = 0x83000000
INFO = 0x83001000
STACK = 0x84000000
STOP = 0x85000000
BUFFERS = (0x86000000, 0x86800000)
STREAM = 0x87000000
SAVED = (UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
         UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11)


def native_relocate(firmware, module, bases):
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    pages = set()

    def region(address, data, size=None):
        for page in range(address & ~4095, (address + max(len(data), size or 0) + 4095) & ~4095, 4096):
            if page not in pages:
                uc.mem_map(page, 4096)
                pages.add(page)
        if data:
            uc.mem_write(address, bytes(data))

    def w(address, value):
        uc.mem_write(address, struct.pack('<I', value & 0xffffffff))

    for s in firmware.segments:
        if s[0] == 1:
            region(s[2], firmware.data[s[1]:s[1] + s[4]], s[5])
    for address, size in ((0, 4096), (CONTEXT, 0x2000), (STACK, 0x20000), (STOP, 4096)):
        region(address, bytes(size))
    w(CONTEXT, INFO)
    w(INFO + 108, len(module.segments))
    for i, s in enumerate(module.segments):
        region(BUFFERS[i], s.data, s.memsz)
        w(CONTEXT + 32 + 12 * i, s.base)
        w(CONTEXT + 40 + 12 * i, BUFFERS[i])
        w(INFO + 112 + 20 * i, len(s.data))
        w(INFO + 116 + 20 * i, s.memsz)
        w(INFO + 124 + 20 * i, bases[i])
    done = []

    def finish(machine, address, size, unused):
        done.append(machine.reg_read(UC_ARM_REG_R0))
        machine.emu_stop()

    uc.hook_add(UC_HOOK_CODE, finish, begin=STOP, end=STOP)
    for stream in module.streams:
        region(STREAM, stream)
        uc.reg_write(UC_ARM_REG_SP, STACK + 0x1ff00)
        uc.reg_write(UC_ARM_REG_LR, STOP | 1)
        uc.reg_write(UC_ARM_REG_R0, CONTEXT)
        uc.reg_write(UC_ARM_REG_R1, STREAM)
        uc.reg_write(UC_ARM_REG_R2, len(stream))
        before = len(done)
        uc.emu_start(0x81000ead, STOP + 4, count=5000000)
        assert len(done) == before + 1, ('native loader did not return', hex(uc.reg_read(UC_ARM_REG_PC)))
        assert done[-1] == 0, ('native relocation rejected image', hex(done[-1]))
    return [bytes(uc.mem_read(BUFFERS[i], s.memsz)) for i, s in enumerate(module.segments)]


def lifecycle_cases(firmware, original, module, report):
    """Execute generated wrappers with native relocation and a native-entry oracle."""
    cases = []
    for bases in ([0x81800000, 0x82400000], [0xe0400040, 0x82a00010]):
        relocated = native_relocate(firmware, module, bases)
        baseline = native_relocate(firmware, original, bases)
        # Every original byte after relocation is preserved, except the two
        # lifecycle export pointers and the four explicitly changed info fields.
        allowed = set()
        for off, length in ((original.info_offset + 0x24, 8), (original.info_offset + 0x44, 8)):
            allowed.update(range(off, off + length))
        for nid in (0x935cd196, 0x79f8e492):
            segment, off, _ = original.export_entries()[0, nid]
            assert segment == 0
            allowed.update(range(off, off + 4))
        for i in range(2):
            for off, value in enumerate(baseline[i]):
                if i == 0 and off in allowed:
                    continue
                assert relocated[i][off] == value, ('native byte changed', i, hex(off))
        for native_result in (0, 1, 0xffffffff, 0x8002d013):
            uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
            pages = set()
            for address, data in list(zip(bases, relocated)) + [(STACK, bytes(0x20000)), (STOP, bytes(4096))]:
                for page in range(address & ~4095, (address + len(data) + 4095) & ~4095, 4096):
                    if page not in pages:
                        uc.mem_map(page, 4096)
                        pages.add(page)
                uc.mem_write(address, data)
            calls, returned = [], []

            def original_entry(machine, address, size, unused):
                calls.append((address, machine.reg_read(UC_ARM_REG_R0), machine.reg_read(UC_ARM_REG_R1)))
                machine.reg_write(UC_ARM_REG_R0, native_result)
                for reg in (UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R12):
                    machine.reg_write(reg, 0xa5a5a5a5)
                machine.reg_write(UC_ARM_REG_PC, machine.reg_read(UC_ARM_REG_LR))

            def finish(machine, address, size, unused):
                returned.append(machine.reg_read(UC_ARM_REG_R0))
                machine.emu_stop()

            for entry in report['lifecycle'].values():
                address = bases[0] + (entry['original'] & ~1)
                uc.hook_add(UC_HOOK_CODE, original_entry, begin=address, end=address)
            uc.hook_add(UC_HOOK_CODE, finish, begin=STOP, end=STOP)
            for n, kind in enumerate(('start', 'stop', 'start')):
                entry = report['lifecycle'][kind]
                sp = STACK + 0x1ff00
                uc.reg_write(UC_ARM_REG_SP, sp)
                uc.reg_write(UC_ARM_REG_LR, STOP | 1)
                uc.reg_write(UC_ARM_REG_R0, 16 + n)
                uc.reg_write(UC_ARM_REG_R1, 0x81234500 + n)
                for i, reg in enumerate(SAVED):
                    uc.reg_write(reg, 0x44000000 + i)
                uc.emu_start(bases[0] + entry['wrapper'], STOP + 4, count=1000)
                assert len(returned) == n + 1 and returned[-1] == native_result
                assert len(calls) == n + 1 and calls[-1] == (bases[0] + (entry['original'] & ~1), 16+n, 0x81234500+n)
                assert uc.reg_read(UC_ARM_REG_SP) == sp
                assert [uc.reg_read(r) for r in SAVED] == [0x44000000+i for i in range(len(SAVED))]
            state = struct.unpack('<8I', uc.mem_read(bases[1] + report['probe_state_offset'], 32))
            assert state[4:] == (2, 1, native_result, native_result)
            cases.append({'bases': bases, 'native_return': native_result, 'calls': len(calls),
                          'preserved_original_image': True, 'state': list(state)})
    return cases


def embedded_branches(firmware, module, report):
    cases = []
    for bases in ([0x81800000, 0x82400000], [0xe0400040, 0xe00a0010]):
        relocated = native_relocate(firmware, module, bases)
        for kind, rows in (('transport', report['patched_calls']), ('import', report['imports']['aliases'])):
            for row in rows:
                uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
                pages = set()
                for address, data in list(zip(bases, relocated)) + [(STACK, bytes(0x4000))]:
                    for page in range(address & ~4095, (address + len(data) + 4095) & ~4095, 4096):
                        if page not in pages:
                            uc.mem_map(page, 4096); pages.add(page)
                    uc.mem_write(address, data)
                site = row['site'] if kind == 'transport' else row['from']
                target = (row['wrapper'] & ~1) if kind == 'transport' else row['to']
                done = []
                uc.reg_write(UC_ARM_REG_SP, STACK + 0x3000)
                uc.reg_write(UC_ARM_REG_LR, STOP | 1)
                for i, reg in enumerate((UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)):
                    uc.reg_write(reg, 0x12340000 + i)

                def reached(machine, address, size, unused):
                    assert bool(machine.reg_read(UC_ARM_REG_CPSR) & 0x20) == (kind == 'transport')
                    assert machine.reg_read(UC_ARM_REG_SP) == STACK + 0x3000
                    assert machine.reg_read(UC_ARM_REG_LR) == (bases[0] + site + 5 if kind == 'transport' else STOP | 1)
                    assert [machine.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)] == [0x12340000+i for i in range(4)]
                    done.append(True); machine.emu_stop()

                uc.hook_add(UC_HOOK_CODE, reached, begin=bases[0] + target, end=bases[0] + target)
                uc.emu_start((bases[0] + site) | (1 if kind == 'transport' else 0), 0, count=10)
                assert done, (kind, row, hex(uc.reg_read(UC_ARM_REG_PC)))
                cases.append({'kind': kind, 'bases': bases, 'site': site, 'target': target})
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--firmware', required=True, type=Path)
    parser.add_argument('--modules', required=True, nargs='+', type=Path)
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--lifecycle-report', type=Path)
    parser.add_argument('--embedded-report', type=Path)
    args = parser.parse_args()
    firmware = Firmware(args.firmware)
    # Exact original instructions used during IDA analysis, never a guessed offset
    # from another firmware revision.
    assert firmware.name == 'SceKernelModulemgr'
    assert hashlib.sha256(firmware.text[0xd34:0x1518]).hexdigest() == 'ddf336ccf14504391c8393ff2710da5b7d60c3731af6e1862358e59ccd3da54a'
    rows = []
    for path in args.modules:
        module = Module.read(path)
        relocations = module.relocations()
        for bases in ([0x81800000, 0x82400000], [0xe0400040, 0x82a00010], [0x82100000, 0x82000000]):
            native = native_relocate(firmware, module, bases)
            host = [bytearray(s.data) + bytes(s.memsz - len(s.data)) for s in module.segments]
            apply_relocations(host, relocations, bases)
            for i in range(2):
                if host[i] != native[i]:
                    at = next(j for j in range(len(host[i])) if host[i][j] != native[i][j])
                    raise AssertionError((str(path), bases, i, hex(at), host[i][at:at+8], native[i][at:at+8]))
            rows.append({'module': str(path), 'bases': bases, 'writes': len(relocations), 'match': True})
    report = {'firmware_sha256': hashlib.sha256(args.firmware.read_bytes()).hexdigest(),
              'cases': rows, 'writes_checked': sum(r['writes'] for r in rows)}
    if args.lifecycle_report:
        report['lifecycle'] = lifecycle_cases(firmware, Module.read(args.modules[0]),
                                             Module.read(args.modules[-1]),
                                             json.loads(args.lifecycle_report.read_text()))
    if args.embedded_report:
        report['branches'] = embedded_branches(firmware, Module.read(args.modules[-1]),
                                               json.loads(args.embedded_report.read_text()))
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(f"{len(rows)} full-image native ARM comparisons passed; {report['writes_checked']} relocation writes checked")


if __name__ == '__main__':
    main()
