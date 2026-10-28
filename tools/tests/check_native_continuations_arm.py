#!/usr/bin/env python3
"""Compare compiled fallback continuations against the original Sony bodies.

Requires Unicorn 2.x, pyelftools, a linked continuation ELF, and the bundled
plaintext libhttp SELF. SSL imports are mocked equally in both executions.
"""
import argparse
import io
from pathlib import Path
import struct
import sys

from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
    UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
    UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
    UC_ARM_REG_R12, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_CPSR)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from firmware_matrix import bundled_module

CONNECTION, STACK, STOP, ERRNO = 0x84000000, 0x84100000, 0x84200000, 0x84001000
SAVED = (UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
         UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11)


def run(text, elf_bytes, base, kind, fixed, ssl_result, io_result, fields):
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    pages = set()

    def map_bytes(address, data, size=None):
        extent = max(len(data), size or 0)
        for page in range(address & ~4095, (address + extent + 4095) & ~4095, 4096):
            if page not in pages:
                uc.mem_map(page, 4096)
                pages.add(page)
        if data:
            uc.mem_write(address, data)

    map_bytes(base, text)
    elf = ELFFile(io.BytesIO(elf_bytes))
    for segment in elf.iter_segments():
        if segment['p_type'] == 'PT_LOAD':
            map_bytes(segment['p_vaddr'], segment.data(), segment['p_memsz'])
    symbols = {symbol.name: symbol['st_value'] for symbol in
               elf.get_section_by_name('.symtab').iter_symbols()}
    targets = (base + 0x18910, (base + 0x860a) | 1,
               base + 0x189b0, (base + 0x8754) | 1)
    uc.mem_write(symbols['g_tls_fixer_native_continuations'], struct.pack('<4I', *targets))
    map_bytes(CONNECTION, bytes(0x2000))
    map_bytes(STACK, bytes(0x4000))
    map_bytes(STOP, bytes(4096))
    uc.mem_write(ERRNO, struct.pack('<I', 0x80410123))
    for offset, value in fields.items():
        uc.mem_write(CONNECTION + offset, struct.pack('<I', value))
    initial_sp = STACK + 0x3f00
    uc.reg_write(UC_ARM_REG_SP, initial_sp)
    uc.reg_write(UC_ARM_REG_LR, STOP | 1)
    uc.reg_write(UC_ARM_REG_R0, CONNECTION)
    uc.reg_write(UC_ARM_REG_R1, io_result & 0xffffffff)
    uc.reg_write(UC_ARM_REG_R2, 0x1234)
    for i, reg in enumerate(SAVED):
        uc.reg_write(reg, 0x44000000 + i)
    calls = []
    done = []
    imports = {0x18910: ssl_result, 0x189b0: ssl_result, 0x187a0: ERRNO,
               0x13bc8: 0, 0x0c4c0: 0, 0x18bd0: 0, 0x18890: 0, 0x18be0: 0}

    def step(machine, address, size, context):
        if address == STOP:
            done.append(True)
            machine.emu_stop()
            return
        offset = address - base
        if offset not in imports:
            return
        thumb = bool(machine.reg_read(UC_ARM_REG_CPSR) & 0x20)
        assert thumb == (offset in (0x13bc8, 0x0c4c0)), (hex(offset), thumb)
        # The observed import arguments and order must match Sony's original.
        args = [machine.reg_read(UC_ARM_REG_R0)]
        if offset == 0x13bc8:
            args.append(machine.reg_read(UC_ARM_REG_R1))
        calls.append((offset, args))
        machine.reg_write(UC_ARM_REG_R0, imports[offset] & 0xffffffff)
        for reg in (UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R12):
            machine.reg_write(reg, 0xa5a5a5a5)
        machine.reg_write(UC_ARM_REG_PC, machine.reg_read(UC_ARM_REG_LR))

    uc.hook_add(UC_HOOK_CODE, step)
    entry = symbols['tls_fixer_native_' + kind] if fixed else base + {
        'map_io': 0x85fe, 'shutdown': 0x874c}[kind] | 1
    uc.emu_start(entry, STOP + 4, count=1000)
    assert done, (kind, fixed, 'did not return')
    assert uc.reg_read(UC_ARM_REG_SP) == initial_sp
    assert [uc.reg_read(reg) for reg in SAVED] == [0x44000000 + i for i in range(8)]
    return uc.reg_read(UC_ARM_REG_R0), bytes(uc.mem_read(CONNECTION, 0x200)), calls


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('libhttp', type=Path)
    args = parser.parse_args()
    text = bundled_module(args.libhttp).text
    elf = args.elf.read_bytes()
    count = 0
    for base in (0x81800000, 0x819a0000, 0x82704000):
        for error in (-1, *range(9)):
            for result in (-0x7fbefedd, 0, 251):
                fields = {0x40: 0x12345678, 0x160: 0x55555555, 0x164: 0x66666666}
                before = run(text, elf, base, 'map_io', False, error, result, fields)
                after = run(text, elf, base, 'map_io', True, error, result, fields)
                assert before == after, ('map_io', base, error, result, before, after)
                count += 1
        for initialized in (-1, 0, 1):
            for bits in range(8):
                fields = {0x40: 0x12345678 if bits & 1 else 0,
                          0x44: 0x23456789 if bits & 2 else 0,
                          0x60: 1 if bits & 4 else 0, 0x118: 0x3456789a}
                before = run(text, elf, base, 'shutdown', False, initialized, 0, fields)
                after = run(text, elf, base, 'shutdown', True, initialized, 0, fields)
                assert before == after, ('shutdown', base, initialized, bits, before, after)
                count += 1
    print(f'{count} ARM differential cases passed: native results, writes, calls, stack and saved registers')


if __name__ == '__main__':
    main()
