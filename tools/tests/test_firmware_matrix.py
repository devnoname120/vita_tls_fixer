"""Regression coverage for variable NIDs in Vita module library tables."""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from firmware_matrix import Firmware


def module_fixture(import_size=0x34, functions=1):
    data = bytearray(0x700)
    data[:7] = b'\x7fELF\x01\x01\x01'
    struct.pack_into('<II', data, 24, 0x40, 52)
    struct.pack_into('<HH', data, 42, 32, 2)
    struct.pack_into('<8I', data, 52, 1, 0x100, 0, 0, 0x400, 0x400, 5, 0x1000)
    struct.pack_into('<8I', data, 84, 1, 0x600, 0x10000, 0x10000, 0x100, 0x100, 6, 0x1000)
    text = memoryview(data)[0x100:0x500]
    text[0x44:0x4e] = b'SceFixture'
    struct.pack_into('<4I', text, 0x64, 0x100, 0x120, 0x140, 0x140 + import_size)
    # Exports share one NID/entry array, with variables after functions.
    struct.pack_into('<H', text, 0x100, 0x20)
    struct.pack_into('<HH', text, 0x106, functions, 1)
    struct.pack_into('<4I', text, 0x110, 0x12345678, 0, 0x280, 0x2a0)
    ids = [0x11111111, 0x22222222] if functions else [0x22222222]
    addresses = [0x300, 0x10020] if functions else [0x10020]
    for i, (nid, address) in enumerate(zip(ids, addresses)):
        struct.pack_into('<I', text, 0x280 + i * 4, nid)
        struct.pack_into('<I', text, 0x2a0 + i * 4, address)
    # Imports keep their function and variable arrays separate.
    struct.pack_into('<6H', text, 0x140, import_size, 1, 0, functions, 1, 0)
    library_at = 0x150 if import_size == 0x34 else 0x14c
    struct.pack_into('<I', text, library_at, 0x12345678)
    arrays_at = 0x15c if import_size == 0x34 else 0x154
    struct.pack_into('<4I', text, arrays_at, 0x200, 0x220, 0x240, 0x260)
    for at, value in ((0x200, 0x11111111), (0x220, 0x300),
                      (0x240, 0x22222222), (0x260, 0x10020)):
        struct.pack_into('<I', text, at, value)
    return bytes(data)


class VariableLibraryTests(unittest.TestCase):
    def test_functions_and_variables_resolve_in_both_import_layouts(self):
        expected = {(0x12345678, 0x11111111): 0x300,
                    (0x12345678, 0x22222222): 0x10020}
        for size in (0x24, 0x34):
            with self.subTest(import_size=size):
                module = Firmware('fixture.elf', module_fixture(size))
                self.assertEqual(module.imports, expected)
                self.assertEqual(module.exports, expected)

    def test_variable_only_library_is_not_dropped(self):
        expected = {(0x12345678, 0x22222222): 0x10020}
        for size in (0x24, 0x34):
            with self.subTest(import_size=size):
                module = Firmware('fixture.elf', module_fixture(size, functions=0))
                self.assertEqual(module.imports, expected)
                self.assertEqual(module.exports, expected)


if __name__ == '__main__':
    unittest.main()
