#!/usr/bin/env python3
"""Relocation format and unchanged-native-behavior checks for the offline merger."""

from dataclasses import replace
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from augment_libhttp import (InvalidModule, Module, Relocation, Segment, apply_relocations,
                            decode_relocations, encode_elf, append_imported_payload, word)


def fixture():
    m = Module.__new__(Module)
    m.segments = [Segment(0x81000000, bytes(1024), 1024, 5, 16),
                  Segment(0x82000000, bytes(512), 512, 6, 16)]
    return m


def words(*values):
    return struct.pack('<' + 'I' * len(values), *values)


def prime():
    return Relocation(0, 0, 0, 0, 0).encode()


class CompactRelocations(unittest.TestCase):
    def test_long_pair_uses_byte_distance(self):
        stream = words(1 << 4 | 47 << 8 | 48 << 20 | 6 << 27, 0x2345, 32)
        self.assertEqual(decode_relocations(stream, fixture()), [
            Relocation(0, 32, 1, 0x2345, 47), Relocation(0, 38, 1, 0x2345, 48)])

    def test_signed_short_addend(self):
        stream = words(1 | 1 << 4 | 2 << 8 | 0x80 << 20, ((-4 & 0x3fffff) << 10))
        self.assertEqual(decode_relocations(stream, fixture()), [Relocation(0, 0x80, 1, 0xfffffffc, 2)])

    def test_delta_absolute_record(self):
        stream = prime() + words(2 | 1 << 4 | 2 << 8 | 12 << 16, 20)
        self.assertEqual(decode_relocations(stream, fixture()), [Relocation(0, 12, 1, 20, 2)])

    def test_mov_pairs_and_reuse(self):
        stream = prime() + words(3 | 1 << 4 | 1 << 8 | 16 << 9 | 4 << 27, 64)
        stream += words(4 | 16 << 4 | 6 << 27)
        stream += words(5 | 16 << 4 | 4 << 13 | 16 << 18 | 6 << 27)
        self.assertEqual([(r.offset, r.code) for r in decode_relocations(stream, fixture())],
                         [(16, 47), (20, 48), (32, 47), (38, 48), (48, 47), (52, 48), (64, 47), (70, 48)])

    def test_pointer_inference_and_packed_deltas(self):
        m = fixture()
        data = bytearray(m.segments[0].data)
        for i, off in enumerate((16, 20, 28, 32, 40, 44, 52)):
            struct.pack_into('<I', data, off, m.segments[i % 2].base + 100 + i * 4)
        m.segments[0] = replace(m.segments[0], data=bytes(data))
        stream = prime() + words(6 | 16 << 4, 7 | (1 | 2 << 7) << 4,
                                 8 | (1 | 2 << 4) << 4, 9 | (1 | 2 << 2) << 4)
        actual = decode_relocations(stream, m)
        self.assertEqual([(r.offset, r.symbol, r.addend) for r in actual],
                         [(off, i % 2, 100 + i * 4) for i, off in enumerate((16, 20, 28, 32, 40, 44, 52))])

    def test_expanded_roundtrip(self):
        relocs = [Relocation(0, 4, 1, 0xfffffff8, 2), Relocation(1, 80, 0, 1, 47)]
        self.assertEqual(decode_relocations(b''.join(r.encode() for r in relocs), fixture()), relocs)

    def test_reject_truncated_records(self):
        streams = [words(0, 0, 16), words(1, 0), prime() + words(2 | 4 << 16, 0),
                   prime() + words(3 | 4 << 9 | 4 << 27, 0)]
        for stream in streams:
            for n in (1, 2, 3):
                with self.subTest(stream=stream.hex(), truncate=n), self.assertRaises(InvalidModule):
                    decode_relocations(stream[:-n], fixture())

    def test_reject_bad_state(self):
        streams = [words(6 | 4 << 4), prime() + words(10), prime() + words(2, 0),
                   prime() + words(4 | 4 << 4 | 4 << 27), prime() + words(6),
                   prime() + words(7), prime() + words(8 | (2 << 4) << 4)]
        for stream in streams:
            with self.subTest(stream=stream.hex()), self.assertRaises(InvalidModule):
                decode_relocations(stream, fixture())

    def test_reject_overlap_and_out_of_range(self):
        relocs = [Relocation(0, 16, 0, 0, 2), Relocation(0, 18, 1, 0, 2)]
        with self.assertRaises(InvalidModule):
            decode_relocations(b''.join(r.encode() for r in relocs), fixture())
        for target, offset, symbol in ((2, 0, 0), (0, 1022, 0), (0, 0, 2)):
            with self.assertRaises(InvalidModule):
                decode_relocations(words(symbol << 4 | 2 << 8 | target << 16, 0, offset), fixture())

    def test_reject_unmapped_inferred_pointer(self):
        with self.assertRaises(InvalidModule):
            decode_relocations(prime() + words(6 | 4 << 4), fixture())


class NativeImage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = Module.read(Path(__file__).resolve().parents[2] / 'misc/lhttp.suprx')

    def test_all_public_exports_retained_in_normalized_image(self):
        m = self.module
        output = Module(encode_elf(m, m.segments, m.relocations()))
        self.assertEqual(output.export_entries(), m.export_entries())
        self.assertEqual(output.info, m.info)
        self.assertEqual(len([key for key in output.export_entries() if key[0] == 0xe8f15cde]), 116)

    def test_original_nid_lookup_parameters_preserved(self):
        for off, library in self.module.export_records():
            if library == 0xe8f15cde:
                self.assertEqual(word(self.module.segments[0].data, off + 12), 4)

    def test_normalized_relocation_equivalence(self):
        m = self.module
        out = Module(encode_elf(m, m.segments, m.relocations()))
        for bases in ([0x81000000, 0x82000000], [0xe0400000, 0x81800000]):
            buffers = [bytearray(s.data) for s in m.segments]
            other = [bytearray(s.data) for s in out.segments]
            apply_relocations(buffers, m.relocations(), bases)
            apply_relocations(other, out.relocations(), bases)
            self.assertEqual(buffers, other)

    def test_reject_overlapping_output_segments(self):
        m = self.module
        segments = [m.segments[0], replace(m.segments[1], base=m.segments[0].base + 64)]
        with self.assertRaises(InvalidModule):
            Module(encode_elf(m, segments, m.relocations()))

    def test_reject_wrong_elf_kind_and_truncation(self):
        data = bytearray(encode_elf(self.module, self.module.segments, self.module.relocations()))
        data[16:18] = b'\x02\x00'
        with self.assertRaises(InvalidModule):
            Module(bytes(data))
        with self.assertRaises(InvalidModule):
            Module(bytes(data[:40]))

    def test_import_merge_retains_native_bindings_and_variable_imports(self):
        native = self.module
        library = 0xcae9ace6
        duplicate = next(iter(native.import_records()[library][1]))
        new_nid = 0x10203040
        data = bytearray(0x1000)
        info = bytearray(0x5c)
        info[4:31] = b'tls_fixer_test'.ljust(27, b'\0')
        info[31] = 6
        struct.pack_into('<II', info, 0x2c, 0x180, 0x1b4)
        data[0x40:0x9c] = info
        for off in (0x100, 0x110):
            struct.pack_into('<3I', data, off, 0xe3e00000, 0xe12fff1e, 0xe1a00000)
        struct.pack_into('<6H10I', data, 0x180, 52, 1, 0, 2, 0, 0,
                         0, library, 0, 0, 0x810001c0, 0x810001d0, 0, 0, 0, 0)
        struct.pack_into('<2I', data, 0x1c0, duplicate, new_nid)
        struct.pack_into('<2I', data, 0x1d0, 0x81000100, 0x81000110)
        template = Module.__new__(Module)
        header = bytearray(native.header)
        struct.pack_into('<I', header, 24, 0x40)
        template.header = bytes(header)
        segments = [Segment(0x81000000, bytes(data), len(data), 5, 16),
                    Segment(0x81010000, bytes(16), 16, 6, 16)]
        relocs = [Relocation(0, a, 0, b, 2) for a,b in ((0x19c,0x1c0),(0x1a0,0x1d0),(0x1d0,0x100),(0x1d4,0x110))]
        payload = Module(encode_elf(template, segments, relocs))
        image, report = append_imported_payload(native, payload)
        merged = Module(image)
        imports = merged.import_records()
        for lib, (_record, functions) in native.import_records().items():
            for nid, stub in functions.items():
                self.assertEqual(imports[lib][1][nid], stub)
        record, functions = imports[library]
        self.assertEqual(struct.unpack_from('<HH', merged.segments[0].data, record + 2), (5, 0))
        self.assertEqual(struct.unpack_from('<H', merged.segments[0].data, record + 8)[0], 1)
        self.assertIn(new_nid, functions)
        ssl_record = imports[0x68d6c3ff][0]
        self.assertEqual(struct.unpack_from('<H', merged.segments[0].data, ssl_record + 4)[0], 8)
        self.assertEqual(len(report['imports']['aliases']), 1)
        alias = report['imports']['aliases'][0]
        self.assertEqual(alias['nid'], duplicate)
        self.assertEqual(struct.unpack_from('<2I', merged.segments[0].data, alias['from']), (0xe59fc000,0xe12fff1c))
        self.assertEqual(word(merged.segments[0].data, alias['from']+8), native.import_records()[library][1][duplicate])

    def test_import_merge_rejects_unhandled_payload_variables(self):
        with self.assertRaisesRegex(InvalidModule, 'variable imports'):
            append_imported_payload(self.module, self.module)


if __name__ == '__main__':
    unittest.main()
