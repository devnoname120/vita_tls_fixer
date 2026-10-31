#!/usr/bin/env python3
"""Offline construction of an experimental Sony HTTP module with an embedded payload.

This is deliberately separate from packaging. It accepts the project's known
plaintext Sony module and a separately linked, two-segment payload. Compact SCE
relocations are expanded before moving anything, including pointer-derived
formats 6-9. The original executable and writable offsets remain unchanged.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, replace
import hashlib
import json
from pathlib import Path
import struct

from firmware_matrix import bundled_module

U32 = 0xffffffff
PT_LOAD = 1
PT_RELA = 0x60000000
SUPPORTED_CODES = {0, 2, 3, 10, 28, 29, 38, 40, 41, 42, 43, 44, 47, 48}


class InvalidModule(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise InvalidModule(message)


def align(value: int, alignment: int) -> int:
    require(alignment > 0 and alignment & (alignment - 1) == 0, "invalid alignment")
    return (value + alignment - 1) & -alignment


def word(data: bytes | bytearray, offset: int) -> int:
    require(0 <= offset <= len(data) - 4, "word outside file-backed data")
    return struct.unpack_from('<I', data, offset)[0]


@dataclass(frozen=True)
class Segment:
    base: int
    data: bytes
    memsz: int
    flags: int
    alignment: int


@dataclass(frozen=True)
class Relocation:
    target: int
    offset: int
    symbol: int
    addend: int
    code: int

    def encode(self) -> bytes:
        # Native format 0. Do not use the SDK's differing short-format bitfields.
        require(self.target in (0, 1) and self.symbol in (0, 1), "invalid relocation segment")
        require(self.code in SUPPORTED_CODES, "unsupported ARM relocation")
        require(0 <= self.offset <= U32, "relocation offset overflow")
        return struct.pack('<III', self.symbol << 4 | self.code << 8 | self.target << 16,
                           self.addend & U32, self.offset)


class Module:
    def __init__(self, data: bytes):
        require(52 <= len(data) <= 16 * 1024 * 1024, "invalid ELF size")
        require(data[:7] == b'\x7fELF\x01\x01\x01', "expected little-endian ELF32")
        header = struct.unpack_from('<16sHHIIIIIHHHHHH', data)
        require(header[1:4] == (0xfe04, 40, 1), "expected ARM ET_SCE_RELEXEC")
        require(header[8:10] == (52, 32), "unexpected ELF header sizes")
        self.header = data[:52]
        self.info_offset = header[4]
        require(self.info_offset >> 30 == 0, "module info must be in first segment")
        phoff, count = header[5], header[10]
        require(1 <= count <= 8 and 52 <= phoff <= len(data) - count * 32,
                "invalid program-header span")
        self.segments: list[Segment] = []
        self.streams: list[bytes] = []
        seen_nonload = False
        for i in range(count):
            kind, offset, base, physical, filesz, memsz, flags, alignment = struct.unpack_from(
                '<8I', data, phoff + i * 32)
            require(offset <= len(data) and filesz <= len(data) - offset, "segment outside ELF")
            require(physical in (0, base), "unexpected physical address")
            if kind == PT_LOAD:
                require(not seen_nonload, "load segment after metadata segment")
                require(0 < memsz <= 8 * 1024 * 1024 and filesz <= memsz,
                        "invalid load segment size")
                require(base + memsz <= U32, "segment address overflow")
                require(16 <= alignment <= 4096 and alignment & (alignment - 1) == 0,
                        "unsupported segment alignment")
                self.segments.append(Segment(base, data[offset:offset + filesz], memsz, flags, alignment))
            else:
                seen_nonload = True
                require(kind == PT_RELA or (kind == 0x6fffff01 and filesz == 0),
                        "unsupported auxiliary segment")
                if kind == PT_RELA and filesz:
                    require(alignment == 16 and flags == 0, "unsupported relocation stream flags")
                    self.streams.append(data[offset:offset + filesz])
        require(len(self.segments) == 2, "expected exactly two load segments")
        require([s.flags for s in self.segments] == [5, 6], "expected RX followed by RW")
        a, b = self.segments
        require(a.base + a.memsz <= b.base or b.base + b.memsz <= a.base, "overlapping segments")
        require(self.info_offset <= len(a.data) - 0x5c, "module info outside text")
        self.info = a.data[self.info_offset:self.info_offset + 0x5c]
        self.name = self.info[4:31].split(b'\0', 1)[0].decode('ascii')
        require(self.info[31] == 6, "expected library module")
        require(not any(self.info[0x38:0x44]), "thread-local storage is not supported by merger")

    @classmethod
    def read(cls, path: Path) -> Module:
        data = path.read_bytes()
        if data[:4] == b'SCE\0':
            data = bundled_module(path).data
        return cls(data)

    def locate(self, address: int, size: int = 1) -> tuple[int, int]:
        matches = [(i, address - s.base) for i, s in enumerate(self.segments)
                   if s.base <= address and address + size <= s.base + s.memsz]
        require(len(matches) == 1, f"unmapped/ambiguous address 0x{address:08x}")
        return matches[0]

    def read_word(self, segment: int, offset: int) -> int:
        require(segment in (0, 1), "invalid segment")
        return word(self.segments[segment].data, offset)

    def relocations(self) -> list[Relocation]:
        result: list[Relocation] = []
        occupied: set[tuple[int, int]] = set()
        for stream in self.streams:
            result.extend(decode_relocations(stream, self, occupied))
        return result

    def export_records(self) -> list[tuple[int, int]]:
        begin, end = struct.unpack_from('<II', self.info, 0x24)
        require(0 <= begin <= end <= len(self.segments[0].data), "invalid export span")
        result = []
        while begin < end:
            require(begin + 32 <= end, "truncated export record")
            size = struct.unpack_from('<H', self.segments[0].data, begin)[0]
            require(size == 32, "unsupported export record")
            # Native +0x0c contains NID lookup-table parameters, not a TLS
            # variable count. Preserve it along with the original NID tables.
            require(struct.unpack_from('<H', self.segments[0].data, begin + 10)[0] == 0,
                    "unsupported export extension")
            result.append((begin, self.read_word(0, begin + 16)))
            begin += size
        return result

    def export_entries(self) -> dict[tuple[int, int], tuple[int, int, int]]:
        result = {}
        for record, library in self.export_records():
            functions = struct.unpack_from('<H', self.segments[0].data, record + 6)[0]
            count = functions + struct.unpack_from('<H', self.segments[0].data, record + 8)[0]
            ns, no = self.locate(self.read_word(0, record + 24), count * 4)
            es, eo = self.locate(self.read_word(0, record + 28), count * 4)
            for i in range(count):
                key = library, self.read_word(ns, no + 4 * i)
                require(key not in result, "duplicate export NID")
                result[key] = es, eo + 4 * i, self.read_word(es, eo + 4 * i)
        return result

    def import_records(self) -> dict[int, tuple[int, dict[int, int]]]:
        begin, end = struct.unpack_from('<II', self.info, 0x2c)
        require(0 <= begin <= end <= len(self.segments[0].data), "invalid import span")
        result = {}
        while begin < end:
            require(begin + 52 <= end, "truncated import record")
            size, _version, _flags, count, _variables, tls = struct.unpack_from('<6H', self.segments[0].data, begin)
            require(size == 52 and tls == 0, "unsupported import record")
            library = self.read_word(0, begin + 16)
            require(library not in result, "duplicate import library")
            nids = self.read_word(0, begin + 28)
            entries = self.read_word(0, begin + 32)
            functions = {}
            if count:
                ns, no = self.locate(nids, count * 4)
                es, eo = self.locate(entries, count * 4)
                for i in range(count):
                    nid = self.read_word(ns, no + i * 4)
                    require(nid not in functions, "duplicate function import")
                    functions[nid] = self.read_word(es, eo + i * 4)
            result[library] = begin, functions
            begin += size
        return result


def decode_relocations(stream: bytes, module: Module,
                       occupied: set[tuple[int, int]] | None = None) -> list[Relocation]:
    """Decode the 3.60 firmware format, rejecting partial/ambiguous writes."""
    if occupied is None:
        occupied = set()
    require(len(stream) >= 8 and word(stream, 0) & 15 in (0, 1), "missing relocation base record")
    result: list[Relocation] = []
    target = symbol = offset = addend = code = code2 = 0
    cursor = 0

    def emit(at: int, op: int) -> None:
        require(target in (0, 1) and symbol in (0, 1), "invalid relocation segment")
        require(op in SUPPORTED_CODES, f"unsupported ARM relocation {op}")
        require(0 <= at <= len(module.segments[target].data) - 4,
                "relocation target outside file-backed data")
        if op in (0, 40):
            return
        positions = {(target, at + i) for i in range(4)}
        require(not occupied.intersection(positions), "overlapping relocation writes")
        occupied.update(positions)
        result.append(Relocation(target, at, symbol, addend & U32, op))

    def pointer(at: int) -> None:
        nonlocal symbol, addend, code, code2
        symbol, addend = module.locate(module.read_word(target, at))
        code, code2 = 2, 0
        emit(at, code)

    while cursor < len(stream):
        value = word(stream, cursor)
        kind = value & 15
        require(kind <= 9, "unknown compact relocation format")
        length = 12 if kind == 0 else 8 if kind <= 3 else 4
        require(cursor + length <= len(stream), "truncated relocation record")
        if kind in (0, 1):
            symbol, code, target = value >> 4 & 15, value >> 8 & 255, value >> 16 & 15
            second = word(stream, cursor + 4)
            if kind == 0:
                addend, offset = second, word(stream, cursor + 8)
                code2, distance = value >> 20 & 127, value >> 27
            else:
                # The firmware arithmetic-shifts this signed word by ten.
                addend = struct.unpack('<i', struct.pack('<I', second))[0] >> 10
                offset, code2, distance = (value >> 20) | ((second & 1023) << 12), 0, 0
            emit(offset, code)
            if code2:
                require(distance > 0, "zero paired relocation distance")
                emit(offset + distance, code2)
        elif kind in (2, 3):
            symbol, addend = value >> 4 & 15, word(stream, cursor + 4)
            delta = value >> 16 if kind == 2 else value >> 9 & 0x3ffff
            require(delta > 0, "zero relocation delta")
            offset += delta
            if kind == 2:
                code, code2 = value >> 8 & 255, 0
            else:
                code, code2 = (47, 48) if value & 256 else (43, 44)
            emit(offset, code)
            if code2:
                require(value >> 27 > 0, "zero paired relocation distance")
                emit(offset + (value >> 27), code2)
        elif kind in (4, 5):
            require((code, code2) in ((43, 44), (47, 48)), "paired delta without MOVW/MOVT base")
            pairs = [(value >> 4 & 0x7fffff, value >> 27)] if kind == 4 else [
                (value >> 4 & 511, value >> 13 & 31), (value >> 18 & 511, value >> 27)]
            for delta, distance in pairs:
                require(delta > 0 and distance > 0, "zero paired delta")
                offset += delta
                emit(offset, code)
                emit(offset + distance, code2)
        elif kind == 6:
            require(value >> 4 > 0, "zero pointer delta")
            offset += value >> 4
            pointer(offset)
        else:
            bits = {7: 7, 8: 4, 9: 2}[kind]
            deltas = value >> 4
            require(deltas > 0, "empty pointer delta list")
            while deltas:
                delta = deltas & ((1 << bits) - 1)
                require(delta > 0, "zero packed pointer delta")
                offset += delta * 4
                pointer(offset)
                deltas >>= bits
        cursor += length
    return result


def relocate_word(original: int, relocation: Relocation, bases: list[int]) -> int:
    """Match native 3.60 ARM relocation operations; no instruction decoding guesswork."""
    absolute = (bases[relocation.symbol] + relocation.addend) & U32
    relative = (absolute - bases[relocation.target] - relocation.offset) & U32
    code = relocation.code
    if code in (0, 40):
        return original
    if code in (2, 38):
        return absolute
    if code in (3, 41):
        return relative
    if code == 10:
        sign = relative >> 24 & 1
        imm11 = relative >> 1 & 0x7ff
        if not original & 0x10000000:  # BLX requires word alignment.
            imm11 &= ~1
        return (original & 0xd000f800 | ((sign ^ (~relative >> 23)) & 1) << 29 |
                ((sign ^ (~relative >> 22)) & 1) << 27 | imm11 << 16 |
                sign << 10 | (relative >> 12 & 0x3ff))
    if code in (28, 29):
        if not original & 0xf0000000:
            original = original & 0xfe7fffff | (relative & 3) << 23
        return original & 0xff000000 | relative >> 2 & 0xffffff
    if code == 42:
        # This is the observed native mask, including its decimal-80000000 quirk.
        return relative & 0x7fffffff | original & 0x04c4b400
    if code in (43, 44):
        immediate = absolute >> (16 if code == 44 else 0) & 0xffff
        return original & 0xfff0f000 | immediate & 0xfff | (immediate >> 12) << 16
    if code in (47, 48):
        immediate = absolute >> (16 if code == 48 else 0) & 0xffff
        return (original & 0x8f00fbf0 | (immediate & 255) << 16 |
                (immediate >> 8 & 7) << 28 | (immediate >> 11 & 1) << 10 | immediate >> 12)
    raise InvalidModule(f"unsupported ARM relocation {code}")


def apply_relocations(segments: list[bytearray], relocs: list[Relocation], bases: list[int]) -> None:
    for r in relocs:
        value = relocate_word(word(segments[r.target], r.offset), r, bases)
        struct.pack_into('<I', segments[r.target], r.offset, value & U32)


def encode_elf(template: Module, segments: list[Segment], relocs: list[Relocation]) -> bytes:
    require(len(segments) == 2, "output must retain RX/RW pair")
    records = b''.join(r.encode() for r in relocs)
    header = bytearray(template.header)
    struct.pack_into('<II', header, 28, 52, 0)  # program table; strip stale sections
    struct.pack_into('<HHHH', header, 44, 3, 0, 0, 0)
    result = bytearray(52 + 3 * 32)
    headers = []
    for s in segments:
        offset = align(len(result), s.alignment)
        result.extend(bytes(offset - len(result)))
        headers.append((1, offset, s.base, 0, len(s.data), s.memsz, s.flags, s.alignment))
        result.extend(s.data)
    offset = align(len(result), 16)
    result.extend(bytes(offset - len(result)))
    headers.append((PT_RELA, offset, 0, 0, len(records), 0, 0, 16))
    result.extend(records)
    result[:52] = header
    for i, h in enumerate(headers):
        struct.pack_into('<8I', result, 52 + 32 * i, *h)
    return bytes(result)


def append_inert_payload(native: Module, payload: Module) -> tuple[bytes, dict]:
    """First loader control: embed code/data without publishing or running it."""
    require(native.name == 'SceLibHttp', "native input must be SceLibHttp")
    require(all(s.memsz == len(s.data) for s in (native.segments[0], payload.segments[0])),
            "RX zero-fill is not supported by the merger")
    offsets = [align(s.memsz, max(s.alignment, p.alignment))
               for s, p in zip(native.segments, payload.segments)]
    buffers = [bytearray(s.data) + bytes(off - len(s.data)) + p.data
               for s, p, off in zip(native.segments, payload.segments, offsets)]
    sizes = [off + s.memsz for off, s in zip(offsets, payload.segments)]
    native_relocs = native.relocations()
    payload_relocs = [replace(r, offset=r.offset + offsets[r.target],
                             addend=(r.addend + offsets[r.symbol]) & U32)
                      for r in payload.relocations()]
    relocs = native_relocs + payload_relocs
    base = native.segments[0].base
    bases = [base, align(base + sizes[0], 4096)]
    apply_relocations(buffers, relocs, bases)
    output_segments = [Segment(bases[i], bytes(buffers[i]), sizes[i], native.segments[i].flags,
                               max(native.segments[i].alignment, payload.segments[i].alignment))
                       for i in range(2)]
    output = encode_elf(native, output_segments, relocs)
    # Re-parse the emitted file rather than trusting intermediate objects.
    result = Module(output)
    require(result.info == native.info, "inert payload changed native module metadata")
    require(len(result.relocations()) == len(relocs), "emitted relocation count mismatch")
    return output, {'mode': 'inert-loader-control', 'payload_offsets': offsets,
                    'native_relocations': len(native_relocs), 'payload_relocations': len(payload_relocs),
                    'native_memory': sum(s.memsz for s in native.segments),
                    'output_memory': sum(s.memsz for s in result.segments),
                    'sha256': hashlib.sha256(output).hexdigest()}


def merge_imports(native: Module, payload: Module, combined: Module, offsets: list[int],
                  buffers: list[bytearray], relocations: list[Relocation]) -> dict:
    """Publish one descriptor per library and alias duplicate payload stubs.

    Native stubs, including its weak SSL imports and variable relocation blobs,
    retain their locations. New functions use the payload's stubs. Duplicated
    payload stubs become simple ARM tail calls to the existing native stubs.
    There are no displaced instructions or runtime hooks.
    """
    native_imports, payload_imports = native.import_records(), payload.import_records()
    originals = list(relocations)
    library_rows = []
    aliases = []

    def address(module, value, additions):
        segment, offset = module.locate(value)
        return segment, offset + additions[segment]

    def append(data):
        at = align(len(buffers[0]), 4)
        buffers[0].extend(bytes(at - len(buffers[0])))
        buffers[0].extend(data)
        return at

    for library in sorted(native_imports.keys() | payload_imports.keys()):
        native_record = native_imports.get(library)
        payload_record = payload_imports.get(library)
        origin = native_record[0] if native_record else payload_record[0] + offsets[0]
        raw = bytearray(combined.segments[0].data[origin:origin + 52])
        functions = {nid: address(native, value, [0, 0]) for nid, value in native_record[1].items()} if native_record else {}
        if payload_record:
            original_payload_record = payload_record[0]
            require(struct.unpack_from('<H', payload.segments[0].data, original_payload_record + 8)[0] == 0,
                    "payload variable imports require separate relocation handling")
            if native_record:
                pv, pf = struct.unpack_from('<HH', payload.segments[0].data, original_payload_record + 2)
                nv, nf = struct.unpack_from('<HH', raw, 2)
                require(pf == nf, "cannot merge imports with different binding flags")
                struct.pack_into('<H', raw, 2, max(nv, pv))
            for nid, original_address in payload_record[1].items():
                target = address(payload, original_address, offsets)
                if nid not in functions:
                    functions[nid] = target
                    continue
                existing = functions[nid]
                require(target[0] == existing[0] == 0 and target[1] % 4 == existing[1] % 4 == 0,
                        "import alias needs ARM stubs in RX")
                require(buffers[0][target[1]:target[1] + 12] == struct.pack('<3I', 0xe3e00000, 0xe12fff1e, 0xe1a00000),
                        "unexpected unbound SDK import stub")
                require(not any(r.target == 0 and target[1] <= r.offset < target[1] + 12 for r in originals),
                        "import stub overlaps existing relocations")
                # ldr ip,[pc,#0]; bx ip; .word original_stub
                struct.pack_into('<3I', buffers[0], target[1], 0xe59fc000, 0xe12fff1c, 0)
                relocations.append(Relocation(0, target[1] + 8, existing[0], existing[1], 2))
                aliases.append({'library': library, 'nid': nid, 'from': target[1], 'to': existing[1]})
        require(len(functions) <= 0xffff, "too many merged function imports")
        struct.pack_into('<H', raw, 6, len(functions))
        ordered = sorted(functions)
        nids_at = append(b''.join(struct.pack('<I', nid) for nid in ordered))
        entries_at = append(bytes(len(ordered) * 4))
        for i, nid in enumerate(ordered):
            segment, offset = functions[nid]
            relocations.append(Relocation(0, entries_at + i * 4, segment, offset, 2))
        library_rows.append((origin, raw, nids_at, entries_at))

    table = align(len(buffers[0]), 4)
    buffers[0].extend(bytes(table - len(buffers[0])))
    for origin, raw, nids_at, entries_at in library_rows:
        destination = len(buffers[0])
        buffers[0].extend(raw)
        for r in originals:
            if r.target == 0 and origin <= r.offset < origin + 52 and r.offset - origin not in (28, 32):
                require(r.code == 2 and r.offset + 4 <= origin + 52, "unexpected import descriptor relocation")
                relocations.append(replace(r, offset=destination + r.offset - origin))
        relocations.append(Relocation(0, destination + 28, 0, nids_at, 2))
        relocations.append(Relocation(0, destination + 32, 0, entries_at, 2))
    struct.pack_into('<II', buffers[0], native.info_offset + 0x2c, table, len(buffers[0]))
    return {'libraries': len(library_rows), 'aliases': aliases}


def append_imported_payload(native: Module, payload: Module) -> tuple[bytes, dict]:
    inert, report = append_inert_payload(native, payload)
    combined = Module(inert)
    buffers = [bytearray(s.data) for s in combined.segments]
    relocations = combined.relocations()
    report['imports'] = merge_imports(native, payload, combined, report['payload_offsets'], buffers, relocations)
    bases = [combined.segments[0].base, align(combined.segments[0].base + len(buffers[0]), 4096)]
    apply_relocations(buffers, relocations, bases)
    segments = [replace(s, base=bases[i], data=bytes(buffers[i]), memsz=max(s.memsz, len(buffers[i])))
                for i, s in enumerate(combined.segments)]
    output = encode_elf(native, segments, relocations)
    verified = Module(output)
    imports = verified.import_records()
    for library, (record, functions) in native.import_records().items():
        for nid, value in functions.items():
            require(imports[library][1][nid] == value, "native import stub moved")
    require(len(verified.relocations()) == len(relocations), "merged import relocation count mismatch")
    report.update(mode='imports-loader-control', sha256=hashlib.sha256(output).hexdigest(),
                  output_memory=sum(s.memsz for s in segments))
    return output, report


def merge_unwind(native: Module, payload: Module, offsets: list[int], buffer: bytearray) -> int:
    entries = []
    for module, addition in ((native, 0), (payload, offsets[0])):
        begin, end, extab_begin, extab_end = struct.unpack_from('<4I', module.info, 0x4c)
        require(extab_begin == extab_end, "external unwind tables need an explicit merge profile")
        require(0 <= begin <= end <= len(module.segments[0].data) and (end - begin) % 8 == 0,
                "invalid exception index")
        for at in range(begin, end, 8):
            first, second = struct.unpack_from('<II', module.segments[0].data, at)
            require(second == 1 or second & 0x80000000, "unexpected out-of-line unwind descriptor")
            relative = first & 0x7fffffff
            if relative & 0x40000000: relative -= 0x80000000
            function = at + relative
            require(0 <= function <= module.segments[0].memsz, "unwind entry points outside RX")
            entries.append((function + addition, second))
    entries.sort()
    require(len({function for function, _ in entries}) == len(entries), "duplicate unwind entries")
    table = align(len(buffer), 4)
    buffer.extend(bytes(table - len(buffer)))
    for function, second in entries:
        buffer.extend(struct.pack('<II', (function - len(buffer)) & 0x7fffffff, second))
    struct.pack_into('<II', buffer, native.info_offset + 0x4c, table, len(buffer))
    return len(entries)


def embed_tls_payload(native: Module, payload: Module) -> tuple[bytes, dict]:
    require(payload.name == 'tls_fixer_http_embedded', "unexpected TLS payload")
    require(hashlib.sha256(native.segments[0].data).hexdigest() ==
            '9282623772823878d62ac093b8b0b76f1dcb654f977475849dbe27801fe0de5e',
            "native HTTP differs from audited 3.74 image")
    combined_bytes, report = append_imported_payload(native, payload)
    combined = Module(combined_bytes)
    offsets = report['payload_offsets']
    buffers = [bytearray(s.data) for s in combined.segments]
    relocations = combined.relocations()
    originals = list(relocations)
    native_exports, payload_exports = native.export_entries(), payload.export_entries()
    library = 0x7f10b001

    def payload_address(value):
        segment, offset = payload.locate(value)
        return segment, offset + offsets[segment]

    def patch_pointer(segment, offset, destination, addend, replacing=False):
        old = [r for r in relocations if r.target == segment and r.offset == offset]
        if replacing:
            require(len(old) == 1 and old[0].code == 2, "unexpected pointer relocation")
            relocations.remove(old[0])
        else:
            require(not old, "binding pointer already relocated")
        relocations.append(Relocation(segment, offset, destination, addend, 2))

    # Export the original API tables, plus the embedded backend's introspection
    # library. HTTP callers continue to use the same library and function NIDs.
    table = align(len(buffers[0]), 4)
    buffers[0].extend(bytes(table - len(buffers[0])))
    copied = native.export_records() + [(off + offsets[0], lib) for off, lib in payload.export_records() if lib]
    for source, _ in copied:
        at = len(buffers[0])
        buffers[0].extend(combined.segments[0].data[source:source + 32])
        for r in originals:
            if r.target == 0 and source <= r.offset < source + 32:
                require(r.code == 2, "unexpected export descriptor relocation")
                relocations.append(replace(r, offset=at + r.offset - source))
    struct.pack_into('<II', buffers[0], native.info_offset + 0x24, table, len(buffers[0]))

    segment, binding = payload_address(payload_exports[library, 0x7f10b003][2])
    require(segment == 1, "bindings must be writable")
    require(buffers[1][binding:binding + 152] == struct.pack('<38I', 0x41584654, 4, *([0] * 36)),
            "unexpected embedded binding ABI")
    patch_pointer(1, binding + 8, 0, 0)
    patch_pointer(1, binding + 12, 1, 0)

    wrapped = [(0, 0x935cd196, 4), (0, 0x79f8e492, 5),
               (0xe8f15cde, 0x214926d9, 6), (0xe8f15cde, 0xc9076666, 7),
               (0xe8f15cde, 0xae8d7c33, 14), (0xe8f15cde, 0x8577833f, 15),
               (0xe8f15cde, 0xaeb3307e, 16), (0xe8f15cde, 0xc616c200, 17),
               (0xe8f15cde, 0xbd5da1d0, 18),
               (0xe8f15cde, 0x72cb0741, 29), (0xe8f15cde, 0x00659635, 30)]
    for original_library, nid, field in wrapped:
        slot_segment, slot_offset, native_address = native_exports[original_library, nid]
        ns, no = native.locate(native_address)
        patch_pointer(1, binding + 4 * field, ns, no)
        ps, po = payload_address(payload_exports[0 if original_library == 0 else library, nid][2])
        patch_pointer(slot_segment, slot_offset, ps, po, replacing=True)
        if original_library == 0:
            require(ps == 0, "module entry outside RX")
            struct.pack_into('<I', buffers[0], native.info_offset + (0x44 if field == 4 else 0x48), po)

    diagnostic_exports = set()
    parser_nid = 0x03a6c89e
    if (library, parser_nid) in payload_exports:
        slot_segment, slot_offset, native_address = native_exports[0xe8f15cde, parser_nid]
        require(native.locate(native_address) == (0, 0xde51), "diagnostic parser continuation changed")
        ps, po = payload_address(payload_exports[library, parser_nid][2])
        patch_pointer(slot_segment, slot_offset, ps, po, replacing=True)
        diagnostic_exports.add((0xe8f15cde, parser_nid))

    transport = [
        (33072, [(65352, 'f8f7f2f8')]),
        (33634, [(65378, 'f8f7fef9')]),
        (34302, [(34520, 'fff791ff'), (34608, 'fff765ff')]),
        (34460, [(50896, 'fbf7e4ff'), (51154, 'fbf763ff'), (51194, 'fbf74fff')]),
        (34548, [(52554, 'fbf7d3fc')]),
        (34636, [(50626, 'fcf7c3f8')])]
    patched_calls = []
    for index, (entry, sites) in enumerate(transport):
        patch_pointer(1, binding + 4 * (8 + index), 0, entry | 1)
        ps, po = payload_address(payload_exports[library, 0x7f10b010 + index][2])
        require(ps == 0 and po & 1, "transport wrapper must be Thumb RX")
        for site, expected in sites:
            require(native.segments[0].data[site:site + 4] == bytes.fromhex(expected), "transport call changed")
            require(not any(r.target == 0 and site <= r.offset < site + 4 for r in originals),
                    "transport call overlaps a native relocation")
            relocations.append(Relocation(0, site, 0, (po & ~1) - 4, 10))
            patched_calls.append({'site': site, 'native': entry, 'wrapper': po})
    cert_nids = [0x2185bb05, 0xa374cd7b, 0xe746465e, 0xd28834e6, 0x24c6257f,
                 0x29aac768, 0x144fa354, 0x19b2bb58, 0xef9ebac7, 0x88391e03]
    ssl_imports = native.import_records()[0x68d6c3ff][1]
    for i, nid in enumerate(cert_nids):
        ns, no = native.locate(ssl_imports[nid])
        patch_pointer(1, binding + 4 * (19 + i), ns, no)
    # Audited native object reference APIs and settings lifetimes. The native
    # image hash is pinned above; each redirected BL is checked separately.
    for field, entry in [(31, 0xba82), (32, 0xbd20), (33, 0xbd66), (34, 0xbef6),
                         (35, 0x11280), (36, 0x113b8), (37, 0xc4c0)]:
        patch_pointer(1, binding + 4 * field, 0, entry | 1)
    settings_calls = [
        (0x11280, 0x7f10b016, [(0x2586, '0ef07bfe'), (0xf3f2, '01f045ff')]),
        (0x113b8, 0x7f10b017, [(0x2970, '0ef022fd'), (0xbd40, '05f03afb'),
                                (0xbde6, '05f0e7fa'), (0xc1c0, '05f0faf8')]),
        # These are the final object frees on failed construction, distinct
        # from the nearby frees of strings and temporary buffers.
        (0xc4c0, 0x7f10b018, [(0x27b8, '09f082fe')]),
        (0xc4c0, 0x7f10b019, [(0xf556, 'fcf7b3ff')])]
    for entry, nid, sites in settings_calls:
        ps, po = payload_address(payload_exports[library, nid][2])
        require(ps == 0 and po & 1, 'settings wrapper must be Thumb RX')
        for site, expected in sites:
            require(native.segments[0].data[site:site + 4] == bytes.fromhex(expected),
                    'native settings call changed')
            require(not any(r.target == 0 and site <= r.offset < site + 4 for r in originals),
                    'settings call overlaps a native relocation')
            relocations.append(Relocation(0, site, 0, (po & ~1) - 4, 10))
            patched_calls.append({'site': site, 'native': entry, 'wrapper': po})
    unwind_count = merge_unwind(native, payload, offsets, buffers[0])
    bases = [combined.segments[0].base, align(combined.segments[0].base + len(buffers[0]), 4096)]
    apply_relocations(buffers, relocations, bases)
    segments = [replace(s, base=bases[i], data=bytes(buffers[i]), memsz=max(s.memsz, len(buffers[i])))
                for i, s in enumerate(combined.segments)]
    output = encode_elf(native, segments, relocations)
    verified = Module(output)
    require(len(verified.relocations()) == len(relocations), "embedded relocation count mismatch")
    exports = verified.export_entries()
    wrapped_keys = {(lib, nid) for lib, nid, _ in wrapped} | diagnostic_exports
    for key, value in native_exports.items():
        if key not in wrapped_keys:
            require(exports[key][2] == value[2], "unrelated native export changed")
    report.update(mode='embedded-tls', bindings_offset=binding, patched_calls=patched_calls,
                  diagnostic_exports=[f'{lib:08x}:{nid:08x}' for lib, nid in sorted(diagnostic_exports)],
                  unwind_entries=unwind_count, output_memory=sum(s.memsz for s in segments),
                  sha256=hashlib.sha256(output).hexdigest())
    return output, report


def embed_lifecycle_probe(native: Module, payload: Module) -> tuple[bytes, dict]:
    """Wrap native lifecycle only; keep HTTP entrypoints and imports unchanged."""
    require(payload.name == 'tls_fixer_http_aug_probe', "unexpected lifecycle payload")
    require(word(payload.info, 0x2c) == word(payload.info, 0x30), "probe must not import libraries")
    require(not any(payload.info[0x4c:0x5c]), "probe unwind metadata requires a separate merge")
    inert, report = append_inert_payload(native, payload)
    combined = Module(inert)
    offsets = report['payload_offsets']
    buffers = [bytearray(s.data) for s in combined.segments]
    relocations = combined.relocations()
    original_exports = native.export_entries()
    payload_exports = payload.export_entries()
    require(set(payload_exports) == {(0, 0x935cd196), (0, 0x79f8e492), (0, 0x6c2224ba),
                                    (0x7f10a001, 0x7f10a002), (0x7f10a001, 0x7f10a003)},
            "unexpected probe exports")

    def relocated_payload_address(address: int) -> tuple[int, int]:
        segment, offset = payload.locate(address)
        return segment, offset + offsets[segment]

    # Publish copied descriptor records, retaining native function/NID tables.
    table = align(len(buffers[0]), 4)
    buffers[0].extend(bytes(table - len(buffers[0])))
    copied = native.export_records() + [(off + offsets[0], lib) for off, lib in payload.export_records() if lib]
    for source, _library in copied:
        destination = len(buffers[0])
        buffers[0].extend(combined.segments[0].data[source:source + 32])
        for r in combined.relocations():
            if r.target == 0 and source <= r.offset < source + 32:
                require(r.code == 2 and r.offset + 4 <= source + 32, "unexpected export relocation")
                relocations.append(replace(r, offset=destination + r.offset - source))
    struct.pack_into('<II', buffers[0], native.info_offset + 0x24, table, len(buffers[0]))

    probe_segment, probe_offset = relocated_payload_address(payload_exports[0x7f10a001, 0x7f10a003][2])
    require(probe_segment == 1, "probe state must be writable")
    require(buffers[1][probe_offset:probe_offset + 32] == struct.pack('<8I', 0x41584654, 1, 0, 0, 0, 0, 0, 0),
            "unexpected probe bindings/state")
    lifecycle = {}
    for i, nid in enumerate((0x935cd196, 0x79f8e492)):
        slot_segment, slot_offset, original = original_exports[0, nid]
        original_segment, original_offset = native.locate(original)
        entry_segment, entry_offset = relocated_payload_address(payload_exports[0, nid][2])
        require(original_segment == entry_segment == slot_segment == 0, "lifecycle entry outside RX")
        slot_relocs = [r for r in relocations if (r.target, r.offset) == (slot_segment, slot_offset)]
        require(len(slot_relocs) == 1 and slot_relocs[0].code == 2, "missing lifecycle export relocation")
        relocations.remove(slot_relocs[0])
        relocations.append(Relocation(0, slot_offset, 0, entry_offset, 2))
        relocations.append(Relocation(1, probe_offset + 8 + i * 4, 0, original_offset, 2))
        struct.pack_into('<I', buffers[0], native.info_offset + 0x44 + i * 4, entry_offset)
        lifecycle['start' if i == 0 else 'stop'] = {'original': original_offset, 'wrapper': entry_offset}
    bases = [combined.segments[0].base, align(combined.segments[0].base + len(buffers[0]), 4096)]
    apply_relocations(buffers, relocations, bases)
    segments = [replace(s, base=bases[i], data=bytes(buffers[i]), memsz=max(s.memsz, len(buffers[i])))
                for i, s in enumerate(combined.segments)]
    output = encode_elf(native, segments, relocations)
    verified = Module(output)
    verified_exports = verified.export_entries()
    for key, value in original_exports.items():
        if key in ((0, 0x935cd196), (0, 0x79f8e492)):
            continue
        require(verified_exports[key][2] == value[2], "changed native non-lifecycle export")
    require(verified.info[0x2c:0x34] == native.info[0x2c:0x34], "changed native import span")
    require(len(verified.relocations()) == len(relocations), "invalid merged relocation stream")
    report.update(mode='lifecycle-loader-control', lifecycle=lifecycle, probe_state_offset=probe_offset,
                  output_memory=sum(s.memsz for s in segments), sha256=hashlib.sha256(output).hexdigest())
    return output, report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', required=True, type=Path)
    parser.add_argument('--payload', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--mode', choices=('inert', 'lifecycle', 'imports', 'tls'), default='inert')
    args = parser.parse_args()
    require(not args.output.exists() and not args.report.exists(), "output already exists")
    merge = {'inert': append_inert_payload, 'lifecycle': embed_lifecycle_probe,
             'imports': append_imported_payload, 'tls': embed_tls_payload}[args.mode]
    image, report = merge(Module.read(args.native), Module.read(args.payload))
    report['inputs'] = {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                        for p in (args.native, args.payload)}
    args.output.write_bytes(image)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
