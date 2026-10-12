#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ValidationError(RuntimeError):
    pass


@dataclass(frozen=True)
class LoadSegment:
    offset: int
    virtual_address: int
    file_size: int
    memory_size: int
    flags: int


def read_descriptor(path: Path) -> dict[str, Any]:
    try:
        descriptor = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"cannot read descriptor {path}: {exc}") from exc

    if descriptor.get("schema_version") != 1:
        raise ValidationError("unsupported descriptor schema_version")
    if not isinstance(descriptor.get("hooks"), list) or not descriptor["hooks"]:
        raise ValidationError("descriptor has no hooks")
    return descriptor


def read_elf_segments(path: Path) -> tuple[bytes, LoadSegment, LoadSegment]:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ValidationError(f"cannot read ELF {path}: {exc}") from exc

    elf_header_format = "<16sHHIIIIIHHHHHH"
    elf_header_size = struct.calcsize(elf_header_format)
    if len(data) < elf_header_size:
        raise ValidationError("ELF is shorter than its header")

    (
        ident,
        elf_type,
        machine,
        version,
        _entry,
        program_offset,
        _section_offset,
        _flags,
        header_size,
        program_entry_size,
        program_count,
        _section_entry_size,
        _section_count,
        _section_name_index,
    ) = struct.unpack_from(elf_header_format, data, 0)

    if ident[:4] != b"\x7fELF" or ident[4] != 1 or ident[5] != 1:
        raise ValidationError("expected ELF32 little-endian input")
    if elf_type not in (2, 0xfe04):
        raise ValidationError(f"expected ELF type ET_EXEC or ET_SCE_RELEXEC, got {elf_type}")
    if machine != 40:
        raise ValidationError(f"expected ARM machine 40, got {machine}")
    if version != 1:
        raise ValidationError(f"unexpected ELF version {version}")
    if header_size != elf_header_size:
        raise ValidationError(
            f"unexpected ELF header size {header_size}, expected {elf_header_size}"
        )

    program_format = "<IIIIIIII"
    expected_program_size = struct.calcsize(program_format)
    if program_entry_size != expected_program_size:
        raise ValidationError(
            f"unexpected program-header size {program_entry_size}, "
            f"expected {expected_program_size}"
        )
    if program_offset > len(data) or program_count > (len(data) - program_offset) // program_entry_size:
        raise ValidationError("program-header table is out of bounds")

    executable_segments: list[LoadSegment] = []
    writable_segments: list[LoadSegment] = []
    for index in range(program_count):
        fields = struct.unpack_from(
            program_format,
            data,
            program_offset + index * program_entry_size,
        )
        program_type, offset, virtual_address, _physical_address, file_size, memory_size, flags, _align = fields
        if program_type == 1:
            if offset > len(data) or file_size > len(data) - offset:
                raise ValidationError(f"load segment {index} is out of bounds")
            segment = LoadSegment(
                offset=offset,
                virtual_address=virtual_address,
                file_size=file_size,
                memory_size=memory_size,
                flags=flags,
            )
            if (flags & 1) != 0:
                executable_segments.append(segment)
            if (flags & 2) != 0 and (flags & 1) == 0:
                writable_segments.append(segment)

    if len(executable_segments) != 1:
        raise ValidationError(
            f"expected one executable PT_LOAD segment, found {len(executable_segments)}"
        )
    if len(writable_segments) != 1:
        raise ValidationError(
            f"expected one writable non-executable PT_LOAD segment, found {len(writable_segments)}"
        )

    return data, executable_segments[0], writable_segments[0]


def decode_hook(hook: dict[str, Any]) -> tuple[str, int, bytes, str]:
    name = hook.get("name")
    offset = hook.get("offset")
    encoded_bytes = hook.get("bytes")
    mask = hook.get("mask")

    if not isinstance(name, str) or not name:
        raise ValidationError("hook has an invalid name")
    if not isinstance(offset, int) or offset < 0:
        raise ValidationError(f"hook {name}: invalid offset")
    if not isinstance(encoded_bytes, str):
        raise ValidationError(f"hook {name}: invalid bytes")
    if not isinstance(mask, str):
        raise ValidationError(f"hook {name}: invalid mask")

    try:
        pattern = bytes.fromhex(encoded_bytes)
    except ValueError as exc:
        raise ValidationError(f"hook {name}: malformed byte string") from exc

    if len(pattern) == 0 or len(pattern) != len(mask):
        raise ValidationError(
            f"hook {name}: byte/mask length mismatch ({len(pattern)} != {len(mask)})"
        )
    if set(mask) - {"x", "?"}:
        raise ValidationError(f"hook {name}: mask contains characters other than x and ?")

    return name, offset, pattern, mask


def masked_match(data: bytes, offset: int, pattern: bytes, mask: str) -> bool:
    if offset < 0 or offset > len(data) or len(pattern) > len(data) - offset:
        return False
    return all(
        mask[index] == "?" or data[offset + index] == pattern[index]
        for index in range(len(pattern))
    )


def masked_occurrences(data: bytes, pattern: bytes, mask: str) -> list[int]:
    if len(pattern) > len(data):
        return []
    return [
        offset
        for offset in range(len(data) - len(pattern) + 1)
        if masked_match(data, offset, pattern, mask)
    ]


def validate_elf(descriptor: dict[str, Any], elf_path: Path) -> None:
    data, text_segment, data_segment = read_elf_segments(elf_path)
    text = data[
        text_segment.offset : text_segment.offset + text_segment.file_size
    ]
    expected_file_size = descriptor.get("text_filesz")
    expected_memory_size = descriptor.get("text_memsz")
    expected_data_file_size = descriptor.get("data_filesz")
    expected_data_memory_size = descriptor.get("data_memsz")

    if text_segment.file_size != expected_file_size:
        raise ValidationError(
            f"text file size mismatch: 0x{text_segment.file_size:X} != 0x{expected_file_size:X}"
        )
    if text_segment.memory_size != expected_memory_size:
        raise ValidationError(
            f"text memory size mismatch: 0x{text_segment.memory_size:X} != 0x{expected_memory_size:X}"
        )
    if data_segment.file_size != expected_data_file_size:
        raise ValidationError(
            f"data file size mismatch: 0x{data_segment.file_size:X} != 0x{expected_data_file_size:X}"
        )
    if data_segment.memory_size != expected_data_memory_size:
        raise ValidationError(
            f"data memory size mismatch: 0x{data_segment.memory_size:X} != 0x{expected_data_memory_size:X}"
        )

    for raw_hook in descriptor["hooks"]:
        name, offset, pattern, mask = decode_hook(raw_hook)
        if not masked_match(text, offset, pattern, mask):
            raise ValidationError(f"hook {name}: signature mismatch at module offset 0x{offset:X}")
        occurrences = masked_occurrences(text, pattern, mask)
        if occurrences != [offset]:
            formatted = ", ".join(f"0x{item:X}" for item in occurrences) or "none"
            raise ValidationError(
                f"hook {name}: signature is not unique at expected offset 0x{offset:X}; "
                f"matches: {formatted}"
            )


def validate_self(descriptor: dict[str, Any], self_path: Path) -> None:
    try:
        digest = hashlib.sha256(self_path.read_bytes()).hexdigest()
    except OSError as exc:
        raise ValidationError(f"cannot read SELF {self_path}: {exc}") from exc

    expected = descriptor.get("compressed_sha256")
    if digest != expected:
        raise ValidationError(f"SELF SHA-256 mismatch: {digest} != {expected}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate an exact tls_fixer TLS module boundary"
    )
    parser.add_argument("--descriptor", type=Path, required=True)
    parser.add_argument("--elf", type=Path, required=True)
    parser.add_argument("--self", dest="self_path", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        descriptor = read_descriptor(args.descriptor)
        validate_elf(descriptor, args.elf)
        if args.self_path is not None:
            validate_self(descriptor, args.self_path)
    except ValidationError as exc:
        print(f"unsupported libhttp: {exc}", file=sys.stderr)
        return 1

    print(f"supported {descriptor.get('module_name', 'module')}: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
