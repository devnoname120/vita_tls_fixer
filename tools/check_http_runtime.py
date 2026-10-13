#!/usr/bin/env python3
"""Reject accidental full-libc or PAF imports in the independent HTTP provider."""
import argparse
import struct
from pathlib import Path
from firmware_matrix import bundled_module

SCE_LIBC = 0xBE43BB07
SCE_LIBKERNEL = 0xCAE9ACE6
SCE_SYSMEM = 0x37FE725A
ALLOWED = {0x203D1A28, SCE_SYSMEM, 0x6704D3C6, 0x6BF8B2A2, 0x859A24B1,
           SCE_LIBKERNEL, 0xEAED1616, 0xF2FF276E, 0xF9AC7CF8}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("provider", type=Path)
    args = parser.parse_args()
    module = bundled_module(args.provider)
    if module.name != "tls_fixer_http":
        raise SystemExit("Expected the HTTP provider, got " + module.name)
    # Include variable-only libraries, which would disappear from a function-NID list.
    begin, end = struct.unpack_from('<II', module.info, 0x2c)
    libraries = set()
    while begin < end:
        size = struct.unpack_from('<H', module.text, begin)[0]
        if size not in (0x24, 0x34):
            raise SystemExit('Unknown import record size')
        libraries.add(struct.unpack_from('<I', module.text, begin + (16 if size == 0x34 else 12))[0])
        begin += size
    if begin != end:
        raise SystemExit('Import table span mismatch')
    if SCE_LIBC in libraries:
        raise SystemExit("HTTP provider imports SceLibc; runtime wrappers are incomplete")
    if SCE_LIBKERNEL not in libraries or SCE_SYSMEM not in libraries:
        raise SystemExit("HTTP provider is missing its native runtime foundation")
    if libraries - ALLOWED:
        raise SystemExit('Unexpected runtime libraries: ' + str([hex(x) for x in libraries - ALLOWED]))
    print("HTTP runtime imports: SceLibKernel/SceSysmem present, SceLibc absent")

if __name__ == "__main__":
    main()
