#!/usr/bin/env python3
"""Reject accidental full-libc or PAF imports in HTTP TLS runtimes."""
import argparse
import struct
from pathlib import Path
from firmware_matrix import bundled_module

SCE_LIBC = 0xBE43BB07
SCE_LIBKERNEL = 0xCAE9ACE6
SCE_SYSMEM = 0x37FE725A
TLS_FIXER_REDIRECTS = 0x0A106567
ALLOWED = {TLS_FIXER_REDIRECTS, 0x203D1A28, SCE_SYSMEM, 0x6704D3C6, 0x6BF8B2A2, 0x859A24B1,
           SCE_LIBKERNEL, 0xEAED1616, 0xF2FF276E, 0xF9AC7CF8, 0x8AF17416}

def import_libraries(module):
    # Include variable-only libraries, which would disappear from a function-NID list.
    begin, end = struct.unpack_from('<II', module.info, 0x2c)
    libraries = {}
    while begin < end:
        size = struct.unpack_from('<H', module.text, begin)[0]
        if size not in (0x24, 0x34):
            raise SystemExit('Unknown import record size')
        library = struct.unpack_from('<I', module.text, begin + (16 if size == 0x34 else 12))[0]
        libraries[library] = struct.unpack_from('<H', module.text, begin + 4)[0]
        begin += size
    if begin != end:
        raise SystemExit('Import table span mismatch')
    return libraries


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("provider", type=Path)
    parser.add_argument("--native-http", type=Path,
                        help="Original Sony HTTP input when auditing an augmented SceLibHttp")
    args = parser.parse_args()
    module = bundled_module(args.provider)
    allowed = ALLOWED
    if args.native_http is not None:
        native = bundled_module(args.native_http)
        if module.name != "SceLibHttp" or native.name != "SceLibHttp":
            raise SystemExit("Augmented HTTP audit requires paired SceLibHttp modules")
        allowed = allowed | import_libraries(native).keys()
    elif module.name != "tls_fixer_http":
        raise SystemExit("Expected the HTTP provider, got " + module.name)
    imports = import_libraries(module)
    libraries = imports.keys()
    if SCE_LIBC in libraries:
        raise SystemExit("HTTP provider imports SceLibc; runtime wrappers are incomplete")
    if SCE_LIBKERNEL not in libraries or SCE_SYSMEM not in libraries:
        raise SystemExit("HTTP provider is missing its native runtime foundation")
    if libraries - allowed:
        raise SystemExit('Unexpected runtime libraries: ' + str([hex(x) for x in libraries - allowed]))
    redirect_functions = {nid for (library, nid) in module.imports if library == TLS_FIXER_REDIRECTS}
    if redirect_functions != {0x9462927F}:
        raise SystemExit("Unexpected tls_fixer redirect syscall imports")
    if args.native_http is not None and not imports[TLS_FIXER_REDIRECTS] & 0x0008:
        raise SystemExit("Augmented HTTP redirect-reader import must remain weak")
    print("HTTP runtime imports: SceLibKernel/SceSysmem present, SceLibc absent")

if __name__ == "__main__":
    main()
