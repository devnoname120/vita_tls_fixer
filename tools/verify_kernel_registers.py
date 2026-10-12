#!/usr/bin/env python3

import argparse
from pathlib import Path
import re
import subprocess
import sys


def find_unmanaged_fp(disassembly: str) -> list[str]:
    instruction = re.compile(r"^\s*[0-9a-f]+:\s+([a-z][a-z0-9.]*)(?:\s+(.*))?$", re.IGNORECASE)
    coprocessor = re.compile(r"p?(?:10|11|0xa|0xb)\s*(?:,|$)", re.IGNORECASE)
    found = []
    count = 0
    for line in disassembly.splitlines():
        match = instruction.match(line)
        if match is None:
            continue
        count += 1
        mnemonic = match[1].lower()
        operands = match[2] or ""
        if (mnemonic.startswith(("v", "f")) or
                (mnemonic.startswith(("mcr", "mrc", "ldc", "stc", "cdp")) and coprocessor.match(operands)) or
                "undefined" in operands.lower() or mnemonic == "udf"):
            found.append(line.strip())
    if count == 0:
        raise ValueError("no executable instructions found; cannot validate kernel register use")
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description="Reject unmanaged FP/SIMD in the tls_fixer kernel executable")
    parser.add_argument("elf", type=Path)
    parser.add_argument("--objdump", default="arm-vita-eabi-objdump")
    arguments = parser.parse_args()
    try:
        result = subprocess.run([arguments.objdump, "-d", "--no-show-raw-insn", "--", str(arguments.elf)],
                                check=True, capture_output=True, text=True, timeout=30)
        invalid = find_unmanaged_fp(result.stdout)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"kernel register check failed: {error}", file=sys.stderr)
        return 1
    if invalid:
        print(f"kernel register check rejected {len(invalid)} instructions:", file=sys.stderr)
        print("\n".join(invalid[:20]), file=sys.stderr)
        return 1
    print("kernel register check: no decoded FP/SIMD instructions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
