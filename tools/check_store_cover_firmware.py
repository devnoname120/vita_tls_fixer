#!/usr/bin/env python3
"""Verify the Store-only artwork ABI against the supplied decrypted firmware."""
import argparse
import hashlib
import json
import re
from pathlib import Path
from firmware_matrix import Firmware

ROOT = Path(__file__).resolve().parents[1]
# IDA-audited export, Store decoder, common product, text and identity routines.
# Both families use a 224-byte output, ID pointer at +0x60 and image pointer at +0x78.
SPANS = {'official': [('0x81000b9e',
               '0x81000bca',
               '584f66dae40259f4f2726734ff189caf6cb625b567158f3be6294985ae6b1fb7'),
              ('0x8100f694',
               '0x8100f6ea',
               '014479c80010d70d2ef502bddb4256be38cdb45650f924adc94b8394888ba22c'),
              ('0x8100e3ba',
               '0x8100e54e',
               '766401e08d5dcf6ae566d2bfe623914755d623d7d6cebb8b0dc074bd4bf7ced5'),
              ('0x8100e0ba',
               '0x8100e3b8',
               '709529732082766b36e2fcb16850a5729b332be351fdea2d7d5568f3bcb25702'),
              ('0x8100dee0',
               '0x8100df90',
               '19dd71d41814d4f793dafc13b19500fe719cc9c0860c2a4d82c94752129663e5'),
              ('0x81000790',
               '0x810007bc',
               '1453afd827e4b9d3dac93e3f911067595bd68df08117b62da782b1f0cad45401'),
              ('0x8100e54e',
               '0x8100e5a4',
               '02cbae7d0dc59f437197b3e0d5a2308708f82040f03287065ae30f2d7e66ac0b')],
 'debug': [('0x81000c02', '0x81000c52', '4707eded88283654fb7c154daf19cd38f6a92133fa9afea5daec6e1406b564df'),
           ('0x8100f740', '0x8100f796', '9d329185aa99dc672e53b2aab62bfe7ad8bb2a3fac0d84c756c8b1b11ba5a5d8'),
           ('0x8100e466', '0x8100e5fa', '55b85f657ed34710854dfad13a576f25389bdf6f41517f02a5de8536ff764320'),
           ('0x8100e166', '0x8100e464', '7b66240f34627ac36fa7730a38469529f6af5211be62de68649f8fff52c7b5e9'),
           ('0x8100df8c', '0x8100e03c', '7fb87aff878027e1b5d4036545c3844b263ddbbb3586154ea4fee8cfd846b06b'),
           ('0x810007f4', '0x81000820', '6e2583fc789bfdccb73e0d84a050a68abdee6ade768018f0a4ea207b905c05c8'),
           ('0x8100e5fa',
            '0x8100e650',
            '0dfa43c6f9fd38fd02689ae5576085d8e79449c2289e40331409570b0cae7759')]}

def verify(root):
    supported = {int(x,16) for x in re.findall(r"UINT32_C\((0x[0-9a-f]+)\)",
                 (ROOT / "store_cover/firmware.h").read_text())}
    results = []
    for cell in json.loads((ROOT / "docs/firmware-compatibility.json").read_text())["verified"]:
        hardware, version = cell["hardware"], cell["firmware"]
        folder = root / hardware / version
        if not folder.exists():
            choices = list((root / hardware).glob(version + "*"))
            if len(choices) != 1:
                raise ValueError("Ambiguous or missing firmware: " + hardware + " " + version)
            folder = choices[0]
        module = Firmware(folder / "fs_dec/vs0/sys/external/np_commerce2.elf")
        if module.nid not in supported:
            raise ValueError("Unlisted Commerce module: " + hex(module.nid))
        family = "official" if hardware == "official" else "debug"
        for start, end, expected in SPANS[family]:
            a, b = int(start, 16), int(end, 16)
            if hashlib.sha256(module.read(a,b-a)).hexdigest() != expected:
                raise ValueError("Commerce ABI differs: " + hardware + " " + version + " " + start)
        if module.exports.get((0x40120dc3,0xf988a255)) != int(SPANS[family][0][0],16) + 1:
            raise ValueError("Store decoder export differs")
        if module.exports.get((0x40120dc3,0xec09ff89)) != int(SPANS[family][5][0],16) + 1:
            raise ValueError("Category decoder export differs")
        results.append({"hardware":hardware,"firmware":version,"commerce_nid":hex(module.nid)})
    if {int(r["commerce_nid"],16) for r in results} != supported:
        raise ValueError("Runtime allowlist contains an unaudited module")
    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("firmware_root", type=Path)
    args = parser.parse_args()
    print(json.dumps({"evidence":"static firmware ABI, not hardware execution", "verified":verify(args.firmware_root)}, indent=2))
