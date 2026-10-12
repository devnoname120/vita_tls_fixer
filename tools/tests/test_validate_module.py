import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("validate_libhttp", Path(__file__).parents[1] / "validate_libhttp.py")
validator = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = validator
spec.loader.exec_module(validator)


class ModuleValidatorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "module.elf"
        self.text = bytearray(256)
        self.text[32:38] = b"ABCDEF"
        self.descriptor = {"schema_version": 1, "module_name": "test", "text_filesz": 256,
                           "text_memsz": 272, "data_filesz": 32, "data_memsz": 64,
                           "hooks": [{"name": "connect", "offset": 32, "bytes": "414243444546", "mask": "xx??xx"}]}

    def tearDown(self):
        self.temporary.cleanup()

    def write_elf(self, elf_type=2):
        data = bytearray(512 + 256 + 32)
        ident = b"\x7fELF\x01\x01\x01" + bytes(9)
        struct.pack_into("<16sHHIIIIIHHHHHH", data, 0, ident, elf_type, 40, 1, 0,
                         52, 0, 0, 52, 32, 2, 0, 0, 0)
        struct.pack_into("<8I", data, 52, 1, 512, 0x81000000, 0, 256, 272, 5, 16)
        struct.pack_into("<8I", data, 84, 1, 768, 0x81400000, 0, 32, 64, 6, 16)
        data[512:768] = self.text
        self.path.write_bytes(data)

    def test_exec_and_sony_relexec(self):
        for kind in (2, 0xfe04):
            self.write_elf(kind)
            validator.validate_elf(self.descriptor, self.path)

    def test_changed_invariant_rejected_by_name(self):
        self.text[32] ^= 1
        self.write_elf()
        with self.assertRaisesRegex(validator.ValidationError, "hook connect: signature mismatch"):
            validator.validate_elf(self.descriptor, self.path)

    def test_relocation_bytes_ignored(self):
        self.text[34:36] = b"xy"
        self.write_elf()
        validator.validate_elf(self.descriptor, self.path)

    def test_ambiguous_signature_rejected(self):
        self.text[80:86] = b"ABCDEF"
        self.write_elf()
        with self.assertRaisesRegex(validator.ValidationError, "not unique"):
            validator.validate_elf(self.descriptor, self.path)

    def test_occurrence_search_matches_reference(self):
        data = b"xxABcDEyyABdDEzzABcDF"
        pattern, mask = b"ABcDE", "xx?xx"
        expected = [i for i in range(len(data)) if validator.masked_match(data, i, pattern, mask)]
        self.assertEqual(validator.masked_occurrences(data, pattern, mask), expected)

    def test_default_browser_descriptor_shapes(self):
        descriptor = validator.read_descriptor(Path(__file__).parents[2] / "tls13/supported_browser.json")
        self.assertEqual(descriptor["module_name"], "ScePsp2Compat")
        self.assertEqual(len(descriptor["hooks"]), 6)
        for hook in descriptor["hooks"]:
            validator.decode_hook(hook)


if __name__ == "__main__":
    unittest.main()
