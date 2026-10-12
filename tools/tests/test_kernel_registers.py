import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location(
    "verify_kernel_registers", Path(__file__).resolve().parents[1] / "verify_kernel_registers.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class KernelRegisterTests(unittest.TestCase):
    def test_rejects_vfp_neon_and_coprocessor_aliases(self):
        instructions = ["vldr d16, [r3, #16]", "vstr d16, [sp, #48]", "vld1.64 {d16-d17}, [r0]",
                        "vmov.i32 q10, #16", "vpush {d8-d9}", "mcr p10, 7, r0, cr1, cr0, 0",
                        "mrc 11, 0, r0, cr0, cr0, 0", "ldc p10, cr0, [r0]", "mcrr p11, 0, r0, r1, cr0"]
        for instruction in instructions:
            with self.subTest(instruction=instruction):
                text = f"81000000 <function>:\n 81000000:\t{instruction}\n"
                self.assertEqual(len(module.find_unmanaged_fp(text)), 1)

    def test_allows_integer_code_not_vector_symbol_names(self):
        text = "81000000 <vector_handler>:\n 81000000:\tmov r0, #0\n 81000004:\tbx lr\n"
        self.assertEqual(module.find_unmanaged_fp(text), [])

    def test_rejects_empty_or_unreadable_disassembly(self):
        for text in ["", "file format elf32-littlearm\n", "81000000:\t.word 0x12345678\n"]:
            with self.subTest(text=text), self.assertRaises(ValueError):
                module.find_unmanaged_fp(text)

    def test_allows_system_coprocessor(self):
        self.assertEqual(module.find_unmanaged_fp("81000000:\tmrc 15, 0, r0, cr13, cr0, 3\n"), [])


if __name__ == "__main__":
    unittest.main()
