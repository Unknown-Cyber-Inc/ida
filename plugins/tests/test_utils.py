"""Tests for idamagic.core.utils."""
import unittest
from types import SimpleNamespace

from idamagic.core.utils import (
    create_proc_name,
    ea2str,
    sign_unsigned,
    str2ea,
    strip_parens,
    to_bool,
)


class TestToBool(unittest.TestCase):
    def test_truthy_strings(self):
        for s in ("1", "true", "True", "TRUE", "yes", "Y"):
            self.assertTrue(to_bool(s), f"to_bool({s!r}) should be True")

    def test_falsy_strings(self):
        for s in ("0", "false", "FALSE", "no", "N", ""):
            self.assertFalse(to_bool(s), f"to_bool({s!r}) should be False")

    def test_native_bools(self):
        self.assertTrue(to_bool(True))
        self.assertFalse(to_bool(False))

    def test_unknown_returns_default(self):
        # Spec: "If the param is not a known boolean value", return
        # the default.
        self.assertEqual(to_bool("maybe", default="unknown"), "unknown")
        self.assertIs(to_bool(object(), default=None), None)

    def test_default_defaults_to_false(self):
        self.assertFalse(to_bool("nonsense"))


class TestEaRoundTrip(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(ea2str(0), "0x0")
        self.assertEqual(ea2str(0x401000), "0x401000")
        # Spec promises lowercase hex digits.
        self.assertEqual(ea2str(0xDEADBEEF), "0xdeadbeef")

    def test_str2ea_inverse(self):
        for n in (0, 1, 0x401000, 0xDEADBEEFCAFE):
            self.assertEqual(str2ea(ea2str(n)), n)

    def test_str2ea_accepts_no_prefix(self):
        # int(x, 16) accepts both "0xabc" and "abc"
        self.assertEqual(str2ea("abc"), 0xABC)


class TestStripParens(unittest.TestCase):
    def test_removes_simple(self):
        self.assertEqual(strip_parens("foo(bar)baz"), "foobaz")

    def test_multiple_groups(self):
        self.assertEqual(strip_parens("a(1)b(2)c"), "abc")

    def test_no_parens(self):
        self.assertEqual(strip_parens("no parens here"), "no parens here")

    def test_empty(self):
        self.assertEqual(strip_parens(""), "")

    def test_nested_non_greedy(self):
        # The regex is non-greedy by virtue of [^)]*: it matches
        # everything except ')'. This means truly nested parens
        # produce an artifact. Documenting current behavior so we
        # notice if it ever changes.
        self.assertEqual(strip_parens("a(b(c)d)e"), "ad)e")


class TestSignUnsigned(unittest.TestCase):
    def test_positive_passes_through(self):
        self.assertEqual(sign_unsigned(0), 0)
        self.assertEqual(sign_unsigned(1), 1)
        self.assertEqual(sign_unsigned(0x7FFFFFFF), 0x7FFFFFFF)

    def test_32bit_sign_extension(self):
        # 0xFFFFFFFF has bit_length 32 → 32-bit cast → -1
        self.assertEqual(sign_unsigned(0xFFFFFFFF), -1)
        # 0x80000000: smallest negative for 32-bit
        self.assertEqual(sign_unsigned(0x80000000), -0x80000000)

    def test_64bit_sign_extension(self):
        # 0xFFFFFFFFFFFFFFFF → bit_length 64 → -1
        self.assertEqual(sign_unsigned(0xFFFFFFFFFFFFFFFF), -1)
        self.assertEqual(sign_unsigned(0x8000000000000000), -0x8000000000000000)

    def test_non_32_non_64_passes_through(self):
        # Anything not exactly 32 or 64 bits wide is treated as
        # positive (the spec says: "If the number of bits does not
        # exactly line up with one of the sizes, the number is
        # positive").
        self.assertEqual(sign_unsigned(0xFF), 0xFF)
        self.assertEqual(sign_unsigned(0xFFFF), 0xFFFF)

    def test_rejects_non_int(self):
        with self.assertRaises(AssertionError):
            sign_unsigned("0xff")  # type: ignore[arg-type]


class TestCreateProcName(unittest.TestCase):
    def test_with_name(self):
        proc = SimpleNamespace(start_ea="0x401000", procedure_name="main")
        self.assertEqual(create_proc_name(proc), "0x401000 - main")

    def test_without_name(self):
        # No procedure_name attribute → returns just the EA
        proc = SimpleNamespace(start_ea="0x401000")
        self.assertEqual(create_proc_name(proc), "0x401000")

    def test_empty_name(self):
        # procedure_name is present but falsy → returns just the EA.
        # This is the bug-prone case: if the API ever returned ""
        # for an unnamed proc, the old code would have printed
        # "0x401000 - " with an awkward trailing dash.
        proc = SimpleNamespace(start_ea="0x401000", procedure_name="")
        self.assertEqual(create_proc_name(proc), "0x401000")


if __name__ == "__main__":
    unittest.main()
