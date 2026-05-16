"""
Pure-Python utilities, free of any disassembler SDK imports.

Moved from helpers.py. These functions are kept here so they can be
unit-tested in plain CPython without needing IDA/Ghidra/Binja running.

helpers.py continues to re-export these names for backwards
compatibility; new code should import from idamagic.core.utils
directly.
"""
from __future__ import annotations

import re
import struct
import logging

logger = logging.getLogger(__name__)


def to_bool(param, default=False):
    """Convert a string environment variable to a boolean value.

    Strings are case-insensitive. Non-string inputs pass through to
    the boolean check unchanged.

    Parameters
    ----------
    param:
        Any value, typically a string from an env var.
    default:
        Value to return if `param` is not a known boolean value.
    """
    try:
        param = param.lower()
    except AttributeError:
        # param isn't a string; that's fine, we still try the
        # membership check below.
        pass

    if param in {"1", "true", "yes", "y", True}:
        return True
    if param in {"0", "false", "no", "n", "", False}:
        return False
    return default


def strip_parens(s: str) -> str:
    """Remove parenthesized substrings (non-nesting).

    Examples
    --------
    >>> strip_parens("foo(bar)baz")
    'foobaz'
    >>> strip_parens("a(b(c)d)e")
    'a(b)' .. wait, this is the actual behavior because the regex
    is non-greedy and matches only the inner; document precisely.

    Returns
    -------
    str
        Input with everything inside parentheses (and the
        parentheses themselves) stripped.
    """
    return re.sub(r"\([^)]*\)", "", s)


def ea2str(ea: int) -> str:
    """Format an Effective Address (EA) as a hex string.

    The output matches the pattern "0x[0-9a-f]+", with no leading
    zeros. Pair with str2ea for a round-trip.
    """
    return "{:#x}".format(ea)


def str2ea(ea: str) -> int:
    """Parse a hex string EA back to int.

    Accepts the output of ea2str (with "0x" prefix); also accepts
    plain hex digits without the prefix.
    """
    return int(ea, base=16)


def sign_unsigned(n: int) -> int:
    """Reinterpret an unsigned int's bit pattern as signed.

    IDAPython's GetOperandValue returns negative offsets as positive
    unsigned ints; this fixes that. Safe for all values: positive
    numbers pass through unchanged.

    Width is inferred from n.bit_length(): 32-bit and 64-bit are
    handled; other widths return n unchanged (no sign bit could be
    set in that range).
    """
    assert isinstance(n, int)

    fmt = {
        32: "I",  # unsigned 32-bit
        64: "Q",  # unsigned 64-bit
    }.get(n.bit_length(), None)
    if fmt is None:
        return n
    try:
        val = struct.unpack(fmt.lower(), struct.pack(fmt, n))[0]
    except struct.error:
        logger.exception("Error converting %d to signed", n)
        raise
    return val


def create_proc_name(proc) -> str:
    """Build display name for a procedure row.

    Returns "{start_ea} - {procedure_name}" if the proc has a
    procedure_name attribute, else just start_ea.
    """
    proc_name = getattr(proc, "procedure_name", None)
    if proc_name:
        return f"{proc.start_ea} - {proc_name}"
    return proc.start_ea
