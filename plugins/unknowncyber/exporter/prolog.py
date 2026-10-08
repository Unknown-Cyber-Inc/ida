"""Instruction → Prolog term formatting.

This is the wire format the Unknown Cyber genomics pipeline expects for IDA
disassembly uploads.  The logic is a faithful port of the original
implementation (operand classification, SIB parsing, sign handling and quote
escaping) with the IDA < 7.4 compatibility shims removed and the ``sark``
dependency isolated to this module.

The formatting *reads* operand display state that
:mod:`unknowncyber.exporter.disassembly` sets up (hex display for all
operands, decimal display for memory operands), so it must only be used from
there.
"""

from __future__ import annotations

import logging
import re
import struct
from typing import Dict, Optional

import ida_ida
import ida_idp
import ida_nalt
import ida_name
import ida_ua
import idaapi
import idautils
import idc

_log = logging.getLogger(__name__)

try:
    import sark  # type: ignore
except ImportError as exc:  # pragma: no cover - reported by the UI
    sark = None  # type: ignore
    _IMPORT_ERROR = exc
else:
    _IMPORT_ERROR = None


def require_sark() -> None:
    if sark is None:
        raise ImportError(
            f"The 'sark' package is required for disassembly export. Install it with the plugin's requirements.txt ({_IMPORT_ERROR})."
        )


FP_OPND = 11  # Floating point (ST) register; sark has no alias for it.

# Registers whose automatic renaming is removed before export so that operand
# text matches what the backend expects.
REGISTER_NAMES = (
    "eax ecx edx ebx esp ebp esi edi al cl dl bl ah ch dh bh es cs ss ds fs gs "
    "efl ctrl stat tags mm0 mm1 mm2 mm3 mm4 mm5 mm6 mm7 "
    "xmm0 xmm1 xmm2 xmm3 xmm4 xmm5 xmm6 xmm7 xmm8 xmm9 xmm10 xmm11 xmm12 xmm13 xmm14 xmm15 "
    "mxcsr ax cx dx bx"
).split()

_PARENS_RE = re.compile(r"\(.*\)")
_ST_RE = re.compile(r"st\(([1-7])\)")


# --------------------------------------------------------------------------
# Name helpers
# --------------------------------------------------------------------------


def demangle(name: str, disable_mask: Optional[int] = None) -> str:
    if not name:
        return name
    if disable_mask is None:
        disable_mask = _short_demnames()
    demangled = ida_name.demangle_name(name, disable_mask, ida_name.DQT_FULL)
    return demangled or name


def _short_demnames() -> int:
    getter = getattr(ida_ida, "inf_get_short_demnames", None)
    if getter is not None:
        return getter()
    return idc.get_inf_attr(idc.INF_SHORT_DEMNAMES)  # IDA 8.x


def processor_name() -> str:
    getter = getattr(ida_ida, "inf_get_procname", None)
    if getter is not None:
        return getter()
    return idaapi.get_inf_structure().procname  # IDA 8.x


def strip_parens(text: str) -> str:
    return _PARENS_RE.sub("", text)


def function_name(ea: int) -> str:
    return strip_parens(demangle(idc.get_func_name(ea)))


# --------------------------------------------------------------------------
# Imports (RVA -> API name)
# --------------------------------------------------------------------------


class Imports(dict):
    """Mapping of import RVA -> demangled API name, built once per export."""

    def __init__(self, image_base: int):
        super().__init__()
        self._image_base = image_base
        self._module: Optional[str] = None
        for i in range(idaapi.get_import_module_qty()):
            self._module = idaapi.get_import_module_name(i)
            if not self._module:
                continue
            idaapi.enum_import_names(i, self._visit)
        self._module = None

    def _visit(self, ea, name, ordinal):
        if name:
            self[ea - self._image_base] = strip_parens(demangle(name))
        return True


# --------------------------------------------------------------------------
# Operand helpers
# --------------------------------------------------------------------------


def dtype2ptr(dtype: int) -> str:
    mapping: Dict[int, str] = {
        ida_ua.dt_byte: "bptr",
        ida_ua.dt_word: "wptr",
        ida_ua.dt_dword: "dptr",
        ida_ua.dt_float: "dptr",
        ida_ua.dt_fword: "fwptr",
        ida_ua.dt_qword: "qptr",
        ida_ua.dt_byte16: "b16ptr",
        ida_ua.dt_byte32: "b32ptr",
        ida_ua.dt_byte64: "b64ptr",
        ida_ua.dt_tbyte: "tbptr",
        ida_ua.dt_string: "strptr",
        ida_ua.dt_unicode: "uniptr",
        ida_ua.dt_void: "voidptr",
        ida_ua.dt_bitfild: "bfldptr",
        ida_ua.dt_code: "codeptr",
        ida_ua.dt_packreal: "packptr",
        ida_ua.dt_ldbl: "ldblptr",
    }
    return mapping.get(dtype, "none")


def sign_unsigned(n: int) -> int:
    """Reinterpret a 32/64-bit unsigned value as signed (IDA reports negative offsets unsigned)."""
    fmt = {32: "I", 64: "Q"}.get(n.bit_length())
    if fmt is None:
        return n
    return struct.unpack(fmt.lower(), struct.pack(fmt, n))[0]


def parse_sib(op_t):
    """Base, index, scale for ``o_mem`` operands with a SIB byte (x86 only)."""
    if ida_idp.get_idp_name() != "pc" and op_t.type == idaapi.o_mem:
        return None, None, None
    if not op_t.specflag1:
        return None, None, None
    sib = op_t.specflag2 & 0xFF
    base = sib & 0b111
    index = (sib >> 3) & 0b111
    scale = 2 ** (sib >> 6)
    return sark.get_register_name(base), sark.get_register_name(index), scale


def set_operand_display(ea: int, op_n: int = -1, display: str = "hex") -> None:
    if display == "hex":
        idc.op_hex(ea, op_n)
    elif display == "dec":
        idc.op_dec(ea, op_n)


def api_call_name(instruction, imports: Imports) -> Optional[str]:
    if not (instruction.insn.is_call or instruction.insn.mnem == "jmp"):
        return None
    for xref in instruction.xrefs_from:
        if xref.type.is_call or xref.type.is_jump:
            return imports.get(xref.to)
    return None


def api_calls(function, imports: Imports):
    for xref in function.xrefs_from:
        if (xref.type.is_call or xref.type.is_jump) and xref.to in imports:
            yield imports[xref.to]


def _format_operand(op, line_ea: int) -> Optional[str]:
    if op.type.is_reg:
        if op.dtype == 0:
            return sark.get_register_name(op.reg_id, 1)
        try:
            return op.reg
        except KeyError:
            return op.text

    if op.type.is_mem:
        set_operand_display(line_ea, op.n, "dec")
        address = ""
        text = op.text
        if re.match(r".*fs:.*", text):
            address += "fs+"
        elif re.match(r".*qs:.*", text):
            address += "qs+"
        elif re.match(r".*ds:.*", text):
            address += "ds+"
        base, index, scale = parse_sib(op.op_t)
        offset = sign_unsigned(op.offset)
        if base is not None:
            base = "" if base == "ebp" else base + "+"
            address += base + index + "*" + str(scale) + "{:+d}".format(offset)
        elif text.startswith("["):
            address += text.strip("][")
        else:
            address += "{:d}".format(op.offset)
        return "{}({})".format(dtype2ptr(op.dtype), address)

    if op.type.is_phrase or op.type.is_displ:
        set_operand_display(line_ea, op.n, "dec")
        addr_expr = op.reg
        if addr_expr is None:
            addr_expr = "pc"
        if op.index:
            addr_expr += "+{}*{}".format(op.index, op.scale)
        if op.offset:
            addr_expr += "{:+d}".format(sign_unsigned(op.offset))
        return "{}({})".format(dtype2ptr(op.dtype), addr_expr)

    if op.type.is_imm or op.type.is_far or op.type.is_near:
        return str(sign_unsigned(idc.get_operand_value(line_ea, op.n)))

    if op.type.type == FP_OPND:
        if processor_name().lower() == "metapc":
            opnd = idc.print_operand(line_ea, op.n)
            if opnd == "st":
                return "st0"
            match = _ST_RE.match(opnd)
            return "st" + match.group(1) if match else None
        return None

    if op.type.name == "Processor_specific_type":
        return "'{}'".format(op.text)
    return None


def _escape(formatted: str) -> str:
    """Escape inner quotes/backslashes so the term is valid Prolog."""
    broken = formatted.split("'")
    if len(broken) > 1:
        formatted = "\\\\".join(formatted.split("\\"))
        broken = formatted.split("'")
    if len(broken) > 3:
        inner = broken[1:-1]
        formatted = "'{}'".format("\\'".join(inner))
    return formatted


def format_instruction(instruction, line_ea: int) -> Optional[str]:
    """``mov eax, [ebx+4]`` → ``mov(eax,dptr(ebx+4))``; ``None`` if an operand is unsupported."""
    formatted = []
    for op in instruction.operands:
        if op.type.type == FP_OPND and idc.print_operand(line_ea, op.n) == "":
            continue  # fldz/fstp/… have empty FP operands
        if op.type.is_void:
            _log.error("void operand in instruction at %#x", line_ea)
            continue
        text = _format_operand(op, line_ea)
        if text is None:
            _log.warning(
                "unsupported operand %d (type %s) in %r at %#x",
                op.n,
                op.type,
                sark.Line(line_ea).disasm,
                line_ea,
            )
            return None
        formatted.append(_escape(text))
    operands = "({})".format(",".join(formatted)) if formatted else ""
    return "{}{}".format(instruction.mnem, operands).lower()


def strings_for(function):
    """Strings referenced from *function* (currently unused by the backend)."""
    for xref in function.xrefs_from:
        try:
            text = sark.get_string(xref.to)
        except sark.exceptions.SarkNoString:
            continue
        if isinstance(text, bytes):
            text = text.decode("utf-8", "replace")
        if len(text) >= 3:
            yield text


def mark_missed_procedures() -> int:
    """Turn ``push ebp; mov ebp, esp`` sequences outside functions into functions.

    Returns the number of functions created.  Only runs inside the export's
    undo point, so the change never persists.
    """
    created = 0
    saw_push = False
    last_ea = None
    for ea in idautils.Heads():
        try:
            sark.get_func(ea)
            saw_push = False
            continue
        except sark.exceptions.SarkNoFunction:
            pass
        dis = idc.GetDisasm(ea)
        if dis == "push    ebp":
            saw_push = True
            last_ea = ea
            continue
        if saw_push and dis == "mov     ebp, esp" and last_ea is not None:
            if idaapi.add_func(last_ea):
                created += 1
        saw_push = False
    return created


def remove_register_renamings(func_t) -> None:
    for reg in REGISTER_NAMES:
        idaapi.del_regvar(func_t, func_t.start_ea, func_t.end_ea, reg)


def input_root_filename() -> str:
    return ida_nalt.get_root_filename() or ""
