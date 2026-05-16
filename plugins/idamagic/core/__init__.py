"""Disassembler-agnostic core: state container, errors, models.

Modules in this package must NOT import from any disassembler SDK
(no ida_*, idc, idaapi, etc). That keeps them portable for the
planned Ghidra and Binary Ninja ports.
"""
