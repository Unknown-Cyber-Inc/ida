# Tests

Pure-Python tests for the parts of `idamagic` that don't depend on
a host disassembler. Designed to run in plain CPython, no IDA / Ghidra
/ Binary Ninja required.

## Run

From the `plugins/` directory:

```
python -m pytest tests/ -v
```

or, if pytest isn't installed, with the stdlib unittest runner:

```
python -m unittest discover -s tests -v
```

## What's covered

- `idamagic.core.utils`: pure Python helpers (`to_bool`, `ea2str`,
  `str2ea`, `strip_parens`, `sign_unsigned`, `create_proc_name`).
- `idamagic.core.enums`: `ItemType.from_string` round-trip and the
  trailing-whitespace defensive strip.
- `idamagic.core.context`: `PluginContext` mutation helpers.

## What's *not* covered (and why)

Anything in `idamagic.ida.*` or `idamagic.helpers.py` that imports
IDA SDKs won't load under plain CPython. Test those in IDA's own
Python console, or behind a mock layer. The point of the
`core/utils.py` split is to make the non-SDK code testable as a
first step; SDK-dependent code can follow later behind the
`DisassemblerHost` interface (mock the host, exercise the widgets).
