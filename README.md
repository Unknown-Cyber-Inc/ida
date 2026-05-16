# idamagic

An IDA Pro plugin that integrates with the UnknownCyber MAGIC
genomics service.

## Install (into IDA)

This package is loaded as an IDA plugin. Copy or symlink the
`idamagic` directory and `magic_plugin_entry.py` into your IDA
plugins folder (typically `~/.idapro/plugins/` on Linux/macOS or
`%APPDATA%\Hex-Rays\IDA Pro\plugins\` on Windows).

Configuration: create a `.env` file inside the `idamagic` directory
with:

    MAGIC_API_KEY=your-api-key
    MAGIC_API_HOST=https://api.magic.unknowncyber.com

Hotkey: `Ctrl-Shift-A`.

## Install (for development / testing)

The `core` and `core.utils` modules are pure Python and can be
worked on without IDA running. To set up a dev environment:

    cd plugins
    python -m venv .venv
    source .venv/bin/activate
    pip install -e .[dev]

Then run the test suite:

    pytest

or, without pytest:

    python -m unittest discover -s tests -v

All 34 tests pass in plain CPython 3.7+; IDA is not required.

## Layout

    plugins/
    ├── magic_plugin_entry.py      ← IDA loads this
    ├── pyproject.toml             ← packaging metadata
    ├── requirements.txt           ← runtime deps for non-pip-toml use
    └── idamagic/
        ├── __init__.py            ← plugin_t (lazy-loaded)
        ├── api.py                 ← MAGIC API wrappers
        ├── helpers.py             ← IDA-specific helpers (legacy)
        ├── hooks.py               ← IDA UI hooks
        ├── layouts.py             ← Qt layout containers
        ├── qt_compat.py           ← PyQt5 / PySide6 shim
        ├── core/                  ← host-agnostic code
        │   ├── async_api.py
        │   ├── context.py
        │   ├── enums.py
        │   ├── errors.py
        │   ├── host.py            ← DisassemblerHost ABC
        │   └── utils.py           ← pure-Python utilities
        ├── ida/                   ← IDA SDK adapter
        │   └── host.py            ← IDAHost (concrete)
        ├── IDA_interface/
        ├── main_interface/
        ├── unknowncyber_interface/
        └── widgets/

For the planned Ghidra and Binary Ninja ports, the plan is to add
sibling packages `idamagic/ghidra/` and `idamagic/binja/` with their
own `host.py` implementing `DisassemblerHost`. Widgets, the API
client, and the data flow stay the same.

## Dependencies

Runtime dependencies (see `pyproject.toml` for versions):
- `cythereal_magic` — the MAGIC SDK
- `python-dotenv` — reads `.env`
- `networkx` — used by the binary parser's flow-graph builder
- `six` — one legacy callsite uses `six.iteritems`

Not listed (intentionally):
- `PyQt5` / `PySide6` — provided by IDA's bundled Python
- `sark` — install separately following Hex-Rays / sark's
  instructions
- IDA SDK modules (`ida_kernwin`, `idc`, etc) — provided by IDA
