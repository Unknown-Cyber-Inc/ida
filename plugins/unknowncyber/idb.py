"""Read-only helpers for the database currently open in IDA.

Everything here must be called on IDA's main thread (see
:func:`unknowncyber.workers.on_main_thread`).  The only function that writes to
disk is :func:`save_database_copy`, which writes a *copy* of the database and
leaves the open database untouched.
"""

from __future__ import annotations

import dataclasses
import hashlib
import logging
import os
from typing import Callable, Dict, Optional

_log = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class LoadedFile:
    """Identity of the file open in IDA."""

    name: str
    path: str
    md5: str
    sha256: str
    idb_path: str
    image_base: int
    arch_bits: Optional[int]
    file_type: str

    @property
    def binary_exists(self) -> bool:
        return bool(self.path) and os.path.isfile(self.path)


def loaded_file() -> LoadedFile:
    import ida_loader
    import ida_nalt

    md5 = _hexdigest(ida_nalt.retrieve_input_file_md5())
    sha256 = _hexdigest(ida_nalt.retrieve_input_file_sha256())
    return LoadedFile(
        name=ida_nalt.get_root_filename() or "",
        path=ida_nalt.get_input_file_path() or "",
        md5=md5,
        sha256=sha256,
        idb_path=ida_loader.get_path(ida_loader.PATH_TYPE_IDB) or "",
        image_base=int(ida_nalt.get_imagebase()),
        arch_bits=arch_bits(),
        file_type=ida_loader.get_file_type_name() or "",
    )


def _hexdigest(value) -> str:
    if value is None:
        return ""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    return str(value).lower()


def arch_bits() -> Optional[int]:
    """64 / 32 / None.  Works on IDA 8.x and 9.x (``inf_*`` getters first, ``inf_structure`` fallback)."""
    try:
        import ida_ida

        if ida_ida.inf_is_64bit():
            return 64
        is32 = getattr(ida_ida, "inf_is_32bit_exactly", None) or getattr(ida_ida, "inf_is_32bit", None)
        if is32 is not None:
            return 32 if is32() else None
    except (ImportError, AttributeError):
        pass
    try:  # IDA 8.x and earlier
        import idaapi

        info = idaapi.get_inf_structure()
        if info.is_64bit():
            return 64
        return 32 if info.is_32bit() else None
    except Exception:  # noqa: BLE001
        return None


def kernel_version() -> str:
    import ida_kernwin

    return ida_kernwin.get_kernel_version()


def image_base() -> int:
    import ida_nalt

    return int(ida_nalt.get_imagebase())


def jump_to(ea: int) -> bool:
    import ida_kernwin

    return bool(ida_kernwin.jumpto(int(ea)))


def function_start(ea: int) -> Optional[int]:
    """Start address of the function containing *ea*, if any."""
    import ida_funcs

    func = ida_funcs.get_func(int(ea))
    return int(func.start_ea) if func else None


def current_ea() -> int:
    import ida_kernwin

    return int(ida_kernwin.get_screen_ea())


# --------------------------------------------------------------------------
# Hashing
# --------------------------------------------------------------------------


def hash_file(path: str, algorithms=("sha1", "sha512")) -> Dict[str, str]:
    digests = {name: hashlib.new(name) for name in algorithms}
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            for d in digests.values():
                d.update(block)
    return {name: d.hexdigest() for name, d in digests.items()}


def idb_content_bytes() -> bytes:
    """Concatenated byte values of every segment (0 for uninitialised bytes).

    This is what the server hashes for IDB/disassembly uploads, so hashing it
    locally tells us whether *this exact* database content was uploaded
    before.
    """
    import ida_bytes
    import ida_segment

    out = bytearray()
    seg = ida_segment.get_first_seg()
    while seg is not None:
        start, end = int(seg.start_ea), int(seg.end_ea)
        out += _segment_bytes(ida_bytes, start, end)
        seg = ida_segment.get_next_seg(start)
    return bytes(out)


def _segment_bytes(ida_bytes, start: int, end: int) -> bytes:
    size = end - start
    if size <= 0:
        return b""
    # Fast path: initialised bytes come straight from the database.
    getter = getattr(ida_bytes, "get_bytes_and_mask", None)
    if getter is not None:
        try:
            result = getter(start, size)
            if isinstance(result, tuple) and len(result) == 2 and result[0] is not None:
                data, mask = result
                data = bytes(data)
                if _mask_all_set(mask, size):
                    return data
                out = bytearray(data)
                for i in range(size):
                    if not (mask[i >> 3] >> (i & 7)) & 1:
                        out[i] = 0
                return bytes(out)
        except Exception:  # noqa: BLE001 - fall back to the slow path below
            pass
    out = bytearray(size)
    for i, ea in enumerate(range(start, end)):
        out[i] = ida_bytes.get_full_flags(ea) & 0xFF
    return bytes(out)


def _mask_all_set(mask, size: int) -> bool:
    full_bytes, rest = divmod(size, 8)
    if any(b != 0xFF for b in bytes(mask[:full_bytes])):
        return False
    if rest and (mask[full_bytes] & ((1 << rest) - 1)) != (1 << rest) - 1:
        return False
    return True


def idb_content_hashes() -> Dict[str, str]:
    data = idb_content_bytes()
    return {
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
    }


# --------------------------------------------------------------------------
# Database copy (IDB upload)
# --------------------------------------------------------------------------


def save_database_copy(path: str) -> None:
    """Write a packed copy of the open database to *path*.

    ``DBFL_TEMP`` keeps the open database's own path unchanged (plain
    ``save_database`` would behave like "Save as").
    """
    import ida_loader

    flags = getattr(ida_loader, "DBFL_TEMP", 0x08)
    if not ida_loader.save_database(path, flags):
        raise OSError(f"IDA could not save a copy of the database to {path}")


# --------------------------------------------------------------------------
# Cursor tracking
# --------------------------------------------------------------------------


class CursorHook:
    """Calls ``callback(function_start_ea)`` whenever the cursor moves."""

    def __init__(self, callback: Callable[[Optional[int]], None]):
        import ida_kernwin

        outer = self

        class _Hooks(ida_kernwin.UI_Hooks):
            def screen_ea_changed(self, ea, prev_ea):
                try:
                    outer._callback(function_start(ea))
                except Exception as exc:  # noqa: BLE001 - never let a UI hook raise into IDA
                    _log.debug("cursor hook failed: %s", exc)

        self._callback = callback
        self._hooks = _Hooks()
        self._hooks.hook()

    def unhook(self) -> None:
        if self._hooks is not None:
            self._hooks.unhook()
            self._hooks = None
