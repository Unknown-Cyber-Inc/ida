"""Build the disassembly archive that ``POST /files/disassembly`` consumes.

Archive layout (unchanged from previous plugin versions)::

    <name>.zip
      binary.json
      procedures/<startEA>.json

Must run on IDA's main thread.  Database modifications are made inside an
undo point and reverted before returning, so the user's database is left
exactly as it was.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import logging
import os
import shutil
import tempfile
import zipfile
from typing import Callable, Dict, List, Optional

from .. import idb

_log = logging.getLogger(__name__)

UNDO_LABEL = "Unknown Cyber disassembly export"
ProgressFn = Callable[[int, int, str], bool]  # (done, total, message) -> keep going?


class ExportError(RuntimeError):
    pass


class ExportCancelled(ExportError):
    pass


@dataclasses.dataclass
class ExportOptions:
    create_missing_functions: bool = True
    keep_archive: bool = False  # leave the zip in place after upload (debugging)


@dataclasses.dataclass
class ExportResult:
    zip_path: str
    workdir: str
    procedure_count: int
    content_sha1: str

    def cleanup(self) -> None:
        shutil.rmtree(self.workdir, ignore_errors=True)


# --------------------------------------------------------------------------
# Undo-point helper
# --------------------------------------------------------------------------


class _UndoPoint:
    """Create an undo point on enter; revert to it on exit."""

    def __init__(self, label: str):
        self._label = label
        self.created = False

    def __enter__(self):
        try:
            import ida_undo

            try:
                self.created = bool(ida_undo.create_undo_point(self._label))
            except TypeError:  # some builds take the action name as bytes
                self.created = bool(ida_undo.create_undo_point(self._label.encode("utf-8")))
        except Exception as exc:  # noqa: BLE001
            _log.warning("could not create undo point: %s", exc)
            self.created = False
        return self

    def __exit__(self, exc_type, exc, tb):
        if not self.created:
            return False
        try:
            import ida_undo

            if not ida_undo.perform_undo():
                _log.warning("perform_undo() returned False; database changes may persist (Edit > Undo)")
        except Exception as err:  # noqa: BLE001
            _log.warning("perform_undo failed: %s", err)
        return False


def undo_available() -> bool:
    try:
        import ida_undo  # noqa: F401

        return True
    except ImportError:
        return False


# --------------------------------------------------------------------------
# Export
# --------------------------------------------------------------------------


def export_disassembly(
    loaded: idb.LoadedFile,
    options: ExportOptions,
    progress: Optional[ProgressFn] = None,
) -> ExportResult:
    """Produce the upload archive for the open database.

    Raises :class:`ExportError` when the original binary is missing (the
    backend needs its sha1/sha512) or when ``sark`` is not installed.
    """
    from . import prolog

    prolog.require_sark()
    import idaapi
    import sark  # type: ignore

    if not loaded.binary_exists:
        raise ExportError(
            "The original binary is not available at\n"
            f"{loaded.path or '(unknown path)'}\n\n"
            "Place it at that path or use 'Upload IDB' instead."
        )

    def report(done: int, total: int, message: str) -> None:
        if progress is not None and not progress(done, total, message):
            raise ExportCancelled("Export cancelled.")

    report(0, 0, "Hashing original binary…")
    file_hashes = idb.hash_file(loaded.path, ("sha1", "sha512"))

    report(0, 0, "Collecting database bytes…")
    content = idb.idb_content_bytes()
    content_sha1 = hashlib.sha1(content).hexdigest()
    padded = content + b"\x00" * ((3 - len(content) % 3) % 3)
    byte_data = base64.b64encode(padded).decode("ascii")

    workdir = tempfile.mkdtemp(prefix="unknowncyber-")
    proc_dir = os.path.join(workdir, "procedures")
    os.mkdir(proc_dir)

    binary_json = {
        "md5": loaded.md5,
        "sha1": file_hashes["sha1"],
        "sha256": loaded.sha256,
        "sha512": file_hashes["sha512"],
        "unix_filetype": loaded.file_type,
        "version": idb.kernel_version(),
        "disassembler": "ida",
        "use_32": loaded.arch_bits == 32,
        "use_64": loaded.arch_bits == 64,
        "file_name": loaded.name,
        "image_base": loaded.image_base,
        "byte_data": byte_data,
    }
    with open(os.path.join(workdir, "binary.json"), "w", encoding="utf-8") as fh:
        json.dump(binary_json, fh)

    count = 0
    try:
        with _UndoPoint(UNDO_LABEL) as undo:
            if not undo.created:
                raise ExportError(
                    "IDA could not create an undo point, so the temporary database changes the export needs "
                    "could not be reverted afterwards. Export aborted to keep your database unchanged."
                )
            report(0, 0, "Rebasing to 0 (temporary)…")
            delta = 0 - idb.image_base()
            if delta:
                idaapi.rebase_program(delta, idaapi.MSF_FIXONCE)

            if options.create_missing_functions:
                report(0, 0, "Looking for unclaimed function prologues…")
                created = prolog.mark_missed_procedures()
                if created:
                    _log.info("created %d temporary functions for export", created)

            imports = prolog.Imports(image_base=0)
            functions = list(sark.functions())
            total = len(functions)
            for index, func in enumerate(functions):
                report(index, total, f"Exporting procedure {index + 1}/{total} at {func.start_ea:#x}")
                proc = _export_function(func, imports, prolog)
                with open(os.path.join(proc_dir, f"{proc['startEA']}.json"), "w", encoding="utf-8") as fh:
                    json.dump(proc, fh)
                count += 1
            report(total, total, "Finalising…")
        # The undo point has been reverted at this point.
    except BaseException:
        shutil.rmtree(workdir, ignore_errors=True)
        raise

    zip_path = os.path.join(workdir, f"{_safe_name(loaded.name) or 'disassembly'}.zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(os.path.join(workdir, "binary.json"), "binary.json")
        for entry in sorted(os.listdir(proc_dir)):
            zf.write(os.path.join(proc_dir, entry), os.path.join("procedures", entry))

    return ExportResult(zip_path=zip_path, workdir=workdir, procedure_count=count, content_sha1=content_sha1)


def _export_function(func, imports, prolog) -> Dict:
    import idc
    import sark  # type: ignore

    prolog.remove_register_renamings(func.func_t)

    proc: Dict = {
        "blocks": [],
        "is_library": func.flags & 0x4,  # FUNC_LIB
        "is_thunk": func.flags & 0x80,  # FUNC_THUNK
        "startEA": func.start_ea,
        "endEA": func.end_ea,
        "procedure_name": prolog.function_name(func.start_ea),
        "segment_name": idc.get_segm_name(func.end_ea),
        "strings": [],
        "api_calls": list(prolog.api_calls(func, imports)),
        "cfg": {},
    }

    adjacency: Dict[int, List[int]] = {}

    def add_node(ea: int) -> None:
        adjacency.setdefault(ea, [])

    def add_edge(src: int, dst: int) -> None:
        add_node(src)
        add_node(dst)
        if dst not in adjacency[src]:
            adjacency[src].append(dst)

    flowchart = sark.FlowChart(func.start_ea)
    for block in flowchart:
        add_node(block.start_ea)
        for pred in block.preds():
            add_edge(pred.start_ea, block.start_ea)
        for succ in block.succs():
            add_edge(block.start_ea, succ.start_ea)
    proc["cfg"] = {f"{src:#x}": [f"{dst:#x}" for dst in dsts] for src, dsts in adjacency.items()}

    for block in sark.FlowChart(func.start_ea):
        block_json = {"startEA": block.start_ea, "endEA": block.end_ea, "lines": []}
        for line in block.lines:
            prolog.set_operand_display(line.start_ea, -1, "hex")
            try:
                insn = line.insn
                block_json["lines"].append(
                    {
                        "startEA": line.start_ea,
                        "endEA": line.end_ea,
                        "type": line.type,
                        "bytes": " ".join(f"{b:02X}" for b in line.bytes),
                        "mnem": insn.mnem,
                        "operands": [op.text for op in insn.operands],
                        "prolog_format": prolog.format_instruction(insn, line.start_ea),
                        "api_call_name": prolog.api_call_name(line, imports),
                        "is_call": insn.is_call,
                    }
                )
            except sark.exceptions.SarkNoInstruction:
                continue
        proc["blocks"].append(block_json)
    return proc


def _safe_name(name: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in (name or ""))[:80]
