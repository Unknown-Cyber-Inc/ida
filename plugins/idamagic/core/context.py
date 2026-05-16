"""
PluginContext: replaces references.py.

The previous design used module-level globals in references.py wrapped
in getter/setter functions. That pattern had several real problems:

  1. The "globals" were declared with type annotations (`loaded_sha1: str`)
     but never initialized at module load. Calling get_loaded_sha1()
     before MAGICMainClass.__init__ runs raises NameError. The plugin
     happened to work only because of import order luck.

  2. set_X(v) / get_X() wrapping a global is the same as exposing the
     global directly, except slower and harder to mock in tests.

  3. State that's shared between sub-widgets should live on the widget
     hierarchy's owner, not in a module. The widget tree already has a
     clean parent chain (main_interface -> unknown_plugin -> list_widget).

  4. The pattern forecloses on ever running two binaries in two
     sessions in the same Python process. Uncommon in IDA, but Ghidra
     and Binary Ninja support it natively.

PluginContext is a plain dataclass. It is instantiated once in
`magic.init()` (the plugin_t entrypoint) and passed by reference to
every widget constructor. State lives on the instance; access is
`self.ctx.version_hash` instead of `get_version_hash()`.

For the planned Ghidra and Binary Ninja ports, PluginContext is reusable
as-is. Only the host adapter (disassembler-specific code in idamagic/ida/,
which will gain siblings idamagic/ghidra/, idamagic/binja/) needs to
change.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class PluginContext:
    """Mutable, session-scoped plugin state.

    A single instance is created at plugin init time and shared
    between all widgets. There are no module-level globals.
    """

    # --- Hashes computed from the loaded IDB and from IDA's record ---
    # of the original binary. These are populated once in main_interface.
    loaded_sha1: Optional[str] = None
    loaded_sha256: Optional[str] = None
    loaded_md5: Optional[str] = None
    ida_sha256: Optional[str] = None
    ida_md5: Optional[str] = None

    # --- Currently selected file/version ---
    # version_hash drives which file's data we display in the
    # right-hand panels. Changing it triggers a refresh.
    version_hash: Optional[str] = None

    # True iff the loaded binary or its IDB has at least one
    # corresponding record on the MAGIC backend.
    file_exists: bool = False

    # True iff the IDA SDK version we're running on is supported
    # (currently 8.x only; gated in main_interface.check_ida_version).
    ida_version_valid: bool = False

    # "IDB" / "Binary" / "Disassembly", set when an upload kicks off
    # so the dropdown entry can show "Recent {type} Upload".
    recent_upload_type: Optional[str] = None

    # --- Upload tracking ---
    # Maps SHA1 -> dropdown index for files that have already been
    # processed by the backend (content files).
    upload_content_hashes: Dict[str, int] = field(default_factory=dict)
    # Maps SHA1 -> dropdown index for files still in the processing
    # pipeline (container files). They graduate to content_hashes once
    # processing completes.
    upload_container_hashes: Dict[str, int] = field(default_factory=dict)

    # --- API ---
    # cythereal_magic.ApiClient. Typed as Any to avoid importing the
    # SDK in this disassembler-agnostic module.
    api_client: Any = None

    # --- Widget references that other widgets need to reach ---
    # These are populated when the widgets are constructed. Prefer
    # accessing widgets via the parent chain where possible; this
    # field exists for the dropdown specifically because dropdown
    # mutations come from multiple sub-widgets.
    dropdown: Any = None  # QComboBox

    # ---- Mutation helpers for the upload-tracking dicts ----

    def add_upload_content_entry(self, sha1: str, index: int) -> None:
        self.upload_content_hashes[sha1] = index

    def add_upload_container_entry(self, sha1: str, index: int) -> None:
        self.upload_container_hashes[sha1] = index

    def remove_upload_container_entry(self, sha1: str) -> None:
        # Tolerate missing keys; the previous getter/setter pattern
        # raised KeyError on stale references during dropdown churn.
        self.upload_container_hashes.pop(sha1, None)

    def increment_upload_content_indexes(self) -> None:
        """
        Used when the original file is uploaded after an IDB or
        disassembly upload. The original always lives at index 0 in
        the dropdown, so every non-zero entry shifts down by one.
        """
        for c_hash in self.upload_content_hashes:
            if self.upload_content_hashes[c_hash] > 0:
                self.upload_content_hashes[c_hash] += 1
