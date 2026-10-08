"""Headless smoke test for the plugin UI.

Runs outside IDA: ``tests/stubs`` provides just enough of the ``ida_*`` API,
PySide6 runs with the offscreen platform plugin and the API client is replaced
by an in-memory fake.  Exercise with::

    python -m pytest tests/ -q

or, without pytest::

    python tests/test_ui_smoke.py
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests" / "stubs"))
sys.path.insert(0, str(ROOT / "plugins"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("UNKNOWNCYBER_BRAND", "1")  # exercise the 1b "ink" code paths headlessly
os.environ.setdefault("UNKNOWNCYBER_API_KEY", "test-key")
os.environ.setdefault("UNKNOWNCYBER_API_HOST", "https://api.example.test")
os.environ["UNKNOWNCYBER_CONFIG_DIR"] = str(Path(os.environ.get("TMPDIR", "/tmp")) / "unknowncyber-tests" / "config")

from unknowncyber import client as client_mod  # noqa: E402
from unknowncyber import config, models  # noqa: E402
from unknowncyber.qt import QtCore, QtGui, QtWidgets  # noqa: E402

SHA1_ORIG = "a" * 40
SHA1_CHILD = "b" * 40
SHA1_OTHER = "c" * 40


class FakeClient:
    """Deterministic stand-in for MagicClient; records every mutation."""

    def __init__(self, settings):
        self.settings = settings
        self.dashboard_base_url = settings.dashboard_base_url
        self.calls = []
        self.notes = {"file": [models.Note("n1", "first note", "alice", "2026-01-01")], "proc": [], "group": []}
        self.tags = {"file": [models.Tag("t1", "packed", "bob", "2026-01-01")], "proc": [], "group": []}
        self._ids = 100

    def _next(self):
        self._ids += 1
        return str(self._ids)

    def _log(self, name, *args):
        self.calls.append((name, args))

    # files
    def ping(self):
        self._log("ping")

    def dashboard_url(self, binary_id):
        return f"{self.dashboard_base_url}/files/{binary_id}"

    def get_file(self, binary_id, with_children=True):
        self._log("get_file", binary_id, with_children)
        if binary_id == SHA1_ORIG or len(binary_id) == 32:
            return models.FileInfo(
                sha1=SHA1_ORIG,
                md5=binary_id if len(binary_id) == 32 else "",
                status="success",
                children=[models.AnalysisVersion("2026-01-02T10:00:00", SHA1_CHILD, "content", "2026-01-02T10:00:00")],
            )
        return None

    def upload_status(self, binary_id):
        self._log("upload_status", binary_id)
        return models.UploadStatus(binary_id, "success", {"srl_juice": "success"})

    def upload_binary(self, payload, *, skip_unpack, arch_bits):
        self._log("upload_binary", len(payload), skip_unpack, arch_bits)
        return SHA1_ORIG

    def upload_disassembly(self, zip_path):
        self._log("upload_disassembly", os.path.basename(zip_path))
        return SHA1_OTHER

    def list_file_matches(self, binary_id, page=1):
        self._log("list_file_matches", binary_id, page)
        return [models.FileMatch(SHA1_OTHER, 0.91, ["other.exe"])]

    def list_file_notes(self, binary_id):
        return list(self.notes["file"])

    def create_file_note(self, binary_id, text):
        note = models.Note(self._next(), text, "me", "now")
        self.notes["file"].append(note)
        self._log("create_file_note", binary_id, text)
        return note

    def update_file_note(self, binary_id, note_id, text):
        self._log("update_file_note", binary_id, note_id, text)

    def delete_file_note(self, binary_id, note_id):
        self._log("delete_file_note", binary_id, note_id)
        self.notes["file"] = [n for n in self.notes["file"] if n.id != note_id]

    def list_file_tags(self, binary_id):
        return list(self.tags["file"])

    def create_file_tag(self, binary_id, name):
        tag = models.Tag(self._next(), name)
        self.tags["file"].append(tag)
        self._log("create_file_tag", binary_id, name)
        return tag

    def delete_file_tag(self, binary_id, tag_id):
        self._log("delete_file_tag", binary_id, tag_id)

    # procedures
    def list_procedures(self, binary_id):
        self._log("list_procedures", binary_id)
        return [
            models.Procedure("0x1000", "main", "d" * 40, binary_id, 3, 4, 20, "static", 1, 0, ["hello"], ["CreateFileA"]),
            models.Procedure("0x1040", "", "e" * 40, binary_id, 1, 1, 5, "static"),
        ]

    def get_procedure_code(self, binary_id, rva):
        self._log("get_procedure_code", binary_id, rva)
        return models.ProcedureCode(binary_id, rva, "main", [["push ebp", "mov ebp, esp"], ["ret"]])

    def rename_procedure(self, binary_id, rva, name):
        self._log("rename_procedure", binary_id, rva, name)

    def list_similar_procedures(self, binary_id, rva):
        self._log("list_similar_procedures", binary_id, rva)
        return [models.SimilarProcedure(SHA1_OTHER, "0x2000", 4, 20), models.SimilarProcedure(binary_id, "0x1040", 1, 5)]

    def list_procedure_notes(self, binary_id, rva):
        return list(self.notes["proc"])

    def create_procedure_note(self, binary_id, rva, text):
        note = models.Note(self._next(), text)
        self.notes["proc"].append(note)
        self._log("create_procedure_note", binary_id, rva, text)
        return note

    def update_procedure_note(self, binary_id, rva, note_id, text):
        self._log("update_procedure_note", note_id, text)

    def delete_procedure_note(self, binary_id, rva, note_id):
        self._log("delete_procedure_note", note_id)

    def list_procedure_tags(self, binary_id, rva):
        return list(self.tags["proc"])

    def create_procedure_tag(self, binary_id, rva, name):
        tag = models.Tag(self._next(), name)
        self.tags["proc"].append(tag)
        return tag

    def delete_procedure_tag(self, binary_id, rva, tag_id):
        self._log("delete_procedure_tag", tag_id)

    # groups
    def list_group_files(self, hard_hash):
        return [models.ContainingFile(SHA1_OTHER, ["other.exe"]), models.ContainingFile(SHA1_CHILD)]

    def list_group_notes(self, hard_hash):
        return list(self.notes["group"])

    def create_group_note(self, hard_hash, text):
        note = models.Note(self._next(), text)
        self.notes["group"].append(note)
        return note

    def update_group_note(self, hard_hash, note_id, text):
        pass

    def delete_group_note(self, hard_hash, note_id):
        pass

    def list_group_tags(self, hard_hash):
        return list(self.tags["group"])

    def create_group_tag(self, hard_hash, name):
        return models.Tag(self._next(), name)

    def delete_group_tag(self, hard_hash, tag_id):
        pass


def pump(app, seconds=0.5):
    """Process events until all worker threads finished or the timeout elapses."""
    deadline = time.time() + seconds
    while time.time() < deadline:
        app.processEvents(QtCore.QEventLoop.ProcessEventsFlag.AllEvents, 50)
        time.sleep(0.01)


_APP = None


def _app():
    global _APP
    _APP = QtWidgets.QApplication.instance() or QtWidgets.QApplication(sys.argv)
    return _APP


def test_client_validation():
    settings = config.Settings(api_host="https://api.example.test", api_key="k")
    assert settings.api_base_url == "https://api.example.test/v2"
    assert config.normalize_host("https://api.example.test/v2/") == "https://api.example.test/v2"
    assert config.validate_host("http://evil.example") is not None
    assert config.validate_host("https://ok.example") is None
    for bad in ("", "zz", "../etc", "0x1000"):
        try:
            client_mod.require_hash(bad)
        except client_mod.ApiError:
            pass
        else:
            raise AssertionError(f"accepted bad hash {bad!r}")
    assert client_mod.require_rva("0x1000") == "0x1000"
    assert client_mod.require_hash(SHA1_ORIG) == SHA1_ORIG


def test_settings_roundtrip(tmp_path=None):
    settings = config.load()
    settings.api_host = "https://api.example.test"
    settings.verify_tls = True
    config.save(settings)
    reloaded = config.load()
    assert reloaded.api_host == "https://api.example.test"
    assert reloaded.api_key == "test-key"  # environment override wins


def test_panel_flow(monkeypatch=None):
    app = _app()
    from unknowncyber.ui import main_widget

    created = {}

    def factory(settings):
        created["client"] = FakeClient(settings)
        return created["client"]

    main_widget.MagicClient = factory  # type: ignore[attr-defined]
    panel = main_widget.MainPanel()
    panel.resize(900, 900)
    panel.show()
    pump(app, 0.8)
    fake = created["client"]

    # Versions discovered: original + child, child preferred (newest).
    versions = panel._versions
    assert [v.binary_id for v in versions] == [SHA1_ORIG, SHA1_CHILD], versions
    assert panel.header.current_version().binary_id == SHA1_CHILD
    assert panel.header._status.text() == "● Ready"
    # Version chips replaced the combobox: one checkable chip per version, the newest checked.
    chips = panel.header._chips
    assert set(chips) == {SHA1_ORIG, SHA1_CHILD} and chips[SHA1_CHILD].isChecked()
    assert chips[SHA1_ORIG].text() == f"Original · {SHA1_ORIG[:8]}"
    assert panel.header._hash.text().startswith("md5 ")
    assert panel._stack.currentWidget() is panel._splitter

    # Procedures load and select; stats tiles and the occurrence bar follow.
    panel.load_procedures()
    pump(app, 0.8)
    assert len(panel.procedures.procedures()) == 2
    assert panel.procedures.stats.value("procedures") == "2"
    assert panel.procedures.stats.value("matches") == "1"
    assert panel.procedures.stats.value("annotated") == "1"
    from unknowncyber.ui import brand
    from unknowncyber.ui import procedures as procedures_mod

    model = panel.procedures._model
    assert model.max_occurrence == 3
    ratios = [model.index(r, procedures_mod.COL_BAR).data(procedures_mod.RATIO_ROLE) for r in range(2)]
    assert ratios[0] == 1.0 and 0.03 <= ratios[1] < 1.0
    assert isinstance(panel.procedures._table.itemDelegateForColumn(procedures_mod.COL_BAR), brand.BarDelegate)
    assert panel.procedures._table.horizontalHeader().isHidden()
    assert panel.procedures._table.isColumnHidden(procedures_mod.COL_BLOCKS)
    assert model.index(0, procedures_mod.COL_OCC).data() == "3"
    assert panel.procedures.select_rva(0x1000)
    pump(app, 0.3)
    target = panel.inspector.procedure_tab.current_target()
    assert target is not None and target.rva == "0x1000" and target.local

    # Title row + tag chips (tags moved out of a tab into a chip row).
    proc_tab = panel.inspector.procedure_tab
    assert proc_tab._title.text() == "main" and proc_tab._address.text() == "0x1000"
    pump(app, 0.4)
    assert proc_tab._tags.loaded and proc_tab._tags._add.isVisible()
    tag_src = proc_tab._tags._source
    proc_tab._tags._create("packed")
    pump(app, 0.5)
    assert [c.text() for c in proc_tab._tags._chips] == ["packed"]
    assert ("create_procedure_tag", (SHA1_CHILD, "0x1000", "packed")) in fake.calls or any(t.name == "packed" for t in fake.tags["proc"])
    assert tag_src is not None

    # Procedure notes: add one through the annotation list without dialogs.
    proc_tab._tabs.setCurrentIndex(1)
    pump(app, 0.5)
    notes = proc_tab._notes
    src = notes._source
    assert src is not None and src.create_fn is not None
    notes._mutate(lambda: src.create_fn("hello from test"), lambda item: notes._set_items(notes._items + [item]), "Saving…")
    pump(app, 0.5)
    assert any(n.text == "hello from test" for n in notes.items)
    assert ("create_procedure_note", (SHA1_CHILD, "0x1000", "hello from test")) in fake.calls

    # Similar procedures + navigation to a remote procedure and back.
    proc_tab._tabs.setCurrentIndex(2)
    pump(app, 0.6)
    tree = proc_tab._similar._tree
    assert tree.topLevelItemCount() == 2
    assert proc_tab._tabs.tabText(2) == "Similar 2"
    remote = models.SimilarProcedure(SHA1_OTHER, "0x2000", 4, 20)
    proc_tab._inspect_similar(remote)
    pump(app, 0.3)
    assert proc_tab.current_target().binary_id == SHA1_OTHER and not proc_tab.current_target().local
    assert proc_tab._back.isVisible()
    proc_tab._go_home()
    assert proc_tab.current_target().rva == "0x1000"

    # Compare dialog opens with diff highlighting and the overlap meter.
    panel._compare(proc_tab.current_target(), remote)
    pump(app, 0.6)
    assert panel._dialogs and panel._dialogs[0].windowTitle() == "Compare procedures"
    assert panel._dialogs[0]._meter._label.text().endswith("%")
    panel._dialogs[0].close()

    # File tab: matches pagination + inspect another file + back.
    file_tab = panel.inspector.file_tab
    file_tab._tabs.setCurrentIndex(1)
    pump(app, 0.5)
    assert file_tab._matches.topLevelItemCount() == 1
    panel.inspector.inspect_file(SHA1_OTHER)
    pump(app, 0.3)
    assert file_tab._back.isVisible()
    file_tab._back.back_requested.emit()
    assert file_tab._binary_id == SHA1_CHILD

    # Cursor hook drives the selection (ea -> rva).
    panel.procedures.on_cursor_function(0x401040)
    assert panel.procedures.selected().start_ea == "0x1040"

    # Upload IDB: database copy is written to a temp dir, uploaded and removed.
    panel._upload_idb()
    pump(app, 1.0)
    assert any(c[0] == "upload_binary" for c in fake.calls)
    import ida_loader

    saved_path = ida_loader.saved[-1][0]
    assert not os.path.exists(saved_path), "temporary IDB copy should be deleted"
    # The fake server reports the container as processed immediately, so the
    # poll resolves it to its child version and the pending list drains.
    assert any(c[0] == "upload_status" for c in fake.calls)
    assert not panel._pending
    assert panel.header.upload_strip.isVisible()
    assert panel.header.current_version().binary_id == SHA1_CHILD

    # Rename flows through to table + inspector.
    panel.procedures.select_rva(0x1000)
    pump(app, 0.2)
    target = proc_tab.current_target()
    fake.calls.clear()
    panel._tasks.run(
        lambda: fake.rename_procedure(target.binary_id, target.rva, "renamed"), on_success=lambda _: proc_tab.update_name("renamed")
    )
    pump(app, 0.3)
    assert proc_tab.current_target().name == "renamed"

    panel.shutdown()
    panel.close()
    pump(app, 0.2)


def test_plugin_auto_opens_panel():
    """The plugin_t opens the panel on database_inited when auto_open is on, once."""
    app = _app()
    import ida_kernwin

    import unknowncyber
    from unknowncyber.ui import main_widget

    main_widget.MagicClient = FakeClient  # type: ignore[attr-defined]
    ida_kernwin._widgets.clear()
    plugin = unknowncyber._build_plugin_class()()
    assert plugin.init() == 2  # PLUGIN_KEEP; the stub reports a database as already open -> auto-open
    pump(app, 0.3)
    assert ida_kernwin.find_widget(unknowncyber.WIDGET_TITLE) is not None
    first = ida_kernwin.find_widget(unknowncyber.WIDGET_TITLE)
    hook = plugin._hook
    hook.database_inited(False, "")  # a second notification must not create a second panel
    assert ida_kernwin.find_widget(unknowncyber.WIDGET_TITLE) is first
    assert hook.create_desktop_widget(unknowncyber.WIDGET_TITLE, None) is first

    # Turning the setting off disables it.
    settings = config.load()
    settings.auto_open = False
    config.save(settings)
    try:
        ida_kernwin._widgets.clear()
        hook.database_inited(False, "")
        assert ida_kernwin.find_widget(unknowncyber.WIDGET_TITLE) is None
    finally:
        settings.auto_open = True
        config.save(settings)
    plugin.term()
    pump(app, 0.2)


def test_settings_dialog_builds():
    app = _app()
    from unknowncyber.ui.settings import SettingsDialog

    dialog = SettingsDialog(config.load())
    dialog.show()
    pump(app, 0.1)
    assert dialog._host.text()
    assert dialog.objectName() == "ucPanel" and dialog._save.property("role") == "primary"
    dialog.close()


def test_panel_builds_without_brand():
    """Light themes keep the plain look: every widget must still build with the brand layer off."""
    app = _app()
    from unknowncyber.ui import brand, main_widget
    from unknowncyber.ui.dialogs import UploadDialog

    brand.force(False)
    try:
        main_widget.MagicClient = FakeClient  # type: ignore[attr-defined]
        panel = main_widget.MainPanel()
        panel.show()
        pump(app, 0.8)
        assert panel.objectName() != "ucPanel"
        assert panel.header._status.text() == "Ready"
        panel.load_procedures()
        pump(app, 0.6)
        assert panel.procedures.stats.value("procedures") == "2"
        dialog = UploadDialog(binary_available=True, sark_available=True, undo_available=True, create_functions=True)
        assert dialog.kind == UploadDialog.BINARY
        dialog.close()
        panel.shutdown()
        panel.close()
    finally:
        brand.force(None)


def test_brand_default_is_on():
    """The ink look is the default regardless of the host theme; 'auto' follows the palette, 'plain' is off."""
    _app()
    from unknowncyber.ui import brand

    saved = os.environ.pop("UNKNOWNCYBER_BRAND", None)
    try:
        brand.refresh()
        assert brand.appearance() == "brand" and brand.is_active()
        brand._appearance = "plain"
        assert not brand.is_active()
        brand._appearance = "auto"
        assert brand.is_active() == (QtWidgets.QApplication.instance().palette().color(QtGui.QPalette.ColorRole.Window).lightness() < 128)
    finally:
        brand.refresh()
        if saved is not None:
            os.environ["UNKNOWNCYBER_BRAND"] = saved


def test_header_version_overflow():
    """More than four versions: newest three chips + a '+N' menu; selection keeps working."""
    _app()
    from unknowncyber.ui.header import HeaderBar

    header = HeaderBar()
    versions = [models.AnalysisVersion(f"v{i}", f"{i:040x}", "content", f"2026-01-0{i}T10:0{i}:00") for i in range(1, 7)]
    seen = []
    header.version_changed.connect(lambda v: seen.append(v.binary_id if v else None))
    header.set_versions(versions, versions[-1].binary_id)
    assert set(header._chips) == {v.binary_id for v in versions[-3:]}
    assert header.current_version().binary_id == versions[-1].binary_id
    assert header._chips[versions[-1].binary_id].text().startswith("Disasm · 01-06 10:06")
    header._chips[versions[-2].binary_id].click()
    assert seen == [versions[-2].binary_id]
    header._select_overflow(versions[0].binary_id)  # from the "+3" menu
    assert header.current_version().binary_id == versions[0].binary_id and versions[0].binary_id in header._chips
    assert seen[-1] == versions[0].binary_id
    header.set_version_hint("Matches this IDB exactly.", match=True)
    assert header._version_hint.text().startswith("✓")


def test_upload_dialog_builds():
    app = _app()
    from unknowncyber.ui.dialogs import UploadDialog

    dialog = UploadDialog(binary_available=False, sark_available=True, undo_available=True, create_functions=True)
    dialog.show()
    pump(app, 0.1)
    assert dialog.kind == UploadDialog.IDB  # binary unavailable -> next enabled option
    assert dialog._cards[dialog._idb].property("selected") is True
    assert dialog._cards[dialog._binary].property("selected") is False
    dialog.close()


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            print("running", name)
            fn()
    print("all smoke tests passed")
