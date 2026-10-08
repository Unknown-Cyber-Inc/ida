"""Inspector card: details for the selected file or procedure (design 1b).

Two outer tabs:

* **File** – tags (chip row), notes and similar files for the selected
  analysis version (or for another file reached from a similarity result).
* **Procedure** – title row, tag chips, then *Overview · Notes · Similar ·
  Group* for the selected procedure (or a remote procedure reached from a
  similarity result).

Navigation to remote files/procedures shows a back bar.
"""

from __future__ import annotations

import dataclasses
from typing import Callable, List, Optional

from .. import models
from ..client import MagicClient
from ..qt import QtCore, QtWidgets, Signal
from ..workers import TaskGroup
from . import brand, style
from .annotations import AnnotationList, AnnotationSource, TagChips
from .dialogs import Banner, BusyIndicator
from .similar import ContainingFilesView, SimilarProceduresView

Qt = QtCore.Qt
ClientProvider = Callable[[], Optional[MagicClient]]


@dataclasses.dataclass(frozen=True)
class ProcTarget:
    binary_id: str
    rva: str
    name: str = ""
    hard_hash: str = ""
    local: bool = True  # belongs to the analysis version currently selected
    procedure: Optional[models.Procedure] = None

    @property
    def key(self) -> str:
        return f"{self.binary_id}:{self.rva}"

    @property
    def title(self) -> str:
        return f"{self.rva} - {self.name}" if self.name else self.rva


class _BackBar(QtWidgets.QFrame):
    back_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("ucBack")
        if not brand.is_active():
            self.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
        layout = QtWidgets.QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        self._button = brand.link_button("← Back", self)
        self._button.clicked.connect(self.back_requested)
        self._label = brand.muted("", self)
        self._label.setProperty("role", "hint")
        layout.addWidget(self._button)
        layout.addWidget(self._label, 1)
        self.hide()

    def set_context(self, text: Optional[str]) -> None:
        self.setVisible(bool(text))
        self._label.setText(text or "")


def _title_row(parent: QtWidgets.QWidget):
    """``name`` (bold 13 px) + ``address`` (monospace, muted) in one row."""
    row = QtWidgets.QHBoxLayout()
    row.setSpacing(8)
    name = QtWidgets.QLabel("", parent)
    name.setProperty("role", "subtitle")
    font = name.font()
    font.setBold(True)
    font.setPixelSize(13)
    name.setFont(font)
    name.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    address = QtWidgets.QLabel("", parent)
    address.setProperty("mono", True)
    mono = style.monospace_font()
    mono.setPixelSize(12)
    address.setFont(mono)
    address.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    if not brand.is_active():
        address.setStyleSheet(f"color: {style.accent('muted', parent).name()};")
    row.addWidget(name)
    row.addWidget(address)
    row.addStretch(1)
    return row, name, address


def _tab_title(base: str, count: int) -> str:
    return f"{base} {count}" if count else base


# --------------------------------------------------------------------------
# File tab
# --------------------------------------------------------------------------


class FileTab(QtWidgets.QWidget):
    inspect_file_requested = Signal(str)

    def __init__(self, client_provider: ClientProvider, parent=None):
        super().__init__(parent)
        self._client = client_provider
        self._tasks = TaskGroup(self)
        self._binary_id = ""
        self._home_binary_id = ""
        self._page = 1
        self._loaded_matches_key = ""

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        self._back = _BackBar(self)
        self._back.back_requested.connect(self._go_home)
        layout.addWidget(self._back)

        head, self._title, self._address = _title_row(self)
        layout.addLayout(head)
        self._tags = TagChips(self)
        layout.addWidget(self._tags)

        self._tabs = QtWidgets.QTabWidget(self)
        self._tabs.setDocumentMode(True)
        self._notes = AnnotationList(self)
        self._tabs.addTab(self._notes, "Notes")
        self._matches_page = self._build_matches()
        self._tabs.addTab(self._matches_page, "Similar files")
        self._tabs.currentChanged.connect(self._on_tab)
        layout.addWidget(self._tabs, 1)

        self._notes.count_changed.connect(lambda n: self._tabs.setTabText(0, _tab_title("Notes", n)))
        self.setEnabled(False)

    def _build_matches(self) -> QtWidgets.QWidget:
        page = QtWidgets.QWidget(self)
        layout = QtWidgets.QVBoxLayout(page)
        layout.setContentsMargins(0, 6, 0, 0)
        layout.setSpacing(6)
        self._matches_banner = Banner(page)
        layout.addWidget(self._matches_banner)
        self._matches_busy = BusyIndicator(page)
        layout.addWidget(self._matches_busy)
        self._matches = QtWidgets.QTreeWidget(page)
        self._matches.setHeaderLabels(["File", "Similarity", ""])
        self._matches.setRootIsDecorated(False)
        self._matches.setAlternatingRowColors(False)
        self._matches.header().setStretchLastSection(False)
        self._matches.header().setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeMode.Stretch)
        self._matches.setColumnWidth(1, 78)
        self._matches.setColumnWidth(2, 42)
        bar_color = brand.PINK if brand.is_active() else style.accent("tag", self).name()
        self._matches_bar = brand.BarDelegate(lambda index: index.data(Qt.ItemDataRole.UserRole + 2), bar_color, self._matches)
        self._matches.setItemDelegateForColumn(1, self._matches_bar)
        if brand.is_active():
            self._matches.setItemDelegate(brand.RowDelegate(self._matches, muted_columns=(2,), inset_column=0))
            self._matches.setItemDelegateForColumn(1, self._matches_bar)
        self._matches.itemDoubleClicked.connect(lambda item, _: self.inspect_file_requested.emit(item.data(0, Qt.ItemDataRole.UserRole)))
        layout.addWidget(self._matches, 1)
        nav = QtWidgets.QHBoxLayout()
        nav.setSpacing(8)
        self._inspect_match = QtWidgets.QPushButton("Inspect file", page)
        self._inspect_match.setEnabled(False)
        self._inspect_match.clicked.connect(self._inspect_selected_match)
        self._matches.itemSelectionChanged.connect(lambda: self._inspect_match.setEnabled(bool(self._matches.selectedItems())))
        self._prev = QtWidgets.QPushButton("‹ Previous", page)
        self._next = QtWidgets.QPushButton("Next ›", page)
        self._page_label = brand.muted("", page)
        self._prev.clicked.connect(lambda: self._load_matches(self._page - 1))
        self._next.clicked.connect(lambda: self._load_matches(self._page + 1))
        nav.addWidget(self._inspect_match)
        nav.addStretch(1)
        nav.addWidget(self._prev)
        nav.addWidget(self._page_label)
        nav.addWidget(self._next)
        layout.addLayout(nav)
        return page

    # -- public --------------------------------------------------------------
    def show_file(self, binary_id: str, *, home: bool = False, label: str = "") -> None:
        if home:
            self._home_binary_id = binary_id
        self._binary_id = binary_id
        self.setEnabled(bool(binary_id))
        self._back.set_context(
            None if (home or binary_id == self._home_binary_id) else f"Viewing another file ({style.short_hash(binary_id, 16)})"
        )
        if label and " · " in label:
            name, _, short = label.partition(" · ")
            self._title.setText(name)
            self._address.setText(short)
        else:
            self._title.setText(label or ("File" if binary_id else "No file selected"))
            self._address.setText(style.short_hash(binary_id, 20) if binary_id else "")
        self._title.setToolTip(binary_id)
        self._address.setToolTip(binary_id)
        client = self._client()
        if not binary_id or client is None:
            self._notes.set_source(None)
            self._tags.set_source(None)
            self._matches.clear()
            return
        self._notes.set_source(
            AnnotationSource(
                kind="note",
                title="File notes",
                key=f"file-notes:{binary_id}",
                list_fn=lambda: client.list_file_notes(binary_id),
                create_fn=lambda text: client.create_file_note(binary_id, text),
                update_fn=lambda note_id, text: client.update_file_note(binary_id, note_id, text),
                delete_fn=lambda note_id: client.delete_file_note(binary_id, note_id),
            )
        )
        self._tags.set_source(
            AnnotationSource(
                kind="tag",
                title="File tags",
                key=f"file-tags:{binary_id}",
                list_fn=lambda: client.list_file_tags(binary_id),
                create_fn=lambda text: client.create_file_tag(binary_id, text),
                delete_fn=lambda tag_id: client.delete_file_tag(binary_id, tag_id),
            )
        )
        self._tags.reload()
        self._page = 1
        self._loaded_matches_key = ""
        self._matches.clear()
        self._on_tab(self._tabs.currentIndex())

    def home_binary_id(self) -> str:
        return self._home_binary_id

    def refresh(self) -> None:
        self._notes.reload(force=True)
        self._tags.reload(force=True)
        self._loaded_matches_key = ""
        self._on_tab(self._tabs.currentIndex())

    # -- internals -----------------------------------------------------------
    def _go_home(self) -> None:
        self.show_file(self._home_binary_id, home=True)

    def _on_tab(self, index: int) -> None:
        if not self._binary_id:
            return
        if index == 0:
            self._notes.reload()
        elif index == 1 and self._loaded_matches_key != f"{self._binary_id}:{self._page}":
            self._load_matches(self._page)

    def _load_matches(self, page: int) -> None:
        client = self._client()
        binary_id = self._binary_id
        if client is None or not binary_id or page < 1:
            return
        self._tasks.invalidate()
        self._matches_banner.clear()
        self._matches_busy.start("Loading similar files…")
        self._prev.setEnabled(False)
        self._next.setEnabled(False)

        def done(matches: List[models.FileMatch]):
            if self._binary_id != binary_id:
                return
            self._page = page
            self._loaded_matches_key = f"{binary_id}:{page}"
            self._matches.clear()
            for m in matches:
                label = m.filename if m.filename else m.sha1
                if m.sha1 == binary_id:
                    label = f"This file  ({label})"
                item = QtWidgets.QTreeWidgetItem([label, "", f"{m.max_similarity:.2f}"])
                item.setToolTip(0, m.sha1)
                item.setData(0, Qt.ItemDataRole.UserRole, m.sha1)
                item.setData(1, Qt.ItemDataRole.UserRole + 2, float(m.max_similarity))
                item.setFont(2, style.monospace_font())
                item.setTextAlignment(2, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                self._matches.addTopLevelItem(item)
            from ..client import PAGE_SIZE

            self._prev.setEnabled(page > 1)
            self._next.setEnabled(len(matches) >= PAGE_SIZE)
            self._page_label.setText(f"Page {page}" + ("" if matches else " · no results"))

        def failed(exc):
            self._matches_banner.error(str(exc))
            self._prev.setEnabled(page > 1)

        self._tasks.run(
            lambda: client.list_file_matches(binary_id, page), on_success=done, on_error=failed, on_finished=self._matches_busy.stop
        )

    def _inspect_selected_match(self) -> None:
        items = self._matches.selectedItems()
        if items:
            self.inspect_file_requested.emit(items[0].data(0, Qt.ItemDataRole.UserRole))


# --------------------------------------------------------------------------
# Procedure tab
# --------------------------------------------------------------------------

TAB_OVERVIEW, TAB_NOTES, TAB_SIMILAR, TAB_GROUP = range(4)


class ProcedureTab(QtWidgets.QWidget):
    jump_requested = Signal(object)  # ProcTarget
    rename_requested = Signal(object)  # ProcTarget
    compare_requested = Signal(object, object)  # (ProcTarget, models.SimilarProcedure)
    inspect_file_requested = Signal(str)

    def __init__(self, client_provider: ClientProvider, parent=None):
        super().__init__(parent)
        self._client = client_provider
        self._target: Optional[ProcTarget] = None
        self._home: Optional[ProcTarget] = None

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        self._back = _BackBar(self)
        self._back.back_requested.connect(self._go_home)
        layout.addWidget(self._back)

        head, self._title, self._address = _title_row(self)
        self._remote = brand.muted("", self)
        self._remote.setProperty("role", "hint")
        head.insertWidget(2, self._remote)
        self._jump = brand.link_button("Jump", self)
        self._rename = brand.link_button("Rename", self)
        head.addWidget(self._jump)
        head.addWidget(self._rename)
        layout.addLayout(head)

        self._tags = TagChips(self)
        layout.addWidget(self._tags)

        self._tabs = QtWidgets.QTabWidget(self)
        self._tabs.setDocumentMode(True)
        self._overview = self._build_overview()
        self._notes = AnnotationList(self)
        self._similar_page = self._build_similar()
        self._group_page = self._build_group()
        self._tabs.addTab(self._overview, "Overview")
        self._tabs.addTab(self._notes, "Notes")
        self._tabs.addTab(self._similar_page, "Similar")
        self._tabs.addTab(self._group_page, "Group")
        self._tabs.currentChanged.connect(self._on_tab)
        layout.addWidget(self._tabs, 1)

        self._notes.count_changed.connect(lambda n: self._tabs.setTabText(TAB_NOTES, _tab_title("Notes", n)))
        self._similar.count_changed.connect(lambda n: self._tabs.setTabText(TAB_SIMILAR, _tab_title("Similar", n)))
        self._jump.clicked.connect(lambda: self._target and self.jump_requested.emit(self._target))
        self._rename.clicked.connect(lambda: self._target and self.rename_requested.emit(self._target))
        self.setEnabled(False)

    def _build_overview(self) -> QtWidgets.QWidget:
        page = QtWidgets.QWidget(self)
        layout = QtWidgets.QVBoxLayout(page)
        layout.setContentsMargins(0, 8, 0, 0)
        layout.setSpacing(8)
        grid = QtWidgets.QFormLayout()
        grid.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(4)
        self._ov_status = QtWidgets.QLabel("", page)
        self._ov_counts = QtWidgets.QLabel("", page)
        self._ov_hash = QtWidgets.QLabel("", page)
        self._ov_hash.setFont(style.monospace_font())
        self._ov_hash.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        for text, widget in (("Status", self._ov_status), ("Counts", self._ov_counts), ("Group hash", self._ov_hash)):
            label = brand.muted(text, page)
            grid.addRow(label, widget)
        layout.addLayout(grid)
        split = QtWidgets.QHBoxLayout()
        split.setSpacing(10)
        self._ov_api = QtWidgets.QListWidget(page)
        self._ov_strings = QtWidgets.QListWidget(page)
        for widget, title in ((self._ov_api, "API calls"), (self._ov_strings, "Strings")):
            box = QtWidgets.QVBoxLayout()
            box.setSpacing(4)
            box.addWidget(style.heading(title, page))
            widget.setAlternatingRowColors(False)
            widget.setFont(style.monospace_font())
            widget.setFrameShape(QtWidgets.QFrame.Shape.NoFrame)
            box.addWidget(widget, 1)
            split.addLayout(box, 1)
        layout.addLayout(split, 1)
        return page

    def _build_similar(self) -> QtWidgets.QWidget:
        page = QtWidgets.QWidget(self)
        layout = QtWidgets.QVBoxLayout(page)
        layout.setContentsMargins(0, 8, 0, 0)
        splitter = QtWidgets.QSplitter(Qt.Orientation.Vertical, page)
        self._similar = SimilarProceduresView(splitter)
        self._files = ContainingFilesView(splitter)
        splitter.addWidget(self._similar)
        splitter.addWidget(self._files)
        splitter.setSizes([300, 150])
        layout.addWidget(splitter)
        self._similar.inspect_requested.connect(self._inspect_similar)
        self._similar.compare_requested.connect(lambda proc: self._target and self.compare_requested.emit(self._target, proc))
        self._similar.jump_requested.connect(self._jump_similar)
        self._files.inspect_file_requested.connect(self.inspect_file_requested)
        return page

    def _build_group(self) -> QtWidgets.QWidget:
        page = QtWidgets.QWidget(self)
        layout = QtWidgets.QVBoxLayout(page)
        layout.setContentsMargins(0, 8, 0, 0)
        layout.setSpacing(8)
        hint = brand.muted("Procedure-group annotations are shared by every file containing this procedure.", page)
        hint.setProperty("role", "hint")
        hint.setWordWrap(True)
        layout.addWidget(hint)
        tags_row = QtWidgets.QHBoxLayout()
        tags_row.setSpacing(8)
        tags_row.addWidget(brand.muted("Group tags", page))
        self._group_tags = TagChips(page)
        tags_row.addWidget(self._group_tags, 1)
        layout.addLayout(tags_row)
        self._group_notes = AnnotationList(page)
        layout.addWidget(self._group_notes, 1)
        return page

    # -- public --------------------------------------------------------------
    def show_procedure(self, target: Optional[ProcTarget], *, home: bool = True) -> None:
        if home:
            self._home = target
        self._target = target
        self.setEnabled(target is not None)
        if target is None:
            self._title.setText("No procedure selected")
            self._address.setText("")
            self._remote.setText("")
            self._back.set_context(None)
            self._notes.set_source(None)
            self._tags.set_source(None)
            self._group_notes.set_source(None)
            self._group_tags.set_source(None)
            self._similar.set_loader("", "", None)
            self._files.set_loader("", "", None)
            self._fill_overview(None)
            return
        self._back.set_context(
            None if (home or target == self._home) else f"Viewing a procedure from another file ({style.short_hash(target.binary_id, 16)})"
        )
        self._set_title(target)
        self._jump.setVisible(target.local)
        self._rename.setVisible(target.local)
        self._tabs.setTabEnabled(TAB_OVERVIEW, target.procedure is not None)
        self._tabs.setTabEnabled(TAB_SIMILAR, target.local)
        self._tabs.setTabEnabled(TAB_GROUP, bool(target.hard_hash))
        self._fill_overview(target.procedure)

        client = self._client()
        if client is None:
            return
        binary_id, rva, hard_hash = target.binary_id, target.rva, target.hard_hash
        self._notes.set_source(
            AnnotationSource(
                kind="note",
                title="Procedure notes",
                key=f"proc-notes:{target.key}",
                list_fn=lambda: client.list_procedure_notes(binary_id, rva),
                create_fn=lambda text: client.create_procedure_note(binary_id, rva, text),
                update_fn=lambda note_id, text: client.update_procedure_note(binary_id, rva, note_id, text),
                delete_fn=lambda note_id: client.delete_procedure_note(binary_id, rva, note_id),
            )
        )
        self._tags.set_source(
            AnnotationSource(
                kind="tag",
                title="Procedure tags",
                key=f"proc-tags:{target.key}",
                list_fn=lambda: client.list_procedure_tags(binary_id, rva),
                create_fn=lambda text: client.create_procedure_tag(binary_id, rva, text),
                delete_fn=lambda tag_id: client.delete_procedure_tag(binary_id, rva, tag_id),
            )
        )
        self._tags.reload()
        if hard_hash:
            self._group_notes.set_source(
                AnnotationSource(
                    kind="note",
                    title="Group notes",
                    key=f"group-notes:{hard_hash}",
                    list_fn=lambda: client.list_group_notes(hard_hash),
                    create_fn=lambda text: client.create_group_note(hard_hash, text),
                    update_fn=lambda note_id, text: client.update_group_note(hard_hash, note_id, text),
                    delete_fn=lambda note_id: client.delete_group_note(hard_hash, note_id),
                )
            )
            self._group_tags.set_source(
                AnnotationSource(
                    kind="tag",
                    title="Group tags",
                    key=f"group-tags:{hard_hash}",
                    list_fn=lambda: client.list_group_tags(hard_hash),
                    create_fn=lambda text: client.create_group_tag(hard_hash, text),
                    delete_fn=lambda tag_id: client.delete_group_tag(hard_hash, tag_id),
                )
            )
            self._files.set_loader(f"files:{hard_hash}", binary_id, lambda: client.list_group_files(hard_hash))
        else:
            self._group_notes.set_source(None)
            self._group_tags.set_source(None)
            self._files.set_loader("", binary_id, None)
        if target.local:
            self._similar.set_loader(f"similar:{target.key}", binary_id, lambda: client.list_similar_procedures(binary_id, rva))
        else:
            self._similar.set_loader("", binary_id, None)
        if not self._tabs.isTabEnabled(self._tabs.currentIndex()):
            self._tabs.setCurrentIndex(TAB_NOTES)
        self._on_tab(self._tabs.currentIndex())

    def update_name(self, name: str) -> None:
        if self._target is None:
            return
        self._target = dataclasses.replace(self._target, name=name)
        if self._home is not None and self._home.key == self._target.key:
            self._home = self._target
        self._set_title(self._target)

    def refresh(self) -> None:
        for widget in (self._notes, self._tags, self._group_notes, self._group_tags):
            widget.reload(force=True)
        self._similar.reload(force=True)
        self._files.reload(force=True)

    def current_target(self) -> Optional[ProcTarget]:
        return self._target

    # -- internals -----------------------------------------------------------
    def _set_title(self, target: ProcTarget) -> None:
        self._title.setText(target.name or target.rva)
        self._title.setVisible(True)
        self._address.setText(target.rva if target.name else "")
        self._address.setVisible(bool(target.name))
        self._remote.setText("" if target.local else f"· remote file {style.short_hash(target.binary_id, 12)}")
        self._remote.setToolTip(target.binary_id)
        self._title.setToolTip(f"{target.title}\nfile {target.binary_id}")

    def _fill_overview(self, proc: Optional[models.Procedure]) -> None:
        self._ov_api.clear()
        self._ov_strings.clear()
        if proc is None:
            self._ov_status.setText("")
            self._ov_counts.setText("")
            self._ov_hash.setText("")
            return
        self._ov_status.setText(proc.status or "-")
        self._ov_counts.setText(f"{proc.block_count} blocks · {proc.code_count} instructions · seen in {proc.occurrence_count:,} files")
        self._ov_hash.setText(proc.hard_hash or "-")
        self._ov_api.addItems(proc.api_calls or ["(none)"])
        self._ov_strings.addItems(proc.strings or ["(none)"])

    def _on_tab(self, index: int) -> None:
        if self._target is None:
            return
        if index == TAB_NOTES:
            self._notes.reload()
        elif index == TAB_SIMILAR:
            self._similar.reload()
            self._files.reload()
        elif index == TAB_GROUP:
            self._group_notes.reload()
            self._group_tags.reload()

    def _inspect_similar(self, proc: models.SimilarProcedure) -> None:
        if self._target is None:
            return
        local = proc.binary_id == self._target.binary_id
        self.show_procedure(ProcTarget(binary_id=proc.binary_id, rva=proc.start_ea, local=local), home=False)

    def _jump_similar(self, proc: models.SimilarProcedure) -> None:
        self.jump_requested.emit(ProcTarget(binary_id=proc.binary_id, rva=proc.start_ea, local=True))

    def _go_home(self) -> None:
        self.show_procedure(self._home, home=True)


# --------------------------------------------------------------------------
# Inspector container
# --------------------------------------------------------------------------


class InspectorView(QtWidgets.QFrame):
    """Card holding the File / Procedure tabs."""

    def __init__(self, client_provider: ClientProvider, parent=None):
        super().__init__(parent)
        self.setObjectName("ucCard")
        if not brand.is_active():
            self.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)
        self._tabs = QtWidgets.QTabWidget(self)
        self._tabs.setDocumentMode(True)
        self._tabs.tabBar().setProperty("outer", True)
        self.file_tab = FileTab(client_provider, self._tabs)
        self.procedure_tab = ProcedureTab(client_provider, self._tabs)
        self._tabs.addTab(self.file_tab, "File")
        self._tabs.addTab(self.procedure_tab, "Procedure")
        layout.addWidget(self._tabs, 1)
        self.file_tab.inspect_file_requested.connect(self.inspect_file)
        self.procedure_tab.inspect_file_requested.connect(self.inspect_file)

    # QTabWidget-compatible surface used by the panel and the tests.
    def setCurrentWidget(self, widget) -> None:  # noqa: N802
        self._tabs.setCurrentWidget(widget)

    def currentWidget(self):  # noqa: N802
        return self._tabs.currentWidget()

    def inspect_file(self, binary_id: str) -> None:
        if not binary_id:
            return
        self.file_tab.show_file(binary_id, home=False)
        self._tabs.setCurrentWidget(self.file_tab)

    def show_procedure(self, target: Optional[ProcTarget]) -> None:
        self.procedure_tab.show_procedure(target, home=True)
        if target is not None:
            self._tabs.setCurrentWidget(self.procedure_tab)
