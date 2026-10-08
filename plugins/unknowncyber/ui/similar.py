"""Similar procedures (grouped by file) and files containing the procedure group."""

from __future__ import annotations

from typing import Callable, Dict, List, Optional

from .. import models
from ..qt import QtCore, QtWidgets, Signal
from ..workers import TaskGroup
from . import brand, style
from .dialogs import Banner, BusyIndicator

Qt = QtCore.Qt
ROLE_ITEM = Qt.ItemDataRole.UserRole + 1
ROLE_RATIO = Qt.ItemDataRole.UserRole + 2
COL_FILE, COL_BAR, COL_SIM, COL_BLOCKS, COL_CODE = range(5)


class SimilarProceduresView(QtWidgets.QWidget):
    """Tree of similar procedures grouped by containing file.

    Signals carry :class:`models.SimilarProcedure` instances.
    """

    inspect_requested = Signal(object)
    compare_requested = Signal(object)
    jump_requested = Signal(object)
    count_changed = Signal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._tasks = TaskGroup(self)
        self._loader: Optional[Callable[[], List[models.SimilarProcedure]]] = None
        self._loaded_key: Optional[str] = None
        self._key = ""
        self._current_binary = ""
        self.count = 0

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        toolbar = QtWidgets.QHBoxLayout()
        toolbar.setSpacing(8)
        toolbar.addWidget(style.heading("Similar procedures", self))
        self._count = brand.muted("", self)
        toolbar.addWidget(self._count)
        toolbar.addStretch(1)
        self._inspect = QtWidgets.QPushButton("Inspect", self)
        self._compare = brand.primary_button("Compare", self)
        self._jump = QtWidgets.QPushButton("Jump", self)
        self._refresh = brand.icon_button("⟳", "Reload", self)
        for b in (self._inspect, self._compare, self._jump):
            b.setEnabled(False)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
        toolbar.addWidget(self._inspect)
        toolbar.addWidget(self._compare)
        toolbar.addWidget(self._jump)
        toolbar.addWidget(self._refresh)
        layout.addLayout(toolbar)

        self._banner = Banner(self)
        layout.addWidget(self._banner)
        self._busy = BusyIndicator(self)
        layout.addWidget(self._busy)

        self._tree = QtWidgets.QTreeWidget(self)
        self._tree.setHeaderLabels(["File / address", "Similarity", "", "Blk", "Code"])
        self._tree.setRootIsDecorated(True)
        self._tree.setIndentation(18)
        self._tree.setAlternatingRowColors(False)
        self._tree.setUniformRowHeights(True)
        self._tree.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.SingleSelection)
        self._tree.header().setStretchLastSection(False)
        self._tree.header().setSectionResizeMode(COL_FILE, QtWidgets.QHeaderView.ResizeMode.Stretch)
        self._tree.setColumnWidth(COL_BAR, 78)
        self._tree.setColumnWidth(COL_SIM, 42)
        self._tree.setColumnWidth(COL_BLOCKS, 44)
        self._tree.setColumnWidth(COL_CODE, 48)
        bar_color = brand.PINK if brand.is_active() else style.accent("tag", self).name()
        self._bar_delegate = brand.BarDelegate(lambda index: index.data(ROLE_RATIO), bar_color, self._tree)
        self._tree.setItemDelegateForColumn(COL_BAR, self._bar_delegate)
        if brand.is_active():
            self._row_delegate = brand.RowDelegate(self._tree, muted_columns=(COL_SIM, COL_BLOCKS, COL_CODE), inset_column=None)
            self._tree.setItemDelegate(self._row_delegate)
            self._tree.setItemDelegateForColumn(COL_BAR, self._bar_delegate)
        self._tree.itemSelectionChanged.connect(self._update_buttons)
        self._tree.itemDoubleClicked.connect(lambda *_: self._emit(self.inspect_requested))
        layout.addWidget(self._tree, 1)

        self._empty = brand.muted("No similar procedures above the similarity threshold.", self)
        self._empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._empty.hide()
        layout.addWidget(self._empty)

        self._inspect.clicked.connect(lambda: self._emit(self.inspect_requested))
        self._compare.clicked.connect(lambda: self._emit(self.compare_requested))
        self._jump.clicked.connect(lambda: self._emit(self.jump_requested))
        self._refresh.clicked.connect(lambda: self.reload(force=True))

    # -- public --------------------------------------------------------------
    def set_loader(self, key: str, current_binary: str, loader: Optional[Callable[[], List[models.SimilarProcedure]]]) -> None:
        self._tasks.invalidate()
        self._busy.stop()
        self._banner.clear()
        self._loader = loader
        self._current_binary = current_binary
        if key != self._loaded_key:
            self._tree.clear()
            self._count.setText("")
            self._empty.hide()
            self._loaded_key = None
            self.count = 0
            self.count_changed.emit(0)
        self._key = key
        self.setEnabled(loader is not None)
        self._update_buttons()

    def reload(self, force: bool = False) -> None:
        loader = self._loader
        if loader is None or (not force and self._loaded_key == self._key):
            return
        self._tasks.invalidate()
        self._banner.clear()
        self._busy.start("Loading similar procedures…")
        key = self._key

        def done(items):
            if self._loader is not loader:
                return
            self._loaded_key = key
            self._populate(list(items))

        self._tasks.run(loader, on_success=done, on_error=lambda exc: self._banner.error(str(exc)), on_finished=self._busy.stop)

    def selected(self) -> Optional[models.SimilarProcedure]:
        items = self._tree.selectedItems()
        if not items:
            return None
        return items[0].data(0, ROLE_ITEM)

    # -- internals -----------------------------------------------------------
    def _populate(self, procs: List[models.SimilarProcedure]) -> None:
        self._tree.clear()
        groups: Dict[str, List[models.SimilarProcedure]] = {}
        for proc in procs:
            groups.setdefault(proc.binary_id, []).append(proc)
        for binary_id, entries in groups.items():
            is_current = binary_id == self._current_binary
            label = f"This file  ({style.short_hash(binary_id, 16)})" if is_current else style.short_hash(binary_id, 24)
            parent = QtWidgets.QTreeWidgetItem([label, "", "", "", ""])
            parent.setToolTip(0, binary_id)
            parent.setFlags(parent.flags() & ~Qt.ItemFlag.ItemIsSelectable)
            font = parent.font(0)
            font.setBold(True)
            parent.setFont(0, font)
            for proc in sorted(entries, key=lambda p: p.start_ea):
                sim = proc.similarity
                child = QtWidgets.QTreeWidgetItem(
                    [proc.start_ea, "", f"{sim:.2f}" if sim is not None else "", str(proc.block_count), str(proc.code_count)]
                )
                child.setFont(0, style.monospace_font())
                child.setFont(COL_SIM, style.monospace_font())
                for col in (COL_SIM, COL_BLOCKS, COL_CODE):
                    child.setTextAlignment(col, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                child.setData(0, ROLE_ITEM, proc)
                child.setData(COL_BAR, ROLE_RATIO, float(sim) if sim is not None else None)  # None: no bar drawn
                parent.addChild(child)
            self._tree.addTopLevelItem(parent)
            parent.setExpanded(is_current or len(groups) <= 3)
        self.count = len(procs)
        self._count.setText(f"({len(procs)} in {len(groups)} files)" if procs else "")
        self.count_changed.emit(self.count)
        self._empty.setVisible(not procs)
        self._tree.setVisible(bool(procs))
        self._update_buttons()

    def _update_buttons(self) -> None:
        proc = self.selected()
        self._inspect.setEnabled(proc is not None)
        self._compare.setEnabled(proc is not None)
        self._jump.setEnabled(proc is not None and proc.binary_id == self._current_binary)

    def _emit(self, signal) -> None:
        proc = self.selected()
        if proc is not None:
            signal.emit(proc)


class ContainingFilesView(QtWidgets.QWidget):
    """Files that contain the selected procedure group."""

    inspect_file_requested = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._tasks = TaskGroup(self)
        self._loader: Optional[Callable[[], List[models.ContainingFile]]] = None
        self._loaded_key: Optional[str] = None
        self._key = ""
        self._current_binary = ""

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        toolbar = QtWidgets.QHBoxLayout()
        toolbar.setSpacing(8)
        toolbar.addWidget(style.heading("Files containing this procedure group", self))
        self._count = brand.muted("", self)
        toolbar.addWidget(self._count)
        toolbar.addStretch(1)
        self._open = QtWidgets.QPushButton("Inspect file", self)
        self._open.setEnabled(False)
        self._refresh = brand.icon_button("⟳", "Reload", self)
        toolbar.addWidget(self._open)
        toolbar.addWidget(self._refresh)
        layout.addLayout(toolbar)
        self._banner = Banner(self)
        layout.addWidget(self._banner)
        self._busy = BusyIndicator(self)
        layout.addWidget(self._busy)
        self._list = QtWidgets.QListWidget(self)
        self._list.setAlternatingRowColors(False)
        if brand.is_active():
            self._list.setItemDelegate(brand.RowDelegate(self._list, muted_columns=(), inset_column=0))
        self._list.itemSelectionChanged.connect(lambda: self._open.setEnabled(bool(self._list.selectedItems())))
        self._list.itemDoubleClicked.connect(lambda _: self._emit())
        layout.addWidget(self._list, 1)
        self._open.clicked.connect(self._emit)
        self._refresh.clicked.connect(lambda: self.reload(force=True))

    def set_loader(self, key: str, current_binary: str, loader) -> None:
        self._tasks.invalidate()
        self._busy.stop()
        self._banner.clear()
        self._loader = loader
        self._current_binary = current_binary
        if key != self._loaded_key:
            self._list.clear()
            self._count.setText("")
            self._loaded_key = None
        self._key = key
        self.setEnabled(loader is not None)

    def reload(self, force: bool = False) -> None:
        loader = self._loader
        if loader is None or (not force and self._loaded_key == self._key):
            return
        self._tasks.invalidate()
        self._banner.clear()
        self._busy.start("Loading files…")
        key = self._key

        def done(files):
            if self._loader is not loader:
                return
            self._loaded_key = key
            self._list.clear()
            for f in files:
                label = f.label if f.sha1 != self._current_binary else f"This file  ({f.label})"
                item = QtWidgets.QListWidgetItem(label)
                item.setToolTip(f.sha1)
                item.setData(Qt.ItemDataRole.UserRole, f.sha1)
                self._list.addItem(item)
            self._count.setText(f"({len(files)})" if files else "(none)")

        self._tasks.run(loader, on_success=done, on_error=lambda exc: self._banner.error(str(exc)), on_finished=self._busy.stop)

    def _emit(self) -> None:
        items = self._list.selectedItems()
        if items:
            self.inspect_file_requested.emit(items[0].data(Qt.ItemDataRole.UserRole))
