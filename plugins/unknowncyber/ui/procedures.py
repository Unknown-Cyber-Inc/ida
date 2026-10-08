"""Procedure list: stats strip, filter row and the table (design 1b).

Filterable, sortable (context menu), synchronised with the disassembler's
cursor.  Behaviour, signals and the model are unchanged from the previous
layout; the visual changes are the stats tiles, the occurrence bar column and
the row delegates.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from .. import models
from ..qt import QtCore, QtWidgets, Signal
from . import brand, style
from .dialogs import Banner, BusyIndicator

Qt = QtCore.Qt

COLUMNS = ("Address", "Name", "", "Occurrences", "Blocks", "Code", "Type", "Notes", "Tags")
COL_ADDRESS, COL_NAME, COL_BAR, COL_OCC, COL_BLOCKS, COL_CODE, COL_TYPE, COL_NOTES, COL_TAGS = range(9)
HIDDEN_COLUMNS = (COL_BLOCKS, COL_CODE, COL_TYPE, COL_NOTES, COL_TAGS)
SORT_ROLE = Qt.ItemDataRole.UserRole + 1
PROC_ROLE = Qt.ItemDataRole.UserRole + 2
RATIO_ROLE = Qt.ItemDataRole.UserRole + 3


class ProcedureTableModel(QtCore.QAbstractTableModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._rows: List[models.Procedure] = []
        self._by_rva: Dict[int, int] = {}
        self.max_occurrence = 0

    # -- data ---------------------------------------------------------------
    def set_procedures(self, procs: List[models.Procedure]) -> None:
        self.beginResetModel()
        self._rows = list(procs)
        self._by_rva = {}
        self.max_occurrence = max((p.occurrence_count for p in self._rows), default=0)
        for index, proc in enumerate(self._rows):
            try:
                self._by_rva[proc.rva] = index
            except ValueError:
                continue
        self.endResetModel()

    def procedures(self) -> List[models.Procedure]:
        return list(self._rows)

    def procedure_at(self, row: int) -> Optional[models.Procedure]:
        return self._rows[row] if 0 <= row < len(self._rows) else None

    def row_for_rva(self, rva: int) -> Optional[int]:
        return self._by_rva.get(rva)

    def replace(self, proc: models.Procedure) -> None:
        for row, existing in enumerate(self._rows):
            if existing.start_ea == proc.start_ea:
                self._rows[row] = proc
                top_left = self.index(row, 0)
                bottom_right = self.index(row, len(COLUMNS) - 1)
                self.dataChanged.emit(top_left, bottom_right)
                return

    # -- QAbstractTableModel ------------------------------------------------
    def rowCount(self, parent=QtCore.QModelIndex()):  # noqa: N802
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QtCore.QModelIndex()):  # noqa: N802
        return 0 if parent.isValid() else len(COLUMNS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):  # noqa: N802
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return COLUMNS[section]
        return None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        proc = self._rows[index.row()]
        col = index.column()
        if role == PROC_ROLE:
            return proc
        if role == RATIO_ROLE:
            return brand.occurrence_ratio(proc.occurrence_count, self.max_occurrence)
        if role in (Qt.ItemDataRole.DisplayRole, SORT_ROLE):
            values = (
                (proc.start_ea, proc.rva if proc.start_ea else 0),
                (proc.name or "", (proc.name or "").lower()),
                ("", proc.occurrence_count),
                (f"{proc.occurrence_count:,}", proc.occurrence_count),
                (str(proc.block_count), proc.block_count),
                (str(proc.code_count), proc.code_count),
                (proc.status or "", proc.status or ""),
                (str(proc.note_count) if proc.note_count else "", proc.note_count),
                (str(proc.tag_count) if proc.tag_count else "", proc.tag_count),
            )
            display, sort_key = values[col]
            return display if role == Qt.ItemDataRole.DisplayRole else sort_key
        if role == Qt.ItemDataRole.TextAlignmentRole and col in (COL_OCC, COL_BLOCKS, COL_CODE, COL_NOTES, COL_TAGS):
            return Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
        if role == Qt.ItemDataRole.FontRole and col == COL_ADDRESS:
            return style.monospace_font()
        if role == Qt.ItemDataRole.ToolTipRole:
            lines = [
                proc.display_name,
                f"{proc.block_count} blocks · {proc.code_count} instructions · {proc.status or 'unknown'}",
                f"Seen in {proc.occurrence_count:,} files · {proc.note_count} notes · {proc.tag_count} tags",
                f"Group hash: {proc.hard_hash or '-'}",
            ]
            if proc.api_calls:
                lines.append("API calls: " + ", ".join(proc.api_calls[:8]) + (" …" if len(proc.api_calls) > 8 else ""))
            return "\n".join(lines)
        return None


class _FilterProxy(QtCore.QSortFilterProxyModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setSortRole(SORT_ROLE)
        self.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self._needle = ""

    def set_needle(self, text: str) -> None:
        self._needle = text.strip().lower()
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row, source_parent):  # noqa: N802
        if not self._needle:
            return True
        proc = self.sourceModel().procedure_at(source_row)
        if proc is None:
            return False
        haystack = " ".join((proc.start_ea, proc.name or "", proc.hard_hash or "", proc.status or "", " ".join(proc.api_calls))).lower()
        return all(part in haystack for part in self._needle.split())


class StatsStrip(QtWidgets.QWidget):
    """Three tiles: procedures · with matches · annotated."""

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QtWidgets.QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        self._tiles = {}
        for key, caption, color in (
            ("procedures", "procedures", brand.TEXT_STRONG),
            ("matches", "with matches", brand.CYAN),
            ("annotated", "annotated", brand.PINK),
        ):
            frame, number = brand.stat_tile("–", caption, color, self)
            layout.addWidget(frame, 1)
            self._tiles[key] = number

    def set_counts(self, procs: Optional[List[models.Procedure]]) -> None:
        if not procs:
            for number in self._tiles.values():
                number.setText("–")
            return
        self._tiles["procedures"].setText(f"{len(procs):,}")
        self._tiles["matches"].setText(f"{sum(1 for p in procs if p.occurrence_count > 1):,}")
        self._tiles["annotated"].setText(f"{sum(1 for p in procs if p.note_count or p.tag_count):,}")

    def value(self, key: str) -> str:
        return self._tiles[key].text()


class ProceduresView(QtWidgets.QWidget):
    """Table of procedures for the selected analysis version."""

    procedure_selected = Signal(object)  # models.Procedure or None
    jump_requested = Signal(object)  # models.Procedure
    rename_requested = Signal(object)  # models.Procedure
    load_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._image_base = 0
        self._follow_cursor = True
        self._suppress_selection = False
        self._sort_column = COL_ADDRESS
        self._sort_order = Qt.SortOrder.AscendingOrder

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        self.stats = StatsStrip(self)
        layout.addWidget(self.stats)

        toolbar = QtWidgets.QHBoxLayout()
        toolbar.setSpacing(8)
        self._search = QtWidgets.QLineEdit(self)
        self._search.setPlaceholderText("⌕ Filter by address, name, hash or API call…")
        self._search.setClearButtonEnabled(True)
        self._count = brand.muted("", self)
        self._follow = QtWidgets.QCheckBox("Follow cursor", self)
        self._follow.setObjectName("ucFollow")
        self._follow.setChecked(True)
        self._follow.setToolTip("Select the procedure under the disassembler's cursor automatically")
        self._load = QtWidgets.QPushButton("Load procedures", self)
        self._load.setCursor(Qt.CursorShape.PointingHandCursor)
        toolbar.addWidget(self._search, 1)
        toolbar.addWidget(self._count)
        toolbar.addWidget(self._follow)
        toolbar.addWidget(self._load)
        layout.addLayout(toolbar)

        self._banner = Banner(self)
        layout.addWidget(self._banner)
        self._busy = BusyIndicator(self)
        layout.addWidget(self._busy)

        self._model = ProcedureTableModel(self)
        self._proxy = _FilterProxy(self)
        self._proxy.setSourceModel(self._model)
        self._table = QtWidgets.QTableView(self)
        self._table.setModel(self._proxy)
        self._table.setSortingEnabled(True)
        self._table.sortByColumn(COL_ADDRESS, Qt.SortOrder.AscendingOrder)
        self._table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.SingleSelection)
        self._table.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setAlternatingRowColors(False)
        self._table.setShowGrid(False)
        self._table.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self._table.verticalHeader().setVisible(False)
        self._table.verticalHeader().setDefaultSectionSize(brand.RowDelegate.ROW_HEIGHT)
        self._table.verticalHeader().setMinimumSectionSize(brand.RowDelegate.ROW_HEIGHT)
        header = self._table.horizontalHeader()
        header.setVisible(False)
        header.setStretchLastSection(False)
        header.setSectionResizeMode(QtWidgets.QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(COL_NAME, QtWidgets.QHeaderView.ResizeMode.Stretch)
        header.setHighlightSections(False)
        for col in HIDDEN_COLUMNS:
            self._table.setColumnHidden(col, True)
        for col, width in ((COL_ADDRESS, 94), (COL_BAR, 98), (COL_OCC, 56)):
            self._table.setColumnWidth(col, width)
        if brand.is_active():
            self._row_delegate = brand.RowDelegate(self._table)
            self._bar_delegate = brand.BarDelegate(lambda index: index.data(RATIO_ROLE), brand.CYAN, self._table)
            self._table.setItemDelegate(self._row_delegate)
            self._table.setItemDelegateForColumn(COL_BAR, self._bar_delegate)
        else:
            self._row_delegate = None
            self._bar_delegate = brand.BarDelegate(lambda index: index.data(RATIO_ROLE), style.accent("brand", self).name(), self._table)
            self._table.setItemDelegateForColumn(COL_BAR, self._bar_delegate)
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._context_menu)
        self._table.doubleClicked.connect(lambda _: self._emit_jump())
        self._table.selectionModel().selectionChanged.connect(self._on_selection)
        layout.addWidget(self._table, 1)

        self._empty = brand.muted("No procedures loaded. Select an analysis version and click 'Load procedures'.", self)
        self._empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._empty.setWordWrap(True)
        layout.addWidget(self._empty, 1)

        self._search.textChanged.connect(self._on_filter)
        self._follow.toggled.connect(self._set_follow)
        self._load.clicked.connect(self.load_requested)
        self._table.hide()
        self._set_follow(True)

    # -- public --------------------------------------------------------------
    @property
    def banner(self) -> Banner:
        return self._banner

    @property
    def table(self) -> QtWidgets.QTableView:
        return self._table

    def set_image_base(self, image_base: int) -> None:
        self._image_base = int(image_base)

    def set_loading(self, loading: bool) -> None:
        self._load.setEnabled(not loading)
        if loading:
            self._busy.start("Loading procedures…")
        else:
            self._busy.stop()

    def set_procedures(self, procs: List[models.Procedure]) -> None:
        self._model.set_procedures(procs)
        self.stats.set_counts(procs)
        self._table.setVisible(bool(procs))
        self._empty.setVisible(not procs)
        self._load.setText("Reload" if procs else "Load procedures")
        self._apply_sort()
        self._update_count()
        self.procedure_selected.emit(None)

    def clear(self) -> None:
        self.set_procedures([])
        self._banner.clear()

    def procedures(self) -> List[models.Procedure]:
        return self._model.procedures()

    def update_procedure(self, proc: models.Procedure) -> None:
        self._model.replace(proc)

    def selected(self) -> Optional[models.Procedure]:
        indexes = self._table.selectionModel().selectedRows()
        if not indexes:
            return None
        return self._proxy.data(indexes[0], PROC_ROLE)

    def select_rva(self, rva: int, *, from_cursor: bool = False) -> bool:
        row = self._model.row_for_rva(rva)
        if row is None:
            return False
        source_index = self._model.index(row, 0)
        proxy_index = self._proxy.mapFromSource(source_index)
        if not proxy_index.isValid():
            return False
        self._suppress_selection = from_cursor
        try:
            self._table.selectRow(proxy_index.row())
            self._table.scrollTo(proxy_index, QtWidgets.QAbstractItemView.ScrollHint.EnsureVisible)
        finally:
            self._suppress_selection = False
        if from_cursor:
            self.procedure_selected.emit(self.selected())
        return True

    def on_cursor_function(self, function_ea: Optional[int]) -> None:
        """Called from the cursor hook with the containing function's start address."""
        if not self._follow_cursor or function_ea is None or not self._table.isVisible():
            return
        current = self.selected()
        for candidate in (function_ea - self._image_base, function_ea):
            if candidate < 0:
                continue
            if current is not None and current.rva == candidate:
                return
            if self.select_rva(candidate, from_cursor=True):
                return

    def focus_search(self) -> None:
        self._search.setFocus()
        self._search.selectAll()

    def sort_by(self, column: int, order=Qt.SortOrder.AscendingOrder) -> None:
        self._sort_column, self._sort_order = column, order
        self._apply_sort()

    # -- internals -----------------------------------------------------------
    def _apply_sort(self) -> None:
        self._table.sortByColumn(self._sort_column, self._sort_order)

    def _set_follow(self, enabled: bool) -> None:
        self._follow_cursor = enabled
        self._follow.setText(("◉ Following cursor" if enabled else "○ Follow cursor") if brand.is_active() else "Follow cursor")

    def _on_filter(self, text: str) -> None:
        self._proxy.set_needle(text)
        self._update_count()

    def _update_count(self) -> None:
        total = self._model.rowCount()
        shown = self._proxy.rowCount()
        self._count.setText(f"{shown:,} of {total:,}" if shown != total else "")
        self._count.setVisible(shown != total)

    def _on_selection(self, *_):
        if self._suppress_selection:
            return
        self.procedure_selected.emit(self.selected())

    def _emit_jump(self) -> None:
        proc = self.selected()
        if proc is not None:
            self.jump_requested.emit(proc)

    def _context_menu(self, pos) -> None:
        proc = self.selected()
        menu = QtWidgets.QMenu(self)
        if proc is not None:
            menu.addAction("Navigate to", self._emit_jump)
            menu.addAction("Rename on server…", lambda: self.rename_requested.emit(proc))
            menu.addSeparator()
            menu.addAction("Copy address", lambda: style.copy_to_clipboard(proc.start_ea))
            if proc.hard_hash:
                menu.addAction("Copy group hash", lambda: style.copy_to_clipboard(proc.hard_hash))
            menu.addSeparator()
        sort_menu = menu.addMenu("Sort by")
        for label, column, order in (
            ("Address", COL_ADDRESS, Qt.SortOrder.AscendingOrder),
            ("Name", COL_NAME, Qt.SortOrder.AscendingOrder),
            ("Occurrences", COL_OCC, Qt.SortOrder.DescendingOrder),
        ):
            action = sort_menu.addAction(label)
            action.setCheckable(True)
            action.setChecked(column == self._sort_column)
            action.triggered.connect(lambda _=False, c=column, o=order: self.sort_by(c, o))
        runner = getattr(menu, "exec", None) or getattr(menu, "exec_")
        runner(self._table.viewport().mapToGlobal(pos))
