"""Notes lists and tag chip rows with inline create / edit / delete.

The same widgets serve file, procedure and procedure-group annotations.  The
caller supplies an :class:`AnnotationSource` describing how to load and
mutate the list for the current target, so the widgets never know about
hashes or RVAs.

* :class:`AnnotationList` – note cards with Add / Edit / Delete.
* :class:`TagChips` – a wrapping row of tag chips plus a ``+ tag`` chip
  (design 1b); right-click a chip to remove it.
"""

from __future__ import annotations

import dataclasses
from typing import Callable, List, Optional, Sequence, Union

from .. import models
from ..qt import QShortcut, QtCore, QtGui, QtWidgets, Signal
from ..workers import TaskGroup
from . import brand, style
from .dialogs import Banner, BusyIndicator, TextEditorDialog, confirm

Qt = QtCore.Qt
Item = Union[models.Note, models.Tag]


@dataclasses.dataclass
class AnnotationSource:
    kind: str  # "note" | "tag"
    title: str
    list_fn: Callable[[], Sequence[Item]]
    create_fn: Optional[Callable[[str], Item]] = None
    update_fn: Optional[Callable[[str, str], None]] = None  # (item id, new text)
    delete_fn: Optional[Callable[[str], None]] = None
    key: str = ""  # identity of the target; a changed key clears the list

    @property
    def is_note(self) -> bool:
        return self.kind == "note"


def _label_of(item: Item) -> str:
    return item.text if isinstance(item, models.Note) else item.name


class _AnnotationBase(QtWidgets.QWidget):
    """Shared load / mutate plumbing for the two presentations."""

    count_changed = Signal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._tasks = TaskGroup(self)
        self._source: Optional[AnnotationSource] = None
        self._items: List[Item] = []
        self._loaded_key: Optional[str] = None
        self._banner = Banner(self)
        self._busy = BusyIndicator(self)

    # -- public --------------------------------------------------------------
    def set_source(self, source: Optional[AnnotationSource]) -> None:
        self._source = source
        self._tasks.invalidate()
        self._busy.stop()
        self._banner.clear()
        if source is None or source.key != self._loaded_key:
            self._set_items([])
            self._loaded_key = None
        self._on_source_changed()
        self.setEnabled(source is not None)

    def reload(self, force: bool = False) -> None:
        source = self._source
        if source is None:
            return
        if not force and self._loaded_key == source.key:
            return
        self._tasks.invalidate()
        self._banner.clear()
        self._busy.start(f"Loading {source.title.lower()}…")
        key = source.key

        def done(items):
            if self._source is not source:
                return
            self._loaded_key = key
            self._set_items(list(items))

        self._tasks.run(source.list_fn, on_success=done, on_error=self._show_error, on_finished=self._busy.stop)

    @property
    def items(self) -> List[Item]:
        return list(self._items)

    @property
    def loaded(self) -> bool:
        return self._source is not None and self._loaded_key == self._source.key

    # -- to override ---------------------------------------------------------
    def _render(self) -> None:
        raise NotImplementedError

    def _on_source_changed(self) -> None:
        pass

    # -- internals -----------------------------------------------------------
    def _set_items(self, items: List[Item]) -> None:
        self._items = items
        self._render()
        self.count_changed.emit(len(items))

    def _show_error(self, exc: Exception) -> None:
        self._banner.error(str(exc))

    def _mutate(self, work: Callable[[], object], after: Callable[[object], None], busy_text: str) -> None:
        self._banner.clear()
        self._busy.start(busy_text)
        self.setEnabled(False)

        def finished():
            self.setEnabled(True)
            self._busy.stop()

        self._tasks.run(work, on_success=after, on_error=self._show_error, on_finished=finished)

    def _create(self, text: str) -> None:
        source = self._source
        if source is None or source.create_fn is None or not text:
            return
        create = source.create_fn
        self._mutate(lambda: create(text), lambda item: self._set_items(self._items + [item]), "Saving…")

    def _delete(self, item: Item) -> None:
        source = self._source
        if source is None or source.delete_fn is None:
            return
        label = _label_of(item)
        label = label if len(label) <= 80 else label[:77] + "…"
        if not confirm(self, "Delete", f"Delete this {'note' if source.is_note else 'tag'}?\n\n{label}"):
            return
        delete = source.delete_fn
        self._mutate(lambda: delete(item.id), lambda _: self._set_items([i for i in self._items if i.id != item.id]), "Deleting…")


# --------------------------------------------------------------------------
# Notes: cards in a list
# --------------------------------------------------------------------------


class _ItemWidget(QtWidgets.QFrame):
    def __init__(self, item: Item, parent=None):
        super().__init__(parent)
        self.setObjectName("ucNote")
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(3)
        if isinstance(item, models.Note):
            text = QtWidgets.QLabel(item.text, self)
            text.setWordWrap(True)
            text.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            layout.addWidget(text)
        else:
            row = QtWidgets.QHBoxLayout()
            row.setContentsMargins(0, 0, 0, 0)
            row.addWidget(brand.tag_chip(item.name, self))
            row.addStretch(1)
            layout.addLayout(row)
        meta_parts = [p for p in (item.username, item.create_time) if p]
        if meta_parts:
            meta = brand.muted(" · ".join(meta_parts), self)
            meta.setProperty("role", "hint")
            layout.addWidget(meta)


class AnnotationList(_AnnotationBase):
    """A list of notes (or tags, as cards) for one target with CRUD controls."""

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        toolbar = QtWidgets.QHBoxLayout()
        toolbar.setSpacing(8)
        self._title = style.heading("", self)
        self._count = brand.muted("", self)
        self._add = QtWidgets.QPushButton("Add", self)
        self._edit = QtWidgets.QPushButton("Edit", self)
        self._delete = QtWidgets.QPushButton("Delete", self)
        self._refresh = brand.icon_button("⟳", "Reload", self)
        for b in (self._add, self._edit, self._delete):
            b.setCursor(Qt.CursorShape.PointingHandCursor)
        toolbar.addWidget(self._title)
        toolbar.addWidget(self._count)
        toolbar.addStretch(1)
        toolbar.addWidget(self._add)
        toolbar.addWidget(self._edit)
        toolbar.addWidget(self._delete)
        toolbar.addWidget(self._refresh)
        layout.addLayout(toolbar)
        layout.addWidget(self._banner)
        layout.addWidget(self._busy)

        self._list = QtWidgets.QListWidget(self)
        self._list.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.SingleSelection)
        self._list.setAlternatingRowColors(False)
        self._list.setSpacing(2)
        self._list.setVerticalScrollMode(QtWidgets.QAbstractItemView.ScrollMode.ScrollPerPixel)
        self._list.itemSelectionChanged.connect(self._update_buttons)
        self._list.itemDoubleClicked.connect(lambda _: self._on_edit())
        layout.addWidget(self._list, 1)

        self._empty = brand.muted("Nothing here yet.", self)
        self._empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._empty)

        self._add.clicked.connect(self._on_add)
        self._edit.clicked.connect(self._on_edit)
        self._delete.clicked.connect(self._on_delete)
        self._refresh.clicked.connect(lambda: self.reload(force=True))

        delete_shortcut = QShortcut(QtGui.QKeySequence.StandardKey.Delete, self._list)
        delete_shortcut.setContext(Qt.ShortcutContext.WidgetShortcut)
        delete_shortcut.activated.connect(self._on_delete)
        self.set_source(None)

    # -- hooks ---------------------------------------------------------------
    def _on_source_changed(self) -> None:
        self._title.setText(self._source.title if self._source else "")
        self._update_buttons()

    def _render(self) -> None:
        items = self._items
        self._list.clear()
        for item in items:
            row = QtWidgets.QListWidgetItem(self._list)
            widget = _ItemWidget(item, self._list)
            row.setSizeHint(widget.sizeHint())
            row.setData(Qt.ItemDataRole.UserRole, item.id)
            self._list.addItem(row)
            self._list.setItemWidget(row, widget)
        self._count.setText(f"({len(items)})" if items else "")
        self._empty.setVisible(not items and self._source is not None)
        self._list.setVisible(bool(items) or self._source is None)
        self._update_buttons()

    # -- internals -----------------------------------------------------------
    def _selected(self) -> Optional[Item]:
        rows = self._list.selectedItems()
        if not rows:
            return None
        item_id = rows[0].data(Qt.ItemDataRole.UserRole)
        return next((i for i in self._items if i.id == item_id), None)

    def _update_buttons(self) -> None:
        source = self._source
        selected = self._selected()
        self._add.setVisible(bool(source and source.create_fn))
        self._edit.setVisible(bool(source and source.update_fn))
        self._delete.setVisible(bool(source and source.delete_fn))
        self._edit.setEnabled(selected is not None)
        self._delete.setEnabled(selected is not None)
        if source:
            self._add.setText(f"Add {'note' if source.is_note else 'tag'}")

    def _on_add(self) -> None:
        source = self._source
        if source is None or source.create_fn is None:
            return
        if source.is_note:
            text = TextEditorDialog.ask(self, "New note", multiline=True, placeholder="Write a note…")
        else:
            text = TextEditorDialog.ask(self, "New tag", multiline=False, placeholder="Tag name")
        if not text:
            return
        create = source.create_fn

        def after(item):
            self._set_items(self._items + [item])
            self._list.setCurrentRow(self._list.count() - 1)

        self._mutate(lambda: create(text), after, "Saving…")

    def _on_edit(self) -> None:
        source = self._source
        item = self._selected()
        if source is None or source.update_fn is None or item is None:
            return
        current = _label_of(item)
        text = TextEditorDialog.ask(self, "Edit note", current, multiline=True)
        if text is None or text == current:
            return
        update = source.update_fn

        def after(_):
            updated = dataclasses.replace(item, text=text) if isinstance(item, models.Note) else dataclasses.replace(item, name=text)
            self._set_items([updated if i.id == item.id else i for i in self._items])

        self._mutate(lambda: update(item.id, text), after, "Saving…")

    def _on_delete(self) -> None:
        item = self._selected()
        if item is not None:
            self._delete(item)


# --------------------------------------------------------------------------
# Tags: chip row
# --------------------------------------------------------------------------


class TagChips(_AnnotationBase):
    """Wrapping row of tag chips with a trailing ``+ tag`` chip."""

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        self._host = QtWidgets.QWidget(self)
        self._flow = brand.FlowLayout(spacing=6)
        self._host.setLayout(self._flow)
        layout.addWidget(self._host)
        layout.addWidget(self._banner)
        layout.addWidget(self._busy)
        self._chips: List[QtWidgets.QLabel] = []
        self._add = brand.add_tag_chip(self._host)
        self._add.setToolTip("Add a tag")
        self._add.clicked.connect(self._on_add)
        self._empty = brand.muted("No tags", self._host)
        self._empty.setProperty("role", "hint")
        self.set_source(None)

    # -- hooks ---------------------------------------------------------------
    def _render(self) -> None:
        for chip in self._chips:
            self._flow.removeWidget(chip)
            chip.deleteLater()
        self._chips = []
        self._flow.removeWidget(self._add)
        self._flow.removeWidget(self._empty)
        for item in self._items:
            chip = brand.tag_chip(_label_of(item), self._host)
            chip.setToolTip(" · ".join(p for p in (item.username, item.create_time) if p) or "Right-click to remove")
            chip.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
            chip.customContextMenuRequested.connect(lambda pos, c=chip, i=item: self._chip_menu(c, i, pos))
            self._flow.addWidget(chip)
            self._chips.append(chip)
        show_empty = not self._items and self.loaded
        self._empty.setVisible(show_empty)
        if show_empty:
            self._flow.addWidget(self._empty)
        self._add.setVisible(bool(self._source and self._source.create_fn))
        self._flow.addWidget(self._add)
        self._host.updateGeometry()

    def _on_source_changed(self) -> None:
        self._render()

    # -- internals -----------------------------------------------------------
    def _on_add(self) -> None:
        source = self._source
        if source is None or source.create_fn is None:
            return
        text = TextEditorDialog.ask(self, "New tag", multiline=False, placeholder="Tag name")
        if text:
            self._create(text)

    def _chip_menu(self, chip: QtWidgets.QLabel, item: Item, pos) -> None:
        source = self._source
        if source is None or source.delete_fn is None:
            return
        menu = QtWidgets.QMenu(self)
        menu.addAction("Remove tag", lambda: self._delete(item))
        menu.addAction("Copy", lambda: style.copy_to_clipboard(_label_of(item)))
        runner = getattr(menu, "exec", None) or getattr(menu, "exec_")
        runner(chip.mapToGlobal(pos))
