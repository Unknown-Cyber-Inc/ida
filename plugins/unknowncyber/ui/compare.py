"""Side-by-side procedure comparison with line diff highlighting."""

from __future__ import annotations

import difflib
from typing import List, Tuple

from .. import models
from ..qt import QtCore, QtGui, QtWidgets
from . import brand, style

Qt = QtCore.Qt


class _CodePane(QtWidgets.QWidget):
    def __init__(self, title: str, code: models.ProcedureCode, parent=None):
        super().__init__(parent)
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        layout.addWidget(style.heading(title, self))
        name = code.name or "(unnamed)"
        meta = brand.muted(f"{name} @ {code.start_ea} · File {style.short_hash(code.binary_id, 20)}", self)
        meta.setProperty("role", "hint")
        meta.setToolTip(code.binary_id)
        meta.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(meta)
        self.editor = QtWidgets.QPlainTextEdit(self)
        self.editor.setReadOnly(True)
        self.editor.setFont(style.monospace_font())
        self.editor.setLineWrapMode(QtWidgets.QPlainTextEdit.LineWrapMode.NoWrap)
        self.editor.setPlainText(code.text)
        layout.addWidget(self.editor, 1)


class CompareDialog(QtWidgets.QDialog):
    def __init__(self, left: models.ProcedureCode, right: models.ProcedureCode, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Compare procedures")
        self.resize(1000, 640)
        self.setWindowFlag(Qt.WindowType.WindowMaximizeButtonHint, True)
        brand.apply(self)
        self._syncing = False

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)
        top = QtWidgets.QHBoxLayout()
        top.setSpacing(12)
        self._lock = QtWidgets.QCheckBox("Synchronise scrolling", self)
        self._lock.setChecked(True)
        self._highlight = QtWidgets.QCheckBox("Highlight differences", self)
        self._highlight.setChecked(True)
        self._stats = QtWidgets.QLabel("", self)
        self._stats.setTextFormat(Qt.TextFormat.RichText)
        self._meter = brand.Meter(self)
        top.addWidget(self._lock)
        top.addWidget(self._highlight)
        top.addStretch(1)
        top.addWidget(self._stats)
        top.addWidget(self._meter)
        layout.addLayout(top)

        splitter = QtWidgets.QSplitter(Qt.Orientation.Horizontal, self)
        self._left = _CodePane("This procedure", left, splitter)
        self._right = _CodePane("Similar procedure", right, splitter)
        splitter.addWidget(self._left)
        splitter.addWidget(self._right)
        splitter.setSizes([500, 500])
        layout.addWidget(splitter, 1)

        buttons = QtWidgets.QHBoxLayout()
        buttons.addStretch(1)
        close = QtWidgets.QPushButton("Close", self)
        close.clicked.connect(self.accept)
        buttons.addWidget(close)
        layout.addLayout(buttons)

        self._left.editor.verticalScrollBar().valueChanged.connect(lambda v: self._sync(self._left, self._right, v))
        self._right.editor.verticalScrollBar().valueChanged.connect(lambda v: self._sync(self._right, self._left, v))
        self._highlight.toggled.connect(self._apply_highlight)
        self._apply_highlight(True)

    def _sync(self, source: _CodePane, target: _CodePane, value: int) -> None:
        if self._syncing or not self._lock.isChecked():
            return
        self._syncing = True
        try:
            src_bar = source.editor.verticalScrollBar()
            dst_bar = target.editor.verticalScrollBar()
            span = src_bar.maximum() - src_bar.minimum()
            ratio = (value - src_bar.minimum()) / span if span else 0.0
            dst_bar.setValue(int(dst_bar.minimum() + ratio * (dst_bar.maximum() - dst_bar.minimum())))
        finally:
            self._syncing = False

    def _apply_highlight(self, enabled: bool) -> None:
        left_lines = self._left.editor.toPlainText().split("\n")
        right_lines = self._right.editor.toPlainText().split("\n")
        if not enabled:
            self._left.editor.setExtraSelections([])
            self._right.editor.setExtraSelections([])
            self._stats.setText("")
            self._meter.hide()
            return
        left_changed, right_changed, same = diff_lines(left_lines, right_lines)
        self._paint(self._left.editor, left_changed, "error")
        self._paint(self._right.editor, right_changed, "success")
        total = max(len(left_lines), len(right_lines), 1)
        muted = brand.TEXT_MUTED if brand.is_active() else style.accent("muted", self).name()
        error = brand.ERROR if brand.is_active() else style.accent("error", self).name()
        success = brand.SUCCESS if brand.is_active() else style.accent("success", self).name()
        self._stats.setText(
            f'<span style="color:{muted}">{same} identical</span> · '
            f'<span style="color:{error}">{len(left_changed)} only here</span> · '
            f'<span style="color:{success}">{len(right_changed)} only there</span>'
        )
        self._meter.show()
        self._meter.set_value(same / total)

    def _paint(self, editor: QtWidgets.QPlainTextEdit, lines: List[int], kind: str) -> None:
        if brand.is_active():
            color = brand.qcolor(brand.ERROR if kind == "error" else brand.SUCCESS, 0.20)
        else:
            color = style.accent(kind, editor)
            color.setAlpha(60)
        selections = []
        document = editor.document()
        for line_no in lines:
            block = document.findBlockByNumber(line_no)
            if not block.isValid():
                continue
            selection = QtWidgets.QTextEdit.ExtraSelection()
            selection.format.setBackground(color)
            selection.format.setProperty(QtGui.QTextFormat.Property.FullWidthSelection, True)
            cursor = QtGui.QTextCursor(block)
            selection.cursor = cursor
            selections.append(selection)
        editor.setExtraSelections(selections)


def diff_lines(left: List[str], right: List[str]) -> Tuple[List[int], List[int], int]:
    """Return (changed line numbers on the left, on the right, number of equal lines)."""
    matcher = difflib.SequenceMatcher(None, left, right, autojunk=False)
    left_changed: List[int] = []
    right_changed: List[int] = []
    same = 0
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            same += i2 - i1
            continue
        left_changed.extend(range(i1, i2))
        right_changed.extend(range(j1, j2))
    return left_changed, right_changed, same
