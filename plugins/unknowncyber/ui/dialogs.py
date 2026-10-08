"""Reusable dialogs and the inline banner widget."""

from __future__ import annotations

from typing import Callable, Optional

from ..qt import QtCore, QtWidgets, Signal, exec_dialog
from . import brand, style

Qt = QtCore.Qt


# --------------------------------------------------------------------------
# Inline banner (replaces most modal popups)
# --------------------------------------------------------------------------


class Banner(QtWidgets.QFrame):
    """One-line message with an optional action button.  Hidden when empty."""

    action_triggered = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("ucBanner")
        if not brand.is_active():
            self.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
        self._kind = "info"
        self._label = QtWidgets.QLabel(self)
        self._label.setWordWrap(True)
        self._label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self._action = QtWidgets.QPushButton(self)
        self._action.setCursor(Qt.CursorShape.PointingHandCursor)
        self._action.hide()
        self._action.clicked.connect(self.action_triggered)
        self._close = style.tool_button("✕", "Dismiss", self)
        self._close.setProperty("role", "close")
        self._close.clicked.connect(self.clear)
        layout = QtWidgets.QHBoxLayout(self)
        layout.setContentsMargins(10, 6, 6, 6)
        layout.setSpacing(8)
        layout.addWidget(self._label, 1)
        layout.addWidget(self._action)
        layout.addWidget(self._close)
        self.hide()

    def show_message(self, text: str, kind: str = "info", action: Optional[str] = None, closable: bool = True) -> None:
        self._kind = kind
        self._label.setText(text)
        self._action.setVisible(bool(action))
        if action:
            self._action.setText(action)
        self._close.setVisible(closable)
        if brand.is_active():
            color = brand.STATUS_COLORS.get(kind, brand.TEXT_MUTED)
            self.setStyleSheet(
                "QFrame#ucBanner {"
                f" border: 1px solid {brand.rgba(color, 0.55)}; background-color: {brand.rgba(color, 0.10)};"
                f" border-radius: {brand.RADIUS}px; }}"
                f"QFrame#ucBanner QLabel {{ border: none; background: transparent; color: {brand.TEXT}; }}"
            )
        else:
            color = style.accent(kind, self)
            self.setStyleSheet(
                "QFrame {"
                f" border: 1px solid rgba({color.red()},{color.green()},{color.blue()},140);"
                f" background-color: rgba({color.red()},{color.green()},{color.blue()},28);"
                " border-radius: 4px; }"
                "QLabel { border: none; background: transparent; }"
            )
        self.show()

    def info(self, text: str, action: Optional[str] = None) -> None:
        self.show_message(text, "info", action)

    def warning(self, text: str, action: Optional[str] = None) -> None:
        self.show_message(text, "warning", action)

    def error(self, text: str, action: Optional[str] = None) -> None:
        self.show_message(text, "error", action)

    def success(self, text: str) -> None:
        self.show_message(text, "success")

    def clear(self) -> None:
        self._label.clear()
        self.hide()


# --------------------------------------------------------------------------
# Text editor dialog (notes, renames)
# --------------------------------------------------------------------------


class TextEditorDialog(QtWidgets.QDialog):
    def __init__(self, title: str, initial: str = "", *, multiline: bool = True, placeholder: str = "", parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(460)
        brand.apply(self)
        self._multiline = multiline
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)
        if multiline:
            self._edit = QtWidgets.QPlainTextEdit(self)
            self._edit.setPlainText(initial)
            self._edit.setPlaceholderText(placeholder)
            self._edit.setMinimumHeight(160)
            self._edit.setTabChangesFocus(True)
        else:
            self._edit = QtWidgets.QLineEdit(self)
            self._edit.setText(initial)
            self._edit.setPlaceholderText(placeholder)
        layout.addWidget(self._edit)
        buttons = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.StandardButton.Save | QtWidgets.QDialogButtonBox.StandardButton.Cancel, self
        )
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        self._save = buttons.button(QtWidgets.QDialogButtonBox.StandardButton.Save)
        self._save.setProperty("role", "primary")
        layout.addWidget(buttons)
        self._edit.textChanged.connect(self._update_state)
        self._update_state()
        if not multiline:
            self._edit.returnPressed.connect(self._accept)
        self._edit.setFocus()
        if initial:
            self._edit.selectAll()

    def text(self) -> str:
        return (self._edit.toPlainText() if self._multiline else self._edit.text()).strip()

    def _update_state(self):
        self._save.setEnabled(bool(self.text()))

    def _accept(self):
        if self.text():
            self.accept()

    @classmethod
    def ask(cls, parent, title: str, initial: str = "", *, multiline: bool = True, placeholder: str = "") -> Optional[str]:
        dialog = cls(title, initial, multiline=multiline, placeholder=placeholder, parent=parent)
        if exec_dialog(dialog) == QtWidgets.QDialog.DialogCode.Accepted:
            return dialog.text()
        return None


def confirm(parent, title: str, text: str, ok_label: str = "Delete") -> bool:
    box = QtWidgets.QMessageBox(parent)
    box.setIcon(QtWidgets.QMessageBox.Icon.Warning)
    box.setWindowTitle(title)
    box.setText(text)
    ok = box.addButton(ok_label, QtWidgets.QMessageBox.ButtonRole.DestructiveRole)
    box.addButton(QtWidgets.QMessageBox.StandardButton.Cancel)
    box.setDefaultButton(QtWidgets.QMessageBox.StandardButton.Cancel)
    exec_dialog(box)
    return box.clickedButton() is ok


def show_error(parent, title: str, text: str) -> None:
    QtWidgets.QMessageBox.critical(parent, title, text)


# --------------------------------------------------------------------------
# Upload chooser
# --------------------------------------------------------------------------


class UploadDialog(QtWidgets.QDialog):
    """Pick what to upload: one card per option (design 1g)."""

    BINARY = "binary"
    IDB = "idb"
    DISASSEMBLY = "disassembly"

    def __init__(self, *, binary_available: bool, sark_available: bool, undo_available: bool, create_functions: bool, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Upload to Unknown Cyber")
        self.setMinimumWidth(500)
        brand.apply(self)
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        self._choices = QtWidgets.QButtonGroup(self)
        self._cards = {}
        self._binary, binary_body = self._option(
            layout,
            self.BINARY,
            "Original binary",
            "Upload the executable itself. The server unpacks and disassembles it.",
            enabled=binary_available,
            disabled_reason="The original binary is not available on disk." if not binary_available else "",
        )
        self._skip_unpack = QtWidgets.QCheckBox("Skip unpacking on the server", self)
        self._skip_unpack.setToolTip("Enable when the file is not packed, or when you want the raw file analysed as-is.")
        binary_body.addWidget(self._skip_unpack)

        self._idb, _ = self._option(
            layout,
            self.IDB,
            "IDA database (.i64)",
            "Upload a copy of this database. Your names and function boundaries are used server-side.",
        )
        self._disasm, disasm_body = self._option(
            layout,
            self.DISASSEMBLY,
            "Disassembly export",
            "Export procedures, blocks and control-flow from this database and upload them.",
            enabled=sark_available and undo_available,
            disabled_reason=(
                "The 'sark' package is not installed; see requirements.txt."
                if not sark_available
                else ("Undo is not available in this IDA build." if not undo_available else "")
            ),
        )
        self._create_funcs = QtWidgets.QCheckBox("Create functions for unclaimed push ebp / mov ebp, esp prologues", self)
        self._create_funcs.setChecked(create_functions)
        disasm_body.addWidget(self._create_funcs)
        note = brand.muted(
            "The export temporarily rebases and normalises the database; the changes are reverted "
            "automatically through an undo point (Edit ▸ Undo shows the step)."
        )
        note.setProperty("role", "hint")
        note.setWordWrap(True)
        disasm_body.addWidget(note)

        buttons = QtWidgets.QHBoxLayout()
        buttons.setSpacing(8)
        buttons.addStretch(1)
        cancel = QtWidgets.QPushButton("Cancel", self)
        cancel.clicked.connect(self.reject)
        self._ok = brand.primary_button("Upload", self)
        self._ok.clicked.connect(self.accept)
        buttons.addWidget(cancel)
        buttons.addWidget(self._ok)
        layout.addLayout(buttons)

        first_enabled = next((b for b in (self._binary, self._idb, self._disasm) if b.isEnabled()), None)
        if first_enabled is not None:
            first_enabled.setChecked(True)
        self._ok.setEnabled(first_enabled is not None)
        self._choices.buttonToggled.connect(lambda *_: self._sync())
        self._sync()

    def _option(self, layout, key, title, description, enabled=True, disabled_reason=""):
        card = QtWidgets.QFrame(self)
        card.setObjectName("ucOption")
        if not brand.is_active():
            card.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
        box = QtWidgets.QVBoxLayout(card)
        box.setContentsMargins(12, 10, 12, 10)
        box.setSpacing(4)
        radio = QtWidgets.QRadioButton(title, card)
        radio.setProperty("uploadKind", key)
        radio.setEnabled(enabled)
        radio.setCursor(Qt.CursorShape.PointingHandCursor)
        font = radio.font()
        font.setBold(True)
        radio.setFont(font)
        self._choices.addButton(radio)
        box.addWidget(radio)
        body = QtWidgets.QVBoxLayout()
        body.setContentsMargins(24, 0, 0, 0)
        body.setSpacing(4)
        desc = brand.muted(description, card)
        desc.setWordWrap(True)
        body.addWidget(desc)
        if disabled_reason:
            reason = QtWidgets.QLabel(disabled_reason, card)
            reason.setProperty("role", "warn")
            reason.setWordWrap(True)
            if not brand.is_active():
                reason.setStyleSheet(f"color: {style.accent('warning', card).name()};")
            body.addWidget(reason)
        box.addLayout(body)
        card.setEnabled(enabled)
        card.mousePressEvent = lambda _event, r=radio: r.isEnabled() and r.setChecked(True)  # type: ignore[method-assign]
        layout.addWidget(card)
        self._cards[radio] = card
        return radio, body

    def _sync(self):
        self._skip_unpack.setEnabled(self._binary.isChecked())
        self._create_funcs.setEnabled(self._disasm.isChecked())
        for radio, card in self._cards.items():
            selected = radio.isChecked()
            if card.property("selected") != selected:
                card.setProperty("selected", selected)
                brand.repolish(card)

    @property
    def kind(self) -> Optional[str]:
        button = self._choices.checkedButton()
        return button.property("uploadKind") if button is not None else None

    @property
    def skip_unpack(self) -> bool:
        return self._skip_unpack.isChecked()

    @property
    def create_functions(self) -> bool:
        return self._create_funcs.isChecked()


# --------------------------------------------------------------------------
# Busy overlay helper
# --------------------------------------------------------------------------


class BusyIndicator(QtWidgets.QWidget):
    """Indeterminate progress bar + label, shown while a view is loading."""

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QtWidgets.QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self._bar = QtWidgets.QProgressBar(self)
        self._bar.setRange(0, 0)
        self._bar.setTextVisible(False)
        self._bar.setFixedHeight(4 if brand.is_active() else 6)
        self._label = brand.muted("Loading…", self)
        self._label.setProperty("role", "hint")
        layout.addWidget(self._label)
        layout.addWidget(self._bar, 1)
        self.hide()

    def start(self, text: str = "Loading…") -> None:
        self._label.setText(text)
        self.show()

    def stop(self) -> None:
        self.hide()


def run_later(fn: Callable[[], None], msec: int = 0) -> None:
    QtCore.QTimer.singleShot(msec, fn)
