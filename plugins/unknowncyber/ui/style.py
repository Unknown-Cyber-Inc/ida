"""Small, theme-aware styling helpers.

IDA ships light and dark themes; nothing here hard-codes a background colour.
Accent colours are derived from the active palette so chips and banners stay
readable in both.
"""

from __future__ import annotations

from ..qt import QtCore, QtGui, QtWidgets

Qt = QtCore.Qt


def is_dark(widget: QtWidgets.QWidget) -> bool:
    return widget.palette().color(QtGui.QPalette.ColorRole.Window).lightness() < 128


def accent(kind: str, widget: QtWidgets.QWidget) -> QtGui.QColor:
    dark = is_dark(widget)
    table = {
        "info": ("#2f6fed", "#7aa6ff"),
        "success": ("#1f8f4e", "#5fd38a"),
        "warning": ("#b26a00", "#ffb84d"),
        "error": ("#c62828", "#ff7b7b"),
        "muted": ("#6b7280", "#9ca3af"),
        "brand": ("#1f7f95", "#55e0fa"),
        "tag": ("#8a2a93", "#e688ff"),
    }
    light, darkc = table.get(kind, table["muted"])
    return QtGui.QColor(darkc if dark else light)


def monospace_font(pixel_size: int = 12) -> QtGui.QFont:
    """The system fixed-pitch font at a fixed pixel size (identical under PyQt5 and PySide6)."""
    font = QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.SystemFont.FixedFont)
    font.setPixelSize(pixel_size)
    return font


def chip(text: str, kind: str = "muted", parent: QtWidgets.QWidget | None = None) -> QtWidgets.QLabel:
    """A rounded label used for statuses and tags."""
    label = QtWidgets.QLabel(text, parent)
    label.setProperty("chipKind", kind)
    label.setAlignment(Qt.AlignmentFlag.AlignCenter)
    restyle_chip(label)
    return label


def restyle_chip(label: QtWidgets.QLabel) -> None:
    kind = label.property("chipKind") or "muted"
    color = accent(kind, label)
    bg = QtGui.QColor(color)
    bg.setAlpha(40)
    label.setStyleSheet(
        "QLabel {"
        f" color: {color.name()};"
        f" background-color: rgba({bg.red()},{bg.green()},{bg.blue()},{bg.alpha()});"
        f" border: 1px solid rgba({color.red()},{color.green()},{color.blue()},120);"
        " border-radius: 9px; padding: 1px 8px; font-size: 11px; }"
    )


def heading(text: str, parent=None) -> QtWidgets.QLabel:
    label = QtWidgets.QLabel(text, parent)
    font = label.font()
    font.setBold(True)
    label.setFont(font)
    return label


def muted(text: str, parent=None) -> QtWidgets.QLabel:
    label = QtWidgets.QLabel(text, parent)
    color = accent("muted", label)
    label.setStyleSheet(f"color: {color.name()};")
    return label


def short_hash(value: str, keep: int = 12) -> str:
    value = value or ""
    return value if len(value) <= keep else value[:keep] + "…"


def tool_button(text: str, tooltip: str = "", parent=None) -> QtWidgets.QToolButton:
    button = QtWidgets.QToolButton(parent)
    button.setText(text)
    button.setToolTip(tooltip or text)
    button.setAutoRaise(True)
    button.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextOnly)
    button.setCursor(Qt.CursorShape.PointingHandCursor)
    return button


def copy_to_clipboard(text: str) -> None:
    QtWidgets.QApplication.clipboard().setText(text or "")


def elide(label: QtWidgets.QLabel, text: str, width: int) -> None:
    metrics = QtGui.QFontMetrics(label.font())
    label.setText(metrics.elidedText(text, Qt.TextElideMode.ElideMiddle, width))
    label.setToolTip(text)
