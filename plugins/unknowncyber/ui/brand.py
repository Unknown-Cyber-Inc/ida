"""Unknown Cyber brand layer for the panel (design 1b, "Cards").

Tokens, the scoped stylesheet, small widget builders and the two row
delegates.  Works with the ``qt`` shim (PyQt5 on IDA 8.3-9.1, PySide6 on 9.2+).

The ink look is applied **only on dark themes** (:func:`is_active`); light
themes keep the plain, palette-derived look from :mod:`style`.  Every rule is
scoped to ``#ucPanel`` so the host application's own widgets are never
restyled.
"""

from __future__ import annotations

import math
import os
from typing import Callable, Optional

from ..qt import QtCore, QtGui, QtWidgets
from . import style

Qt = QtCore.Qt

# --------------------------------------------------------------------------- tokens
INK = "#150A24"  # panel background
CARD = "#1D1030"  # card / stat tile surface
CARD_BORDER = "#2F1F48"
PANEL_BORDER = "#2C1D42"
FIELD = "#0F0619"  # line edits, filter
CHIP_BORDER = "#3A2A55"
TRACK = "#2A1C3E"  # bar track

TEXT = "#E4E0EC"
TEXT_STRONG = "#FFFFFF"
TEXT_MUTED = "#9D93B0"
TEXT_PLACEHOLDER = "#6F6585"
CHIP_TEXT = "#B9B0C9"

PRIMARY = "#329DB6"
ON_PRIMARY = "#06141A"
CYAN = "#55E0FA"
MAGENTA = "#A936B3"
PINK = "#E688FF"
TAG_TEXT = "#F0B8FF"

SUCCESS = "#5FD38A"
WARNING = "#FFB84D"
ERROR = "#FF7B7B"
INFO = "#7AA6FF"

RADIUS = 4
RADIUS_CARD = 6
RADIUS_CHIP = 12
RADIUS_PILL = 9

STATUS_COLORS = {"success": SUCCESS, "warning": WARNING, "error": ERROR, "info": INFO, "muted": TEXT_MUTED}


def rgba(hex_color: str, alpha: float) -> str:
    """QSS ``rgba()`` with a 0-255 alpha (Qt 5 does not accept fractional alpha)."""
    c = QtGui.QColor(hex_color)
    return f"rgba({c.red()},{c.green()},{c.blue()},{round(alpha * 255)})"


def qcolor(hex_color: str, alpha: float = 1.0) -> QtGui.QColor:
    c = QtGui.QColor(hex_color)
    c.setAlpha(round(alpha * 255))
    return c


# --------------------------------------------------------------------------- activation
_forced: Optional[bool] = None


APPEARANCE_BRAND = "brand"  # always the ink/cards look (default)
APPEARANCE_AUTO = "auto"  # ink look on dark host themes only
APPEARANCE_PLAIN = "plain"  # never; plain palette-derived widgets
APPEARANCES = (APPEARANCE_BRAND, APPEARANCE_AUTO, APPEARANCE_PLAIN)
_appearance: Optional[str] = None


def appearance() -> str:
    """The configured appearance (cached; :func:`refresh` re-reads it)."""
    global _appearance
    if _appearance is None:
        try:
            from .. import config

            value = (config.load().appearance or APPEARANCE_BRAND).lower()
        except Exception:  # noqa: BLE001 - never let a config problem break the UI
            value = APPEARANCE_BRAND
        _appearance = value if value in APPEARANCES else APPEARANCE_BRAND
    return _appearance


def refresh() -> None:
    """Forget the cached appearance (call after the settings dialog saved)."""
    global _appearance
    _appearance = None


def is_active() -> bool:
    """Whether the ink/cards look is in effect.

    Order: :func:`force` (tests) → ``UNKNOWNCYBER_BRAND=0/1`` → the *Appearance*
    setting (``brand`` = always, the default; ``auto`` = only on dark host
    themes; ``plain`` = never).
    """
    if _forced is not None:
        return _forced
    env = os.environ.get("UNKNOWNCYBER_BRAND")
    if env in ("0", "1"):
        return env == "1"
    mode = appearance()
    if mode == APPEARANCE_PLAIN:
        return False
    if mode == APPEARANCE_BRAND:
        return True
    app = QtWidgets.QApplication.instance()
    if app is None:
        return False
    return app.palette().color(QtGui.QPalette.ColorRole.Window).lightness() < 128


def force(active: Optional[bool]) -> None:
    """Override :func:`is_active` (``None`` restores auto-detection)."""
    global _forced
    _forced = active


def apply(widget: QtWidgets.QWidget) -> bool:
    """Give *widget* the ink look (when active).  Returns whether it was applied."""
    if not is_active():
        return False
    widget.setObjectName("ucPanel")
    widget.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
    widget.setStyleSheet(stylesheet())
    return True


def stylesheet() -> str:
    """The scoped QSS with resource paths resolved."""
    return PANEL_QSS.replace("{CHECK}", res_path("check-12.png").replace("\\", "/"))


# --------------------------------------------------------------------------- stylesheet
PANEL_QSS = f"""
#ucPanel {{ background: {INK}; color: {TEXT}; font-family: Arial; font-size: 12px; }}
#ucPanel QWidget {{ color: {TEXT}; font-family: Arial; font-size: 12px; }}
#ucPanel QLabel {{ background: transparent; color: {TEXT}; }}
#ucPanel QLabel[muted="true"] {{ color: {TEXT_MUTED}; }}
#ucPanel QLabel[mono="true"] {{ color: {TEXT_MUTED}; font-size: 11px; }}
#ucPanel QLabel[section="true"] {{ color: {CYAN}; font-size: 11px; letter-spacing: 1px; font-weight: bold; }}
#ucPanel QLabel[role="title"] {{ color: {TEXT_STRONG}; font-size: 14px; font-weight: bold; }}
#ucPanel QLabel[role="subtitle"] {{ color: {TEXT_STRONG}; font-size: 13px; font-weight: bold; }}
#ucPanel QLabel[role="hint"] {{ color: {TEXT_MUTED}; font-size: 11px; }}
#ucPanel QLabel[role="match"] {{ color: {CYAN}; font-size: 11px; }}
#ucPanel QLabel[role="warn"] {{ color: {WARNING}; }}

#ucPanel QFrame#ucCard {{
    background: {CARD}; border: 1px solid {CARD_BORDER}; border-radius: {RADIUS_CARD}px;
}}
#ucPanel QFrame#ucStat {{ background: {CARD}; border: none; border-radius: {RADIUS_CARD}px; }}
#ucPanel QFrame#ucNote {{ background: {INK}; border: none; border-radius: {RADIUS}px; }}
#ucPanel QFrame#ucOption {{ background: {CARD}; border: 1px solid {CARD_BORDER}; border-radius: {RADIUS_CARD}px; }}
#ucPanel QFrame#ucOption[selected="true"] {{ border-color: {PRIMARY}; background: {rgba(PRIMARY, 0.10)}; }}
#ucPanel QFrame#ucStrip {{ background: {INK}; border: 1px solid {CARD_BORDER}; border-radius: {RADIUS}px; }}
#ucPanel QFrame#ucBack {{ background: transparent; border: none; }}

/* buttons */
#ucPanel QPushButton, #ucPanel QToolButton {{
    background: transparent; color: {TEXT}; border: 1px solid {CHIP_BORDER};
    border-radius: {RADIUS}px; padding: 5px 10px;
}}
#ucPanel QPushButton:hover, #ucPanel QToolButton:hover {{ border-color: {PRIMARY}; color: {TEXT_STRONG}; }}
#ucPanel QPushButton:pressed, #ucPanel QToolButton:pressed {{ background: {rgba(PRIMARY, 0.18)}; }}
#ucPanel QPushButton:disabled, #ucPanel QToolButton:disabled {{ color: {TEXT_PLACEHOLDER}; border-color: {CARD_BORDER}; }}
#ucPanel QPushButton[role="primary"] {{
    border: none; color: {TEXT_STRONG}; font-weight: bold; padding: 6px 12px;
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 {PRIMARY}, stop:1 {MAGENTA});
}}
#ucPanel QPushButton[role="primary"]:hover {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 {CYAN}, stop:1 {PINK}); color: {ON_PRIMARY};
}}
#ucPanel QPushButton[role="primary"]:disabled {{ background: {rgba(PRIMARY, 0.35)}; color: {rgba(TEXT_STRONG, 0.5)}; }}
#ucPanel QPushButton[role="link"] {{ border: none; padding: 0 2px; color: {CYAN}; background: transparent; }}
#ucPanel QPushButton[role="link"]:hover {{ color: {PINK}; }}
#ucPanel QPushButton[role="link"]:disabled {{ color: {TEXT_PLACEHOLDER}; }}
#ucPanel QPushButton[role="outline"] {{ border: 1px solid {PRIMARY}; color: {CYAN}; }}
#ucPanel QPushButton[role="outline"]:hover {{ border-color: {CYAN}; }}
#ucPanel QToolButton[role="icon"] {{ padding: 5px 8px; font-size: 13px; }}
#ucPanel QToolButton[role="close"] {{ border: none; color: {TEXT_MUTED}; padding: 0 4px; }}
#ucPanel QToolButton[role="close"]:hover {{ color: {TEXT_STRONG}; }}
#ucPanel QToolButton::menu-indicator {{ image: none; width: 0; }}

/* version chips (checkable QPushButtons in a QButtonGroup) */
#ucPanel QPushButton[chip="version"] {{
    border-radius: {RADIUS_CHIP}px; padding: 3px 9px; color: {CHIP_TEXT}; border: 1px solid {CHIP_BORDER}; font-size: 11px;
}}
#ucPanel QPushButton[chip="version"]:hover {{ border-color: {PRIMARY}; color: {TEXT_STRONG}; }}
#ucPanel QPushButton[chip="version"]:checked {{
    background: {PRIMARY}; border-color: {PRIMARY}; color: {ON_PRIMARY}; font-weight: bold;
}}
#ucPanel QPushButton[chip="more"] {{
    border-radius: {RADIUS_CHIP}px; padding: 3px 9px; color: {CHIP_TEXT}; border: 1px solid {CHIP_BORDER}; font-size: 11px;
}}
#ucPanel QPushButton[chip="more"]::menu-indicator {{ image: none; width: 0; }}
#ucPanel QPushButton[chip="addtag"] {{
    border: 1px dashed {CHIP_BORDER}; color: {TEXT_MUTED}; border-radius: {RADIUS_PILL}px; padding: 2px 8px; font-size: 11px;
}}
#ucPanel QPushButton[chip="addtag"]:hover {{ border-color: {PINK}; color: {TAG_TEXT}; }}
#ucPanel QLabel[chip="tag"] {{
    background: {rgba(MAGENTA, 0.25)}; color: {TAG_TEXT}; border-radius: {RADIUS_PILL}px; padding: 2px 8px; font-size: 11px;
}}
#ucPanel QLabel[chip="stage"] {{ border-radius: {RADIUS_PILL}px; padding: 1px 8px; font-size: 11px; }}

/* follow-cursor toggle */
#ucPanel QCheckBox {{ color: {TEXT}; spacing: 6px; }}
#ucPanel QCheckBox::indicator {{ width: 12px; height: 12px; border: 1px solid {CHIP_BORDER}; border-radius: 3px; background: {FIELD}; }}
#ucPanel QCheckBox::indicator:checked {{ background: {PRIMARY}; border-color: {PRIMARY}; image: url("{{CHECK}}"); }}
#ucPanel QCheckBox::indicator:disabled {{ border-color: {CARD_BORDER}; }}
#ucPanel QCheckBox#ucFollow {{ color: {TEXT_MUTED}; spacing: 0; }}
#ucPanel QCheckBox#ucFollow:checked {{ color: {CYAN}; }}
#ucPanel QCheckBox#ucFollow::indicator {{ width: 0; height: 0; border: none; }}
#ucPanel QTabBar[outer="true"]::tab {{ font-size: 11px; color: {TEXT_MUTED}; padding: 2px 0 4px 0; margin-right: 12px; }}
#ucPanel QTabBar[outer="true"]::tab:selected {{ color: {CYAN}; border-bottom: 2px solid {CYAN}; }}
#ucPanel QRadioButton {{ color: {TEXT_STRONG}; font-weight: bold; spacing: 8px; }}
#ucPanel QRadioButton:disabled {{ color: {TEXT_PLACEHOLDER}; }}
#ucPanel QRadioButton::indicator {{ width: 14px; height: 14px; border-radius: 7px; border: 1px solid {CHIP_BORDER}; background: {FIELD}; }}
#ucPanel QRadioButton::indicator:checked {{
    border-color: {CYAN};
    background: qradialgradient(cx:0.5, cy:0.5, radius:0.5, fx:0.5, fy:0.5, stop:0 {CYAN}, stop:0.55 {CYAN}, stop:0.62 {FIELD});
}}

/* inputs */
#ucPanel QLineEdit, #ucPanel QComboBox, #ucPanel QSpinBox, #ucPanel QPlainTextEdit, #ucPanel QTextEdit {{
    background: {FIELD}; color: {TEXT}; border: 1px solid {CARD_BORDER};
    border-radius: {RADIUS}px; padding: 5px 8px; selection-background-color: {rgba(PRIMARY, 0.5)};
}}
#ucPanel QLineEdit:focus, #ucPanel QComboBox:focus, #ucPanel QSpinBox:focus, #ucPanel QPlainTextEdit:focus {{
    border-color: {PRIMARY};
}}
#ucPanel QLineEdit:disabled {{ color: {TEXT_PLACEHOLDER}; }}
#ucPanel QComboBox::drop-down {{ border: none; width: 18px; }}
#ucPanel QComboBox QAbstractItemView {{ background: {CARD}; color: {TEXT}; selection-background-color: {rgba(PRIMARY, 0.5)}; border: 1px solid {CARD_BORDER}; }}
#ucPanel QSpinBox::up-button, #ucPanel QSpinBox::down-button {{ width: 14px; border: none; background: transparent; }}

/* procedure list + trees */
#ucPanel QTableView, #ucPanel QTreeWidget, #ucPanel QTreeView, #ucPanel QListWidget {{
    background: transparent; border: none; color: {TEXT}; outline: 0;
    alternate-background-color: transparent; gridline-color: transparent;
    selection-background-color: {rgba(CYAN, 0.12)}; selection-color: {TEXT_STRONG};
}}
#ucPanel QTableView::item:selected, #ucPanel QTreeWidget::item:selected, #ucPanel QListWidget::item:selected {{
    background: {rgba(CYAN, 0.12)}; color: {TEXT_STRONG};
}}
#ucPanel QHeaderView {{ background: transparent; }}
#ucPanel QHeaderView::section {{
    background: transparent; color: {TEXT_MUTED}; border: none; border-bottom: 1px solid {CARD_BORDER}; padding: 3px 6px; font-size: 11px;
}}
#ucPanel QTreeWidget::branch {{ background: transparent; }}

/* inspector tabs */
#ucPanel QTabWidget::pane {{ border: none; border-top: 1px solid {CARD_BORDER}; }}
#ucPanel QTabBar {{ background: transparent; }}
#ucPanel QTabBar::tab {{ background: transparent; color: {TEXT_MUTED}; border: none; padding: 3px 0 5px 0; margin-right: 14px; }}
#ucPanel QTabBar::tab:selected {{ color: {TEXT_STRONG}; border-bottom: 2px solid {PINK}; }}
#ucPanel QTabBar::tab:hover {{ color: {TEXT}; }}
#ucPanel QTabBar::tab:disabled {{ color: {TEXT_PLACEHOLDER}; }}

#ucPanel QSplitter::handle {{ background: transparent; }}
#ucPanel QSplitter::handle:vertical {{ height: 10px; }}
#ucPanel QSplitter::handle:horizontal {{ width: 10px; }}
#ucPanel QProgressBar {{ background: {TRACK}; border: none; border-radius: 2px; max-height: 4px; }}
#ucPanel QProgressBar::chunk {{
    border-radius: 2px; background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 {PRIMARY}, stop:1 {MAGENTA});
}}
#ucPanel QScrollBar:vertical {{ background: transparent; width: 8px; margin: 0; }}
#ucPanel QScrollBar::handle:vertical {{ background: {CHIP_BORDER}; border-radius: 4px; min-height: 24px; }}
#ucPanel QScrollBar:horizontal {{ background: transparent; height: 8px; margin: 0; }}
#ucPanel QScrollBar::handle:horizontal {{ background: {CHIP_BORDER}; border-radius: 4px; min-width: 24px; }}
#ucPanel QScrollBar::add-line, #ucPanel QScrollBar::sub-line {{ height: 0; width: 0; }}
#ucPanel QScrollBar::add-page, #ucPanel QScrollBar::sub-page {{ background: transparent; }}
#ucPanel QMenu {{ background: {CARD}; color: {TEXT}; border: 1px solid {CARD_BORDER}; }}
#ucPanel QMenu::item:selected {{ background: {rgba(PRIMARY, 0.35)}; }}
#ucPanel QToolTip {{ background: {CARD}; color: {TEXT}; border: 1px solid {CARD_BORDER}; }}
"""


# --------------------------------------------------------------------------- small builders
def card(parent=None, name: str = "ucCard") -> QtWidgets.QFrame:
    """A rounded card surface (plain QFrame on light themes)."""
    frame = QtWidgets.QFrame(parent)
    frame.setObjectName(name)
    if not is_active():
        frame.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
    layout = QtWidgets.QVBoxLayout(frame)
    layout.setContentsMargins(10, 10, 10, 10)
    layout.setSpacing(10)
    return frame


def stat_tile(value: str, label: str, color: str = TEXT_STRONG, parent=None):
    """Returns ``(frame, value_label)`` so the number can be updated."""
    frame = card(parent, "ucStat")
    frame.layout().setContentsMargins(8, 8, 8, 8)
    frame.layout().setSpacing(2)
    number = QtWidgets.QLabel(value, frame)
    font = number.font()
    font.setBold(True)
    font.setPixelSize(18)
    number.setFont(font)
    if is_active():
        number.setStyleSheet(f"color: {color}; font-size: 18px; font-weight: bold;")
    caption = muted(label, frame)
    frame.layout().addWidget(number)
    frame.layout().addWidget(caption)
    return frame, number


def muted(text: str, parent=None) -> QtWidgets.QLabel:
    label = style.muted(text, parent)
    label.setProperty("muted", True)
    return label


def section_label(text: str, parent=None) -> QtWidgets.QLabel:
    label = QtWidgets.QLabel(text.upper(), parent)
    label.setProperty("section", True)
    if not is_active():
        font = label.font()
        font.setBold(True)
        label.setFont(font)
    return label


def tag_chip(text: str, parent=None) -> QtWidgets.QLabel:
    label = style.chip(text, "tag", parent)
    label.setProperty("chip", "tag")
    if is_active():
        label.setStyleSheet("")  # the scoped QSS takes over
    return label


def add_tag_chip(parent=None) -> QtWidgets.QPushButton:
    button = QtWidgets.QPushButton("+ tag", parent)
    button.setCursor(Qt.CursorShape.PointingHandCursor)
    button.setProperty("chip", "addtag")
    button.setFlat(True)
    button.setFocusPolicy(Qt.FocusPolicy.NoFocus)
    return button


def status_pill(text: str, kind: str, parent=None) -> QtWidgets.QLabel:
    label = style.chip(text, kind, parent)
    set_status_pill(label, text, kind)
    return label


def set_status_pill(label: QtWidgets.QLabel, text: str, kind: str) -> None:
    label.setProperty("chipKind", kind)
    if not is_active():
        label.setText(text)
        style.restyle_chip(label)
        return
    color = STATUS_COLORS.get(kind, TEXT_MUTED)
    label.setText(f"● {text}")
    label.setStyleSheet(
        f"QLabel {{ color: {color}; background: {rgba(color, 0.14)}; border: none; border-radius: {RADIUS_PILL}px; padding: 2px 9px; font-size: 11px; }}"
    )


def stage_chip(text: str, kind: str, parent=None) -> QtWidgets.QLabel:
    """Pipeline-stage chip (upload strip)."""
    label = style.chip(text, kind, parent)
    if is_active():
        color = STATUS_COLORS.get(kind, TEXT_MUTED)
        label.setStyleSheet(
            f"QLabel {{ color: {color}; background: {rgba(color, 0.14)}; border: 1px solid {rgba(color, 0.45)}; border-radius: {RADIUS_PILL}px; padding: 1px 8px; font-size: 11px; }}"
        )
    return label


def link_button(text: str, parent=None) -> QtWidgets.QPushButton:
    button = QtWidgets.QPushButton(text, parent)
    button.setProperty("role", "link")
    button.setFlat(True)
    button.setCursor(Qt.CursorShape.PointingHandCursor)
    return button


def primary_button(text: str, parent=None) -> QtWidgets.QPushButton:
    button = QtWidgets.QPushButton(text, parent)
    button.setProperty("role", "primary")
    button.setCursor(Qt.CursorShape.PointingHandCursor)
    if not is_active():
        button.setDefault(True)
    return button


def icon_button(text: str, tooltip: str, parent=None) -> QtWidgets.QToolButton:
    button = style.tool_button(text, tooltip, parent)
    button.setProperty("role", "icon")
    if is_active():
        button.setAutoRaise(False)
    return button


def repolish(widget: QtWidgets.QWidget) -> None:
    """Re-evaluate the stylesheet after a dynamic property changed."""
    widget.style().unpolish(widget)
    widget.style().polish(widget)
    widget.update()


def res_path(name: str) -> str:
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "res", name)


def shield_pixmap(height: int) -> QtGui.QPixmap:
    source = "shield-128.png" if height > 64 else "shield-64.png"
    pm = QtGui.QPixmap(res_path(source))
    if pm.isNull():
        return pm
    return pm.scaledToHeight(height, Qt.TransformationMode.SmoothTransformation)


def shield_icon() -> QtGui.QIcon:
    icon = QtGui.QIcon()
    for size in (16, 24, 32, 48, 64, 128):
        path = res_path(f"shield-{size}.png")
        if os.path.isfile(path):
            icon.addFile(path, QtCore.QSize(size, size))
    return icon


# --------------------------------------------------------------------------- flow layout
class FlowLayout(QtWidgets.QLayout):
    """Wrapping horizontal layout (version chips, tag chips)."""

    def __init__(self, parent=None, spacing: int = 6):
        super().__init__(parent)
        self._items = []
        self._spacing = spacing
        self.setContentsMargins(0, 0, 0, 0)

    def addItem(self, item):  # noqa: N802
        self._items.append(item)

    def count(self):
        return len(self._items)

    def itemAt(self, index):  # noqa: N802
        return self._items[index] if 0 <= index < len(self._items) else None

    def takeAt(self, index):  # noqa: N802
        return self._items.pop(index) if 0 <= index < len(self._items) else None

    def expandingDirections(self):  # noqa: N802
        try:
            return Qt.Orientations()  # PyQt5
        except AttributeError:
            return Qt.Orientation(0)  # PySide6

    def hasHeightForWidth(self):  # noqa: N802
        return True

    def heightForWidth(self, width):  # noqa: N802
        return self._arrange(QtCore.QRect(0, 0, width, 0), dry=True)

    def setGeometry(self, rect):  # noqa: N802
        super().setGeometry(rect)
        self._arrange(rect, dry=False)

    def sizeHint(self):  # noqa: N802
        return self.minimumSize()

    def minimumSize(self):  # noqa: N802
        size = QtCore.QSize()
        for item in self._items:
            size = size.expandedTo(item.minimumSize())
        margins = self.contentsMargins()
        return size + QtCore.QSize(margins.left() + margins.right(), margins.top() + margins.bottom())

    def clear(self) -> None:
        while self._items:
            item = self._items.pop()
            widget = item.widget()
            if widget is not None:
                widget.setParent(None)
                widget.deleteLater()

    def _arrange(self, rect, *, dry: bool) -> int:
        margins = self.contentsMargins()
        x = rect.x() + margins.left()
        y = rect.y() + margins.top()
        right = rect.right() - margins.right()
        line_height = 0
        for item in self._items:
            widget = item.widget()
            if widget is not None and widget.isHidden():
                continue
            hint = item.sizeHint()
            if x + hint.width() > right and line_height > 0:
                x = rect.x() + margins.left()
                y += line_height + self._spacing
                line_height = 0
            if not dry:
                item.setGeometry(QtCore.QRect(QtCore.QPoint(x, y), hint))
            x += hint.width() + self._spacing
            line_height = max(line_height, hint.height())
        return y + line_height + margins.bottom() - rect.y()


# --------------------------------------------------------------------------- delegates
def occurrence_ratio(count: int, max_count: int) -> float:
    """Log scale: 1 file is a sliver, the most common group in the list is full."""
    if max_count <= 0 or count <= 0:
        return 0.03 if max_count > 0 else 0.0
    return max(0.03, min(1.0, math.log10(count + 1) / math.log10(max_count + 1)))


class RowDelegate(QtWidgets.QStyledItemDelegate):
    """Paints 1b rows: cyan 12 % selection fill and a 2 px cyan edge on column 0; 25 px rows.

    Install on the whole view; :class:`BarDelegate` replaces it for bar columns.
    """

    ROW_HEIGHT = 25

    def __init__(self, parent=None, *, muted_columns=(0,), inset_column: Optional[int] = 0):
        super().__init__(parent)
        self._muted_columns = set(muted_columns)
        self._inset_column = inset_column

    def paint(self, painter, option, index):
        selected = bool(option.state & QtWidgets.QStyle.StateFlag.State_Selected)
        painter.save()
        if selected:
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(qcolor(CYAN, 0.12))
            painter.drawRect(option.rect)
            if index.column() == 0:
                painter.setBrush(QtGui.QColor(CYAN))
                painter.drawRect(QtCore.QRect(option.rect.left(), option.rect.top(), 2, option.rect.height()))
        painter.restore()
        opt = QtWidgets.QStyleOptionViewItem(option)
        self.initStyleOption(opt, index)
        opt.state &= ~QtWidgets.QStyle.StateFlag.State_Selected
        opt.state &= ~QtWidgets.QStyle.StateFlag.State_HasFocus
        opt.state &= ~QtWidgets.QStyle.StateFlag.State_MouseOver
        if index.column() == self._inset_column:
            opt.rect = opt.rect.adjusted(8, 0, 0, 0)
        if index.column() in self._muted_columns:
            text_color = QtGui.QColor(TEXT_MUTED)
        else:
            text_color = QtGui.QColor(TEXT_STRONG if selected else TEXT)
        opt.palette.setColor(QtGui.QPalette.ColorRole.Text, text_color)
        opt.palette.setColor(QtGui.QPalette.ColorRole.HighlightedText, text_color)
        opt.backgroundBrush = QtGui.QBrush(Qt.BrushStyle.NoBrush)
        widget = getattr(option, "widget", None)
        painter.save()
        QtWidgets.QApplication.style().drawControl(QtWidgets.QStyle.ControlElement.CE_ItemViewItem, opt, painter, widget)
        painter.restore()

    def sizeHint(self, option, index):  # noqa: N802
        size = super().sizeHint(option, index)
        return QtCore.QSize(size.width(), self.ROW_HEIGHT)


class BarDelegate(RowDelegate):
    """4 px rounded bar on a track; ``ratio_fn(index) -> 0..1``.  Cyan for procedures, pink for similarity."""

    def __init__(self, ratio_fn: Callable[[QtCore.QModelIndex], float], color: str = CYAN, parent=None):
        super().__init__(parent, muted_columns=(), inset_column=None)
        self._ratio = ratio_fn
        self._color = QtGui.QColor(color)

    def paint(self, painter, option, index):
        selected = bool(option.state & QtWidgets.QStyle.StateFlag.State_Selected)
        painter.save()
        painter.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing)
        painter.setPen(Qt.PenStyle.NoPen)
        if selected:
            painter.setBrush(qcolor(CYAN, 0.12))
            painter.drawRect(option.rect)
        try:
            value = self._ratio(index)
        except Exception:  # noqa: BLE001 - never let painting raise
            value = None
        if value is None:  # group header rows etc.: no track at all
            painter.restore()
            return
        ratio = float(value or 0.0)
        r = option.rect.adjusted(4, 0, -4, 0)
        track = QtCore.QRectF(r.x(), r.center().y() - 2, r.width(), 4)
        if is_active():
            painter.setBrush(QtGui.QColor(TRACK))
        else:  # light themes: a soft track from the palette
            soft = option.palette.color(QtGui.QPalette.ColorRole.Mid)
            soft.setAlpha(90)
            painter.setBrush(soft)
        painter.drawRoundedRect(track, 2, 2)
        if ratio > 0:
            fill = QtCore.QRectF(track)
            fill.setWidth(max(4.0, track.width() * min(1.0, ratio)))
            painter.setBrush(self._color)
            painter.drawRoundedRect(fill, 2, 2)
        painter.restore()


# --------------------------------------------------------------------------- overlap meter
class Meter(QtWidgets.QWidget):
    """120×6 gradient bar + bold percentage (compare dialog)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._value = 0.0
        layout = QtWidgets.QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        self._bar = QtWidgets.QWidget(self)
        self._bar.setFixedSize(120, 6)
        self._bar.paintEvent = self._paint_bar  # type: ignore[method-assign]
        self._label = QtWidgets.QLabel("0%", self)
        font = self._label.font()
        font.setBold(True)
        self._label.setFont(font)
        if is_active():
            self._label.setStyleSheet(f"color: {CYAN}; font-weight: bold;")
        layout.addWidget(self._bar)
        layout.addWidget(self._label)

    def set_value(self, ratio: float) -> None:
        self._value = max(0.0, min(1.0, ratio))
        self._label.setText(f"{round(self._value * 100)}%")
        self._bar.update()

    def _paint_bar(self, _event) -> None:
        painter = QtGui.QPainter(self._bar)
        painter.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing)
        painter.setPen(Qt.PenStyle.NoPen)
        rect = QtCore.QRectF(self._bar.rect())
        painter.setBrush(QtGui.QColor(TRACK) if is_active() else style.accent("muted", self._bar).lighter(160))
        painter.drawRoundedRect(rect, 3, 3)
        fill = QtCore.QRectF(rect)
        fill.setWidth(rect.width() * self._value)
        gradient = QtGui.QLinearGradient(rect.left(), 0, rect.right(), 0)
        gradient.setColorAt(0.0, QtGui.QColor(PRIMARY))
        gradient.setColorAt(1.0, QtGui.QColor(CYAN))
        painter.setBrush(QtGui.QBrush(gradient))
        painter.drawRoundedRect(fill, 3, 3)
        painter.end()
