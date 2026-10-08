"""Header card: file identity, server status, analysis-version chips and actions (design 1b)."""

from __future__ import annotations

from typing import Dict, List, Optional

from .. import models
from ..qt import QtCore, QtGui, QtWidgets, Signal
from . import brand, style

Qt = QtCore.Qt
MAX_VISIBLE_CHIPS = 4  # more than this: newest 3 + "+N ▾"


class UploadStrip(QtWidgets.QFrame):
    """Shows the processing pipeline of pending uploads as chips + a gradient progress bar."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("ucStrip")
        if not brand.is_active():
            self.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(8, 6, 8, 6)
        layout.setSpacing(6)
        self._title = brand.muted("", self)
        layout.addWidget(self._title)
        self._chips_layout = brand.FlowLayout(spacing=6)
        chips_host = QtWidgets.QWidget(self)
        chips_host.setLayout(self._chips_layout)
        layout.addWidget(chips_host)
        self._progress = QtWidgets.QProgressBar(self)
        self._progress.setRange(0, 0)
        self._progress.setTextVisible(False)
        self._progress.setFixedHeight(4)
        layout.addWidget(self._progress)
        self.hide()

    def show_status(self, status: models.UploadStatus) -> None:
        self._chips_layout.clear()
        state = status.status.lower()
        kind = {"success": "success", "failure": "error", "pending": "info"}.get(state, "muted")
        headline = {"success": "Processing finished", "failure": "Processing failed", "pending": "Processing…"}.get(
            state, f"Status: {status.status}"
        )
        self._title.setText(f"{headline} · {style.short_hash(status.binary_id, 14)}")
        self._title.setToolTip(status.binary_id)
        for key, value in status.pipeline.items():
            self._chips_layout.addWidget(brand.stage_chip(f"{models.pipeline_label(key)}: {value}", _stage_kind(value), self))
        if not status.pipeline:
            self._chips_layout.addWidget(brand.stage_chip(status.status.capitalize() or "Unknown", kind, self))
        self._progress.setVisible(state == "pending")
        self.show()

    def clear(self) -> None:
        self.hide()


def _version_label(version: models.AnalysisVersion) -> str:
    """Short chip label: ``Original · 3f9a1c0b``, ``Disasm · 09-30 14:12``, ``Processing · <label>``."""
    if version.kind == "original":
        return f"Original · {version.binary_id[:8]}"
    if version.kind == "container":
        return f"Processing · {version.label}"
    if version.timestamp:
        stamp = version.timestamp.replace("T", " ")
        # 2026-09-30 14:12:00 -> 09-30 14:12
        return f"Disasm · {stamp[5:16]}"
    return f"Upload · {version.label}"


def _stage_kind(value: str) -> str:
    v = (value or "").lower()
    if v in ("success", "done", "complete", "completed", "finished"):
        return "success"
    if v in ("failure", "failed", "error"):
        return "error"
    if v in ("pending", "running", "processing", "queued", "started"):
        return "info"
    return "muted"


def _arch_text(arch_bits: Optional[int]) -> str:
    return {32: "x86", 64: "x64"}.get(arch_bits or 0, "")


def _format_text(file_type: str) -> str:
    """``Portable executable for 80386 (PE)`` → ``PE``; ``ELF64 for x86-64`` → ``ELF64``."""
    text = (file_type or "").strip()
    if not text:
        return ""
    if "(" in text and text.endswith(")"):
        return text[text.rfind("(") + 1 : -1]
    return text.split()[0]


class HeaderBar(QtWidgets.QWidget):
    upload_requested = Signal()
    refresh_requested = Signal()
    settings_requested = Signal()
    dashboard_requested = Signal()
    version_changed = Signal(object)  # models.AnalysisVersion or None

    def __init__(self, parent=None):
        super().__init__(parent)
        self._versions: List[models.AnalysisVersion] = []
        self._chips: Dict[str, QtWidgets.QPushButton] = {}
        self._selected_id: Optional[str] = None
        self._updating = False
        self._md5 = ""

        outer = QtWidgets.QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        self._card = brand.card(self)
        outer.addWidget(self._card)
        layout = self._card.layout()

        # -- row A: logo, title column, status pill ---------------------------
        row_a = QtWidgets.QHBoxLayout()
        row_a.setSpacing(10)
        self._logo = QtWidgets.QLabel(self._card)
        pixmap = brand.shield_pixmap(35)
        if not pixmap.isNull():
            self._logo.setPixmap(pixmap)
        else:
            self._logo.hide()
        row_a.addWidget(self._logo, 0, Qt.AlignmentFlag.AlignVCenter)

        titles = QtWidgets.QVBoxLayout()
        titles.setSpacing(3)
        self._name = QtWidgets.QLabel("No file", self._card)
        self._name.setProperty("role", "title")
        font = self._name.font()
        font.setBold(True)
        font.setPixelSize(14)
        self._name.setFont(font)
        self._name.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        sub = QtWidgets.QHBoxLayout()
        sub.setSpacing(4)
        self._hash = QtWidgets.QLabel("", self._card)
        self._hash.setProperty("mono", True)
        mono = style.monospace_font()
        mono.setPixelSize(11)
        self._hash.setFont(mono)
        self._hash.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self._hash.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._hash.customContextMenuRequested.connect(self._hash_menu)
        self._copy = QtWidgets.QToolButton(self._card)
        self._copy.setText("⧉")
        self._copy.setToolTip("Copy MD5")
        self._copy.setProperty("role", "close")
        self._copy.setAutoRaise(True)
        self._copy.setCursor(Qt.CursorShape.PointingHandCursor)
        sub.addWidget(self._hash)
        sub.addWidget(self._copy)
        sub.addStretch(1)
        titles.addWidget(self._name)
        titles.addLayout(sub)
        row_a.addLayout(titles, 1)

        self._status = brand.status_pill("Not configured", "muted", self._card)
        row_a.addWidget(self._status, 0, Qt.AlignmentFlag.AlignTop)
        layout.addLayout(row_a)

        # -- row B: version chips + hint -------------------------------------
        self._chip_host = QtWidgets.QWidget(self._card)
        self._chip_layout = brand.FlowLayout(spacing=6)
        self._chip_host.setLayout(self._chip_layout)
        self._group = QtWidgets.QButtonGroup(self)
        self._group.setExclusive(True)
        layout.addWidget(self._chip_host)
        self._version_hint = brand.muted("", self._card)
        self._version_hint.setProperty("role", "hint")
        self._version_hint.setWordWrap(True)
        self._version_hint.hide()
        layout.addWidget(self._version_hint)

        # -- row C: actions ----------------------------------------------------
        row_c = QtWidgets.QHBoxLayout()
        row_c.setSpacing(8)
        self._upload = brand.primary_button("Upload…", self._card)
        self._refresh = brand.icon_button("⟳", "Refresh from server", self._card)
        self._dashboard = QtWidgets.QPushButton("Dashboard ↗", self._card)
        self._dashboard.setToolTip("Open in the Unknown Cyber dashboard")
        self._dashboard.setCursor(Qt.CursorShape.PointingHandCursor)
        self._settings = brand.icon_button("⚙", "Settings", self._card)
        row_c.addWidget(self._upload, 1)
        row_c.addWidget(self._refresh)
        row_c.addWidget(self._dashboard)
        row_c.addWidget(self._settings)
        layout.addLayout(row_c)

        self._strip = UploadStrip(self._card)
        layout.addWidget(self._strip)

        self._upload.clicked.connect(self.upload_requested)
        self._refresh.clicked.connect(self.refresh_requested)
        self._settings.clicked.connect(self.settings_requested)
        self._dashboard.clicked.connect(self.dashboard_requested)
        self._copy.clicked.connect(lambda: style.copy_to_clipboard(self._md5))
        self.set_file(None)
        self.set_versions([])

    # -- public --------------------------------------------------------------
    @property
    def upload_strip(self) -> UploadStrip:
        return self._strip

    def set_file(self, name: Optional[str], md5: str = "", *, arch_bits: Optional[int] = None, file_type: str = "") -> None:
        self._md5 = md5 or ""
        display = name or "No file"
        style.elide(self._name, display, 360)
        parts = [f"md5 {style.short_hash(md5, 12)}"] if md5 else []
        if arch_bits:
            parts.append(_arch_text(arch_bits))
        fmt = _format_text(file_type)
        if fmt:
            parts.append(fmt)
        self._hash.setText(" · ".join(p for p in parts if p))
        self._hash.setToolTip(md5)
        self._copy.setVisible(bool(md5))

    def set_status(self, text: str, kind: str) -> None:
        brand.set_status_pill(self._status, text, kind)

    def set_actions_enabled(self, *, upload: bool, refresh: bool, dashboard: bool) -> None:
        self._upload.setEnabled(upload)
        self._refresh.setEnabled(refresh)
        self._dashboard.setEnabled(dashboard)

    def set_versions(self, versions: List[models.AnalysisVersion], selected: Optional[str] = None) -> None:
        self._updating = True
        try:
            self._versions = list(versions)
            for button in list(self._chips.values()):
                self._group.removeButton(button)
            self._chips = {}
            self._chip_layout.clear()
            self._chip_host.setVisible(bool(self._versions))
            if not self._versions:
                self._selected_id = None
                return
            if selected not in {v.binary_id for v in self._versions}:
                selected = self._versions[-1].binary_id
            self._selected_id = selected
            visible = self._versions
            overflow: List[models.AnalysisVersion] = []
            if len(self._versions) > MAX_VISIBLE_CHIPS:
                visible = self._versions[-3:]
                overflow = self._versions[:-3]
                chosen = next((v for v in overflow if v.binary_id == selected), None)
                if chosen is not None:  # keep the selected one visible
                    overflow = [v for v in overflow if v is not chosen]
                    visible = [chosen] + visible[1:]
            for version in visible:
                self._add_chip(version)
            if overflow:
                more = QtWidgets.QPushButton(f"+{len(overflow)} ▾", self._chip_host)
                more.setProperty("chip", "more")
                more.setCursor(Qt.CursorShape.PointingHandCursor)
                menu = QtWidgets.QMenu(more)
                for version in overflow:
                    action = menu.addAction(_version_label(version))
                    action.setToolTip(version.binary_id)
                    action.triggered.connect(lambda _=False, b=version.binary_id: self._select_overflow(b))
                more.setMenu(menu)
                self._chip_layout.addWidget(more)
            chip = self._chips.get(selected)
            if chip is not None:
                chip.setChecked(True)
        finally:
            self._updating = False
        self.set_version_hint("")

    def current_version(self) -> Optional[models.AnalysisVersion]:
        return next((v for v in self._versions if v.binary_id == self._selected_id), None)

    def set_version_hint(self, text: str, *, match: bool = False) -> None:
        """Caption under the chips; ``match=True`` renders it as ``✓ …`` in cyan."""
        if text and match:
            text = "✓ " + text
        self._version_hint.setProperty("role", "match" if match else "hint")
        if brand.is_active():
            brand.repolish(self._version_hint)
        else:
            self._version_hint.setStyleSheet(f"color: {style.accent('brand' if match else 'muted', self).name()};")
        self._version_hint.setText(text)
        self._version_hint.setVisible(bool(text))

    def select_version(self, binary_id: str) -> None:
        if any(v.binary_id == binary_id for v in self._versions):
            if binary_id in self._chips:
                self._chips[binary_id].setChecked(True)  # emits through _on_chip
            else:
                self._select_overflow(binary_id)

    # -- internals -----------------------------------------------------------
    def _add_chip(self, version: models.AnalysisVersion) -> None:
        chip = QtWidgets.QPushButton(_version_label(version), self._chip_host)
        chip.setCheckable(True)
        chip.setProperty("chip", "version")
        chip.setToolTip(version.binary_id)
        chip.setCursor(Qt.CursorShape.PointingHandCursor)
        chip.toggled.connect(lambda checked, b=version.binary_id: self._on_chip(b, checked))
        self._group.addButton(chip)
        self._chip_layout.addWidget(chip)
        self._chips[version.binary_id] = chip

    def _on_chip(self, binary_id: str, checked: bool) -> None:
        if not checked or self._updating:
            return
        if binary_id == self._selected_id:
            return
        self._selected_id = binary_id
        self.version_changed.emit(self.current_version())

    def _select_overflow(self, binary_id: str) -> None:
        """A version from the "+N" menu becomes a visible, selected chip."""
        self.set_versions(self._versions, binary_id)
        self.version_changed.emit(self.current_version())

    def _hash_menu(self, pos) -> None:
        if not self._md5:
            return
        menu = QtWidgets.QMenu(self)
        menu.addAction("Copy MD5", lambda: style.copy_to_clipboard(self._md5))
        runner = getattr(menu, "exec", None) or getattr(menu, "exec_")
        runner(self._hash.mapToGlobal(pos))

    def shield_icon(self) -> QtGui.QIcon:
        return brand.shield_icon()
