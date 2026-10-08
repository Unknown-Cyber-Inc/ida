"""Qt binding shim.

IDA 9.2+ ships PySide6 (Qt 6); IDA 8.x, 9.0 and 9.1 ship PyQt5 (Qt 5).
Everything in this package imports Qt through this module so that only one
place knows which binding is in use.  Both bindings are exercised by the test
suite (``UNKNOWNCYBER_QT_BINDING=PyQt5``).

Only the APIs that genuinely differ are wrapped here (``Signal``, ``exec``,
``FormToQtWidget``, ``QShortcut``).  Enum access uses the fully-qualified Qt 6
style (``Qt.AlignmentFlag.AlignLeft``), which PyQt5 >= 5.11 also accepts.
"""

from __future__ import annotations

import os as _os

_forced = _os.environ.get("UNKNOWNCYBER_QT_BINDING", "").strip()  # "PySide6" / "PyQt5"; used by tests

if _forced == "PyQt5":
    from PyQt5 import QtCore, QtGui, QtWidgets  # type: ignore

    Signal = QtCore.pyqtSignal
    Slot = QtCore.pyqtSlot
    BINDING = "PyQt5"
else:
    try:  # IDA >= 9.2 (and any install where PySide6 is importable)
        if _forced == "PyQt5":  # pragma: no cover - handled above
            raise ImportError
        from PySide6 import QtCore, QtGui, QtWidgets  # type: ignore

        Signal = QtCore.Signal
        Slot = QtCore.Slot
        BINDING = "PySide6"
    except ImportError:  # IDA 8.x, 9.0, 9.1
        from PyQt5 import QtCore, QtGui, QtWidgets  # type: ignore

        Signal = QtCore.pyqtSignal
        Slot = QtCore.pyqtSlot
        BINDING = "PyQt5"

# Qt 6 moved QShortcut/QAction from QtWidgets to QtGui.
QShortcut = getattr(QtGui, "QShortcut", None) or QtWidgets.QShortcut
QAction = getattr(QtGui, "QAction", None) or QtWidgets.QAction

__all__ = [
    "QtCore",
    "QtGui",
    "QtWidgets",
    "Signal",
    "Slot",
    "BINDING",
    "QShortcut",
    "QAction",
    "exec_dialog",
    "form_to_widget",
]


def exec_dialog(dialog) -> int:
    """``QDialog.exec()`` (Qt 6) / ``exec_()`` (older PyQt5)."""
    runner = getattr(dialog, "exec", None) or getattr(dialog, "exec_")
    return int(runner())


def form_to_widget(plugin_form, form):
    """Return the ``QWidget`` backing an ``ida_kernwin.PluginForm``."""
    if BINDING == "PySide6":
        return plugin_form.FormToPySideWidget(form)
    return plugin_form.FormToPyQtWidget(form)
