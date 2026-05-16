"""
Qt compatibility shim.

IDA 8.x and 9.0/9.1 ship PyQt5. IDA 9.2+ ships PySide6 with a PyQt5
compatibility layer (the "PyQt5 shims") that Hex-Rays explicitly
labels as transitional.

Binary Ninja uses PySide6 natively.

Importing through this module instead of PyQt5/PySide6 directly means
the rest of the codebase doesn't need to care which one is loaded.
Add new helpers here as needed (e.g. signal differences, exec vs exec_).

Usage:

    from idamagic import qt_compat
    from idamagic.qt_compat import QtCore, QtGui, QtWidgets, Qt

Or selectively:

    from idamagic.qt_compat import QtWidgets

Notes:

- PySide6 uses .exec() everywhere; PyQt5 uses .exec_() (because
  `exec` was a Python 2 keyword). Use the exec_dialog() helper
  below to call the right one.
- Enum scoping differs: PyQt5 has flat enums (Qt.UserRole), PySide6
  has scoped enums (Qt.ItemDataRole.UserRole), but both libraries
  accept the flat form when used as values.
"""
from __future__ import annotations

import os

_QT_BACKEND = None

# Allow forcing one backend via env, useful for testing.
_FORCED = os.environ.get("IDAMAGIC_QT_BACKEND", "").lower().strip()

if _FORCED == "pyside6":
    from PySide6 import QtCore, QtGui, QtWidgets  # noqa: F401
    from PySide6.QtCore import Qt  # noqa: F401
    _QT_BACKEND = "pyside6"
elif _FORCED == "pyqt5":
    from PyQt5 import QtCore, QtGui, QtWidgets  # noqa: F401
    from PyQt5.QtCore import Qt  # noqa: F401
    _QT_BACKEND = "pyqt5"
else:
    # Auto-detect. Prefer PySide6 if available (matches IDA 9.2+
    # and Binary Ninja) and fall back to PyQt5 (IDA 8.x/9.0/9.1).
    try:
        from PySide6 import QtCore, QtGui, QtWidgets  # noqa: F401
        from PySide6.QtCore import Qt  # noqa: F401
        _QT_BACKEND = "pyside6"
    except ImportError:
        from PyQt5 import QtCore, QtGui, QtWidgets  # noqa: F401
        from PyQt5.QtCore import Qt  # noqa: F401
        _QT_BACKEND = "pyqt5"


def qt_backend() -> str:
    """Return the loaded Qt backend name: 'pyqt5' or 'pyside6'."""
    return _QT_BACKEND


def exec_dialog(dialog) -> int:
    """Call the appropriate exec method for the loaded Qt binding.

    PySide6 dropped `exec_` and exposes only `exec`; PyQt5 keeps both
    but `exec_` is the documented form. Use this anywhere the
    codebase previously called `popup.exec_()`.
    """
    if hasattr(dialog, "exec"):
        # PySide6 (and PyQt5 6.0+ has both, but exec works on either)
        return dialog.exec()
    return dialog.exec_()


# Convenience re-exports of the most-used enum values so callers can
# write Qt-style code without worrying about scoping changes.
USER_ROLE = Qt.UserRole
DECORATION_ROLE = Qt.DecorationRole
DISPLAY_ROLE = Qt.DisplayRole
EDIT_ROLE = Qt.EditRole
