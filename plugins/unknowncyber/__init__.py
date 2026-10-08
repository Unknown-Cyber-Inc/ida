"""Unknown Cyber MAGIC plugin for IDA Pro 8.3 and 9.x.

Package layout
--------------
``qt``          Qt binding shim (PySide6 on IDA >= 9.2, PyQt5 on IDA 8.3-9.1).
``config``      Persistent settings + credential storage.
``client``      Typed, validated wrapper around the ``cythereal_magic`` SDK.
``models``      Plain data classes shared by the client and the UI.
``workers``     Background execution helpers (network off the UI thread).
``idb``         Read-only helpers for the currently loaded database.
``exporter``    Disassembly export (the only code that mutates the database,
                always inside an undo point that is reverted afterwards).
``ui``          The dockable widget and its dialogs.
"""

from __future__ import annotations

import logging

__version__ = "1.1.0"
PLUGIN_NAME = "Unknown Cyber"
WIDGET_TITLE = "Unknown Cyber"
PLUGIN_HOTKEY = "Ctrl-Shift-A"

_log = logging.getLogger(__name__)


def _configure_logging() -> None:
    """Attach a handler to *our* logger only.

    The previous implementation called ``logging.basicConfig`` from several
    modules, which reconfigured IDA's root logger and crashed on an empty
    ``IDA_LOGLEVEL`` value.
    """
    import os

    from . import config

    level_name = (os.environ.get("UNKNOWNCYBER_LOGLEVEL") or config.load().log_level or "INFO").upper()
    level = logging.getLevelName(level_name)
    if not isinstance(level, int):
        level = logging.INFO
    pkg_logger = logging.getLogger(__name__)
    pkg_logger.setLevel(level)
    if not any(getattr(h, "_unknowncyber", False) for h in pkg_logger.handlers):
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("[unknowncyber] %(levelname)s %(name)s: %(message)s"))
        handler._unknowncyber = True  # type: ignore[attr-defined]
        pkg_logger.addHandler(handler)
    pkg_logger.propagate = False


class UnknownCyberPlugin:  # pragma: no cover - instantiated by IDA
    """``ida_idaapi.plugin_t`` implementation.

    Defined lazily (see :func:`_build_plugin_class`) so that importing this
    package outside of IDA (unit tests, linting) does not require ``ida_idaapi``.
    """

    def __new__(cls):
        return _build_plugin_class()()


def _build_plugin_class():
    import ida_idaapi
    import ida_kernwin

    class _Plugin(ida_idaapi.plugin_t):
        flags = ida_idaapi.PLUGIN_FIX
        wanted_name = PLUGIN_NAME
        wanted_hotkey = PLUGIN_HOTKEY
        comment = "Unknown Cyber MAGIC: upload, annotate and compare procedures"
        help = "Opens the Unknown Cyber panel. Configure the API host and key under the panel's settings."
        version = __version__

        def __init__(self):
            super().__init__()
            self._form = None
            self._hook = None

        # -- plugin_t -------------------------------------------------------
        def init(self):
            if not ida_kernwin.is_idaq():
                _log.info("GUI not available; plugin disabled in this session")
                return ida_idaapi.PLUGIN_SKIP
            _configure_logging()
            self._install_autoinst_hook()
            _log.info("loaded v%s (hotkey %s)", __version__, PLUGIN_HOTKEY)
            # Plugins are normally initialised before any database is open; if one is
            # already open (plugin loaded late), apply the auto-open setting now.
            if self._database_open():
                self._auto_open()
            return ida_idaapi.PLUGIN_KEEP

        def run(self, arg):
            self.show()

        def term(self):
            if self._hook is not None:
                self._hook.unhook()
                self._hook = None
            if self._form is not None:
                try:
                    self._form.Close(0)
                except Exception:  # noqa: BLE001 - IDA may already have destroyed it
                    pass
                self._form = None

        # -- helpers --------------------------------------------------------
        def show(self):
            """Open the panel (or bring it to the front) next to the disassembly view."""
            from .ui.main_widget import UnknownCyberForm

            existing = ida_kernwin.find_widget(WIDGET_TITLE)
            if existing is not None:
                ida_kernwin.activate_widget(existing, True)
                return
            self._form = UnknownCyberForm()
            self._form.Show(WIDGET_TITLE)
            self._dock_beside_view()
            widget = ida_kernwin.find_widget(WIDGET_TITLE)
            if widget is not None:
                ida_kernwin.activate_widget(widget, True)

        @staticmethod
        def _dock_beside_view():
            """Dock to the right of the disassembly view instead of as a tab in front of it."""
            for view in ("IDA View-A", "Pseudocode-A", "Hex View-1"):
                if ida_kernwin.find_widget(view) is None:
                    continue
                try:
                    ida_kernwin.set_dock_pos(WIDGET_TITLE, view, ida_kernwin.DP_RIGHT)
                except Exception as exc:  # noqa: BLE001 - layout is cosmetic
                    _log.debug("set_dock_pos failed: %s", exc)
                return

        @staticmethod
        def _database_open():
            try:
                import ida_loader

                return bool(ida_loader.get_path(ida_loader.PATH_TYPE_IDB))
            except Exception:  # noqa: BLE001
                return False

        def _auto_open(self):
            """Open the panel after a database finished loading, if the setting is on."""
            from . import config

            if not config.load().auto_open:
                return
            plugin = self

            def _request():
                try:
                    plugin.show()
                except Exception as exc:  # noqa: BLE001 - never raise out of a UI request
                    _log.warning("could not open panel automatically: %s", exc)
                return False  # run once

            # Defer until IDA has finished setting up the UI for this database.
            ida_kernwin.execute_ui_requests([_request])

        def _install_autoinst_hook(self):
            """Re-create the widget when IDA restores a saved desktop; open it when a database loads."""
            plugin = self

            class _DesktopHook(ida_kernwin.UI_Hooks):
                def create_desktop_widget(self, title, cfg):
                    if title == WIDGET_TITLE:
                        existing = ida_kernwin.find_widget(WIDGET_TITLE)
                        if existing is not None:
                            return existing  # already opened (auto-open); don't create a second one
                        from unknowncyber.ui.main_widget import UnknownCyberForm

                        plugin._form = UnknownCyberForm()
                        plugin._form.Show(WIDGET_TITLE)
                        return plugin._form.GetWidget()
                    return None

                def database_inited(self, is_new_database, idc_script):
                    plugin._auto_open()

            self._hook = _DesktopHook()
            self._hook.hook()

    return _Plugin
