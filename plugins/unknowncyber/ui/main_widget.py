"""The dockable Unknown Cyber panel and its controller logic."""

from __future__ import annotations

import base64
import dataclasses
import logging
import os
import shutil
import tempfile
from typing import Dict, List, Optional

from .. import config, idb, models
from ..client import ApiError, MagicClient, NotConfigured
from ..qt import QShortcut, QtCore, QtGui, QtWidgets, exec_dialog, form_to_widget
from ..workers import TaskGroup
from . import brand, style
from .compare import CompareDialog
from .dialogs import Banner, TextEditorDialog, UploadDialog, show_error
from .header import HeaderBar
from .inspector import InspectorView, ProcTarget
from .procedures import ProceduresView
from .settings import SettingsDialog

_log = logging.getLogger(__name__)
Qt = QtCore.Qt


@dataclasses.dataclass
class PendingUpload:
    binary_id: str
    kind: str  # "original" | "container"
    label: str
    status: Optional[models.UploadStatus] = None


class MainPanel(QtWidgets.QWidget):
    """Everything inside the dock widget.  One instance per open database."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._tasks = TaskGroup(self)  # queries; superseded by every refresh
        self._uploads = TaskGroup(self)  # uploads; never invalidated by a refresh
        self._settings = config.load()
        self._client: Optional[MagicClient] = None
        self._client_settings: Optional[config.Settings] = None
        self._loaded: Optional[idb.LoadedFile] = None
        self._content_hashes: Dict[str, str] = {}
        self._versions: List[models.AnalysisVersion] = []
        self._version: Optional[models.AnalysisVersion] = None
        self._pending: List[PendingUpload] = []
        self._dialogs: List[QtWidgets.QDialog] = []
        self._cursor_hook = None

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)
        self.header = HeaderBar(self)
        layout.addWidget(self.header)
        self.banner = Banner(self)
        layout.addWidget(self.banner)

        # Content (procedures + inspector) or the "connect" state when not configured.
        self._stack = QtWidgets.QStackedWidget(self)
        self._splitter = QtWidgets.QSplitter(Qt.Orientation.Vertical, self._stack)
        self._splitter.setHandleWidth(10)
        self._splitter.setChildrenCollapsible(False)
        self.procedures = ProceduresView(self._splitter)
        self.inspector = InspectorView(lambda: self._client, self._splitter)
        self._splitter.addWidget(self.procedures)
        self._splitter.addWidget(self.inspector)
        self._splitter.setStretchFactor(0, 3)
        self._splitter.setStretchFactor(1, 4)
        self.procedures.setMinimumHeight(220)
        self.inspector.setMinimumHeight(200)
        self._splitter.setSizes([360, 480])
        self._stack.addWidget(self._splitter)
        self._connect_state = self._build_connect_state()
        self._stack.addWidget(self._connect_state)
        layout.addWidget(self._stack, 1)
        brand.apply(self)

        self._poll_timer = QtCore.QTimer(self)
        self._poll_timer.timeout.connect(self._poll_pending)

        self.header.upload_requested.connect(self.upload)
        self.header.refresh_requested.connect(self.refresh)
        self.header.settings_requested.connect(self.open_settings)
        self.header.dashboard_requested.connect(self.open_dashboard)
        self.header.version_changed.connect(self._on_version_changed)
        self.procedures.load_requested.connect(self.load_procedures)
        self.procedures.procedure_selected.connect(self._on_procedure_selected)
        self.procedures.jump_requested.connect(lambda proc: self._jump(proc.start_ea))
        self.procedures.rename_requested.connect(
            lambda proc: self._rename(ProcTarget(proc.binary_id, proc.start_ea, proc.name, proc.hard_hash, True, proc))
        )
        self.inspector.procedure_tab.jump_requested.connect(lambda target: self._jump(target.rva))
        self.inspector.procedure_tab.rename_requested.connect(self._rename)
        self.inspector.procedure_tab.compare_requested.connect(self._compare)
        self.banner.action_triggered.connect(self._on_banner_action)
        self._banner_action = None

        search_shortcut = QShortcut(QtGui.QKeySequence.StandardKey.Find, self)
        search_shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        search_shortcut.activated.connect(self.procedures.focus_search)

        self._install_cursor_hook()
        QtCore.QTimer.singleShot(0, self.refresh)

    def _build_connect_state(self) -> QtWidgets.QWidget:
        """Centred column: shield, title, copy, primary "Open settings" (design 1i)."""
        page = QtWidgets.QWidget(self._stack)
        layout = QtWidgets.QVBoxLayout(page)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(10)
        layout.addStretch(2)
        logo = QtWidgets.QLabel(page)
        pixmap = brand.shield_pixmap(50)
        if not pixmap.isNull():
            logo.setPixmap(pixmap)
            effect = QtWidgets.QGraphicsOpacityEffect(logo)
            effect.setOpacity(0.85)
            logo.setGraphicsEffect(effect)
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(logo)
        title = QtWidgets.QLabel("Connect to Unknown Cyber", page)
        title.setProperty("role", "title")
        font = title.font()
        font.setBold(True)
        font.setPixelSize(14)
        title.setFont(font)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        copy = brand.muted("Enter your Unknown Cyber API host and key to get started.", page)
        copy.setAlignment(Qt.AlignmentFlag.AlignCenter)
        copy.setWordWrap(True)
        layout.addWidget(copy)
        row = QtWidgets.QHBoxLayout()
        row.addStretch(1)
        self._connect_button = brand.primary_button("Open settings", page)
        self._connect_button.clicked.connect(self.open_settings)
        row.addWidget(self._connect_button)
        row.addStretch(1)
        layout.addLayout(row)
        layout.addStretch(3)
        return page

    def _show_content(self, configured: bool) -> None:
        self._stack.setCurrentWidget(self._splitter if configured else self._connect_state)

    # ------------------------------------------------------------------ lifecycle
    def shutdown(self) -> None:
        self._poll_timer.stop()
        self._tasks.invalidate()
        if self._cursor_hook is not None:
            self._cursor_hook.unhook()
            self._cursor_hook = None
        for dialog in list(self._dialogs):
            dialog.close()

    def _install_cursor_hook(self) -> None:
        try:
            self._cursor_hook = idb.CursorHook(self.procedures.on_cursor_function)
        except Exception as exc:  # noqa: BLE001 - outside IDA or hook unavailable
            _log.debug("cursor hook unavailable: %s", exc)

    # ------------------------------------------------------------------ settings
    def _build_client(self) -> bool:
        """(Re)create the API client only when the settings changed."""
        cached = self._client_settings
        if self._client is not None and cached == self._settings and cached.api_key == self._settings.api_key:
            return True
        try:
            self._client = MagicClient(self._settings)
            self._client_settings = dataclasses.replace(self._settings)
            return True
        except NotConfigured:
            self._client = None
            return False
        except ImportError as exc:
            self._client = None
            self.banner.error(f"The 'cythereal_magic' package is not installed ({exc}). See requirements.txt.")
            return False

    def open_settings(self) -> None:
        updated = SettingsDialog.edit(self._settings, self)
        if updated is None:
            return
        appearance_changed = updated.appearance != self._settings.appearance
        self._settings = updated
        brand.refresh()
        from .. import _configure_logging

        _configure_logging()
        self.banner.clear()
        self.refresh()
        if appearance_changed:
            self.banner.info("Appearance changes apply the next time the panel is opened.")

    def _on_banner_action(self) -> None:
        action = self._banner_action
        self._banner_action = None
        if action == "settings":
            self.open_settings()
        elif action == "retry":
            self.refresh()
        elif action == "upload":
            self.upload()

    def _banner_with_action(self, kind: str, text: str, action_label: str, action: str) -> None:
        self._banner_action = action
        self.banner.show_message(text, kind, action_label)

    # ------------------------------------------------------------------ refresh
    def refresh(self) -> None:
        """Re-read the loaded file identity and ask the server what it knows."""
        self.banner.clear()
        if not self._build_client():
            self.header.set_status("Not configured", "muted")
            self.header.set_actions_enabled(upload=False, refresh=True, dashboard=False)
            self.header.set_versions([])
            self._show_content(False)
            return
        self._show_content(True)
        try:
            self._loaded = idb.loaded_file()
            self._content_hashes = idb.idb_content_hashes()
        except Exception as exc:  # noqa: BLE001 - no database open / outside IDA
            _log.debug("could not read database identity: %s", exc)
            self._loaded = None
            self.header.set_file(None)
            self.header.set_status("No database", "muted")
            self.header.set_actions_enabled(upload=False, refresh=True, dashboard=False)
            self.banner.warning("Open a database in IDA to use the Unknown Cyber panel.")
            return

        loaded = self._loaded
        self.header.set_file(loaded.name, loaded.md5, arch_bits=loaded.arch_bits, file_type=loaded.file_type)
        self.header.set_status("Checking…", "info")
        self.header.set_actions_enabled(upload=False, refresh=False, dashboard=False)
        self.procedures.set_image_base(loaded.image_base)
        client = self._client
        content_sha1 = self._content_hashes.get("sha1", "")
        md5 = loaded.md5

        def work():
            original = client.get_file(md5, with_children=True)
            content = client.get_file(content_sha1, with_children=False) if content_sha1 else None
            return original, content

        self._tasks.invalidate()
        self._tasks.run(work, on_success=self._on_refreshed, on_error=self._on_refresh_failed)

    def _on_refresh_failed(self, exc: Exception) -> None:
        self.header.set_status("Offline", "error")
        self.header.set_actions_enabled(upload=False, refresh=True, dashboard=False)
        if isinstance(exc, ApiError) and exc.unauthorized:
            self._banner_with_action("error", str(exc), "Open settings", "settings")
        else:
            self._banner_with_action("error", str(exc), "Retry", "retry")

    def _on_refreshed(self, result) -> None:
        original, content = result
        loaded = self._loaded
        assert loaded is not None
        versions: List[models.AnalysisVersion] = []
        if original is not None:
            versions.append(models.AnalysisVersion(label="Original file", binary_id=original.sha1 or loaded.md5, kind="original"))
            versions.extend(original.children)
        if content is not None and all(v.binary_id != content.sha1 for v in versions):
            versions.append(models.AnalysisVersion(label="This IDB (uploaded)", binary_id=content.sha1, kind="content"))
        for pending in self._pending:
            if all(v.binary_id != pending.binary_id for v in versions):
                versions.append(models.AnalysisVersion(label=pending.label, binary_id=pending.binary_id, kind=pending.kind))
        self._versions = versions

        self.header.set_actions_enabled(upload=True, refresh=True, dashboard=original is not None)
        if not versions:
            self.header.set_status("Not uploaded", "warning")
            self.header.set_versions([])
            self._banner_with_action(
                "info",
                "This file has not been uploaded to Unknown Cyber yet. Upload the binary, the IDB or a disassembly export to get started.",
                "Upload…",
                "upload",
            )
            self.procedures.clear()
            self.inspector.file_tab.show_file("", home=True)
            self.inspector.show_procedure(None)
            return
        status = (original.status if original else "").lower()
        if status == "pending" or any(not (p.status and p.status.finished) for p in self._pending):
            self.header.set_status("Processing", "info")
        elif status == "failure":
            self.header.set_status("Processing failed", "error")
        else:
            self.header.set_status("Ready", "success")

        preferred = self._version.binary_id if self._version else None
        if preferred is None:
            # Prefer the processed contents of this very IDB, then the newest child, then the original.
            if content is not None:
                preferred = content.sha1
            elif len(versions) > 1:
                preferred = versions[-1].binary_id
            else:
                preferred = versions[0].binary_id
        self.header.set_versions(versions, preferred)
        self._on_version_changed(self.header.current_version())
        if self._pending:
            self._poll_timer.start(max(5, self._settings.auto_poll_seconds) * 1000)
            self._poll_pending()

    # ------------------------------------------------------------------ versions
    def _on_version_changed(self, version: Optional[models.AnalysisVersion]) -> None:
        previous = self._version
        self._version = version
        if version is None:
            self.procedures.clear()
            self.inspector.file_tab.show_file("", home=True)
            self.inspector.show_procedure(None)
            return
        if previous is None or previous.binary_id != version.binary_id:
            self.procedures.clear()
            self.inspector.show_procedure(None)
            self.inspector.file_tab.show_file(
                version.binary_id, home=True, label=f"{version.label} · {style.short_hash(version.binary_id, 20)}"
            )
            self.inspector.setCurrentWidget(self.inspector.file_tab)
        content_sha1 = self._content_hashes.get("sha1", "")
        if version.kind == "container":
            self.header.set_version_hint("Still processing on the server; procedures appear when it finishes.")
        elif version.kind == "content" and version.binary_id == content_sha1:
            self.header.set_version_hint("Matches this IDB exactly.", match=True)
        elif version.kind == "original":
            self.header.set_version_hint("Server-side analysis of the original binary.")
        else:
            self.header.set_version_hint("Different database contents; addresses may not line up with this IDB.")

    # ------------------------------------------------------------------ procedures
    def load_procedures(self) -> None:
        client, version = self._client, self._version
        if client is None or version is None:
            self.procedures.banner.warning("Select an analysis version first.")
            return
        if version.kind == "container":
            self.procedures.banner.info("This upload is still being processed. Try again in a moment.")
            return
        self.procedures.banner.clear()
        self.procedures.set_loading(True)
        binary_id = version.binary_id

        def done(procs: List[models.Procedure]):
            if self._version is None or self._version.binary_id != binary_id:
                return
            self.procedures.set_procedures(procs)
            if not procs:
                self.procedures.banner.info("The server has no procedures for this version yet.")
            elif binary_id != self._content_hashes.get("sha1", "") and version.kind != "original":
                self.procedures.banner.warning(
                    "These procedures come from different database contents; addresses may not line up with this IDB."
                )
            self._select_cursor_procedure()

        def failed(exc: Exception):
            self.procedures.banner.error(str(exc))

        self._tasks.run(
            lambda: client.list_procedures(binary_id),
            on_success=done,
            on_error=failed,
            on_finished=lambda: self.procedures.set_loading(False),
        )

    def _select_cursor_procedure(self) -> None:
        try:
            self.procedures.on_cursor_function(idb.function_start(idb.current_ea()))
        except Exception:  # noqa: BLE001 - outside IDA
            pass

    def _on_procedure_selected(self, proc: Optional[models.Procedure]) -> None:
        if proc is None:
            self.inspector.show_procedure(None)
            return
        self.inspector.show_procedure(ProcTarget(proc.binary_id, proc.start_ea, proc.name, proc.hard_hash, True, proc))

    def _jump(self, rva_text: str) -> None:
        try:
            rva = int(rva_text, 16)
        except ValueError:
            return
        base = self._loaded.image_base if self._loaded else 0
        try:
            if not idb.jump_to(rva + base):
                idb.jump_to(rva)
        except Exception as exc:  # noqa: BLE001
            _log.debug("jump failed: %s", exc)

    def _rename(self, target: ProcTarget) -> None:
        client = self._client
        if client is None:
            return
        name = TextEditorDialog.ask(self, "Rename procedure on server", target.name, multiline=False, placeholder="New procedure name")
        if not name or name == target.name:
            return

        def done(_):
            self.inspector.procedure_tab.update_name(name)
            if target.procedure is not None:
                self.procedures.update_procedure(dataclasses.replace(target.procedure, name=name))
            self.banner.success(f"Renamed {target.rva} to '{name}' on the server.")

        self._tasks.run(
            lambda: client.rename_procedure(target.binary_id, target.rva, name),
            on_success=done,
            on_error=lambda exc: self.banner.error(str(exc)),
        )

    def _compare(self, target: ProcTarget, other: models.SimilarProcedure) -> None:
        client = self._client
        if client is None:
            return
        self.banner.info("Fetching procedure code…")

        def work():
            return client.get_procedure_code(target.binary_id, target.rva), client.get_procedure_code(other.binary_id, other.start_ea)

        def done(codes):
            self.banner.clear()
            dialog = CompareDialog(codes[0], codes[1], self)
            dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
            dialog.finished.connect(lambda _: dialog in self._dialogs and self._dialogs.remove(dialog))
            self._dialogs.append(dialog)
            dialog.show()

        self._tasks.run(work, on_success=done, on_error=lambda exc: self.banner.error(str(exc)))

    # ------------------------------------------------------------------ uploads
    def upload(self) -> None:
        client, loaded = self._client, self._loaded
        if client is None or loaded is None:
            return
        try:
            from ..exporter import prolog  # noqa: F401  (import check only)
            from ..exporter.prolog import sark

            sark_available = sark is not None
        except Exception:  # noqa: BLE001
            sark_available = False
        from ..exporter.disassembly import undo_available

        dialog = UploadDialog(
            binary_available=loaded.binary_exists,
            sark_available=sark_available,
            undo_available=undo_available(),
            create_functions=self._settings.create_missing_functions,
            parent=self,
        )
        if exec_dialog(dialog) != QtWidgets.QDialog.DialogCode.Accepted or not dialog.kind:
            return
        if dialog.kind == UploadDialog.BINARY:
            self._upload_binary(skip_unpack=dialog.skip_unpack)
        elif dialog.kind == UploadDialog.IDB:
            self._upload_idb()
        else:
            self._upload_disassembly(create_functions=dialog.create_functions)

    def _start_upload(self, label: str) -> None:
        self.banner.info(f"{label}… this can take a while for large files.")
        self.header.set_actions_enabled(upload=False, refresh=False, dashboard=True)

    def _finish_upload(self) -> None:
        self.header.set_actions_enabled(upload=True, refresh=True, dashboard=True)

    def _upload_failed(self, exc: Exception) -> None:
        self.banner.error(f"Upload failed: {exc}")

    def _register_pending(self, binary_id: str, kind: str, label: str) -> None:
        if any(p.binary_id == binary_id for p in self._pending):
            return
        self._pending.append(PendingUpload(binary_id=binary_id, kind=kind, label=label))

    def _upload_binary(self, *, skip_unpack: bool) -> None:
        client, loaded = self._client, self._loaded
        assert client is not None and loaded is not None
        path, bits = loaded.path, loaded.arch_bits
        self._start_upload("Uploading the original binary")

        def work():
            with open(path, "rb") as fh:
                payload = base64.b64encode(fh.read()).decode("ascii")
            return client.upload_binary(payload, skip_unpack=skip_unpack, arch_bits=bits)

        def done(sha1: str):
            self._register_pending(sha1, "original", "Original file")
            self.banner.success("Binary uploaded. Processing status is shown above.")
            self._version = None
            self.refresh()

        self._uploads.run(work, on_success=done, on_error=self._upload_failed, on_finished=self._finish_upload)

    def _upload_idb(self) -> None:
        client, loaded = self._client, self._loaded
        assert client is not None and loaded is not None
        workdir = tempfile.mkdtemp(prefix="unknowncyber-idb-")
        copy_path = os.path.join(workdir, f"{loaded.md5}.i64")
        try:
            idb.save_database_copy(copy_path)
        except Exception as exc:  # noqa: BLE001
            shutil.rmtree(workdir, ignore_errors=True)
            show_error(self, "Upload IDB", f"Could not save a copy of the database:\n{exc}")
            return
        bits = loaded.arch_bits
        self._start_upload("Uploading a copy of the IDB")

        def work():
            try:
                with open(copy_path, "rb") as fh:
                    payload = base64.b64encode(fh.read()).decode("ascii")
                return client.upload_binary(payload, skip_unpack=True, arch_bits=bits)
            finally:
                shutil.rmtree(workdir, ignore_errors=True)

        def done(sha1: str):
            self._register_pending(sha1, "container", "IDB upload (this session)")
            self.banner.success("IDB uploaded. The processed version appears in the version list when the server finishes.")
            self.refresh()

        self._uploads.run(work, on_success=done, on_error=self._upload_failed, on_finished=self._finish_upload)

    def _upload_disassembly(self, *, create_functions: bool) -> None:
        client, loaded = self._client, self._loaded
        assert client is not None and loaded is not None
        from ..exporter import ExportCancelled, ExportError, ExportOptions, export_disassembly

        try:
            import ida_kernwin
        except ImportError:
            ida_kernwin = None  # type: ignore

        def progress(done: int, total: int, message: str) -> bool:
            if ida_kernwin is None:
                return True
            text = f"{message}\n({done}/{total})" if total else message
            ida_kernwin.replace_wait_box(text)
            return not ida_kernwin.user_cancelled()

        if ida_kernwin is not None:
            ida_kernwin.show_wait_box("Exporting disassembly for Unknown Cyber…")
        try:
            result = export_disassembly(loaded, ExportOptions(create_missing_functions=create_functions), progress)
        except ExportCancelled:
            self.banner.info("Export cancelled.")
            return
        except ExportError as exc:
            show_error(self, "Disassembly export", str(exc))
            return
        except ImportError as exc:
            show_error(self, "Disassembly export", str(exc))
            return
        except Exception as exc:  # noqa: BLE001
            _log.exception("export failed")
            show_error(self, "Disassembly export", f"Export failed: {exc}")
            return
        finally:
            if ida_kernwin is not None:
                ida_kernwin.hide_wait_box()

        self._start_upload(f"Uploading {result.procedure_count} procedures")

        def work():
            try:
                return client.upload_disassembly(result.zip_path)
            finally:
                result.cleanup()

        def done(sha1: str):
            self._register_pending(sha1, "container", "Disassembly upload (this session)")
            self.banner.success("Disassembly uploaded. The processed version appears in the version list when the server finishes.")
            self.refresh()

        self._uploads.run(work, on_success=done, on_error=self._upload_failed, on_finished=self._finish_upload)

    # ------------------------------------------------------------------ status polling
    def _poll_pending(self) -> None:
        client = self._client
        if client is None or not self._pending:
            self._poll_timer.stop()
            self.header.upload_strip.clear()
            return
        snapshot = list(self._pending)

        def work():
            results = []
            for pending in snapshot:
                status = client.upload_status(pending.binary_id)
                info = client.get_file(pending.binary_id, with_children=True) if pending.kind == "container" else None
                results.append((pending, status, info))
            return results

        self._tasks.run(work, on_success=self._on_polled, on_error=lambda exc: _log.info("status poll failed: %s", exc))

    def _on_polled(self, results) -> None:
        changed = False
        for pending, status, info in results:
            pending.status = status
            if info is not None and info.children:
                # The container has been processed: the newest child is the usable version.
                child = info.children[-1]
                self._pending = [p for p in self._pending if p is not pending]
                if self._version is None or self._version.binary_id == pending.binary_id:
                    self._version = models.AnalysisVersion(label=child.label, binary_id=child.binary_id, kind="content")
                changed = True
            elif status.finished:
                self._pending = [p for p in self._pending if p is not pending]
                changed = True
        latest = results[-1][1] if results else None
        if latest is not None:
            self.header.upload_strip.show_status(latest)
        if changed:
            self.refresh()
        if not self._pending:
            self._poll_timer.stop()

    # ------------------------------------------------------------------ misc
    def open_dashboard(self) -> None:
        client = self._client
        version = self._version or (self._versions[0] if self._versions else None)
        if client is None or version is None:
            return
        try:
            QtGui.QDesktopServices.openUrl(QtCore.QUrl(client.dashboard_url(version.binary_id)))
        except ApiError as exc:
            self.banner.error(str(exc))


def build_form_class():
    """Return the ``ida_kernwin.PluginForm`` subclass (requires IDA)."""
    import ida_kernwin

    class UnknownCyberForm(ida_kernwin.PluginForm):
        def __init__(self):
            super().__init__()
            self.panel: Optional[MainPanel] = None

        def OnCreate(self, form):  # noqa: N802 - IDA API
            parent = form_to_widget(self, form)
            layout = QtWidgets.QVBoxLayout(parent)
            layout.setContentsMargins(0, 0, 0, 0)
            self.panel = MainPanel(parent)
            layout.addWidget(self.panel)
            try:
                parent.setWindowIcon(brand.shield_icon())
            except Exception:  # noqa: BLE001 - cosmetic
                pass

        def OnClose(self, form):  # noqa: N802 - IDA API
            if self.panel is not None:
                self.panel.shutdown()
                self.panel = None

        def Show(self, caption, options=0):  # noqa: N802 - IDA API
            if not options:
                options = getattr(ida_kernwin.PluginForm, "WOPN_DP_RIGHT", 0) | getattr(ida_kernwin.PluginForm, "WOPN_DP_SZHINT", 0)
            return super().Show(caption, options=options)

    return UnknownCyberForm


def __getattr__(name):  # PEP 562: build the IDA-dependent class lazily
    if name == "UnknownCyberForm":
        return build_form_class()
    raise AttributeError(name)
