"""Settings dialog: host, API key, TLS options, behaviour."""

from __future__ import annotations

from .. import client as client_mod
from .. import config
from ..qt import QtCore, QtWidgets, exec_dialog
from ..workers import TaskGroup
from . import brand
from .dialogs import Banner

Qt = QtCore.Qt


class SettingsDialog(QtWidgets.QDialog):
    def __init__(self, settings: config.Settings, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Unknown Cyber settings")
        self.setMinimumWidth(580)
        brand.apply(self)
        self._tasks = TaskGroup(self)
        self._settings = settings
        self._saved = False

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)
        self._banner = Banner(self)
        layout.addWidget(self._banner)

        form = QtWidgets.QFormLayout()
        form.setFieldGrowthPolicy(QtWidgets.QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        form.setHorizontalSpacing(12)
        form.setVerticalSpacing(8)
        layout.addLayout(form)
        form.addRow(brand.section_label("Connection", self))

        self._host = QtWidgets.QLineEdit(settings.api_host, self)
        self._host.setPlaceholderText(config.DEFAULT_HOST)
        form.addRow("API host", self._host)

        key_row = QtWidgets.QHBoxLayout()
        self._key = QtWidgets.QLineEdit(settings.api_key, self)
        self._key.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
        self._key.setPlaceholderText("Paste your Unknown Cyber API key")
        self._reveal = QtWidgets.QToolButton(self)
        self._reveal.setText("Show")
        self._reveal.setCheckable(True)
        self._reveal.toggled.connect(
            lambda on: self._key.setEchoMode(QtWidgets.QLineEdit.EchoMode.Normal if on else QtWidgets.QLineEdit.EchoMode.Password)
        )
        key_row.addWidget(self._key, 1)
        key_row.addWidget(self._reveal)
        form.addRow("API key", key_row)

        backend = config.key_storage_backend()
        if backend == "keyring":
            storage_note = "The key is stored in your operating system's credential store."
        elif backend == "environment":
            storage_note = "The key comes from the UNKNOWNCYBER_API_KEY environment variable and cannot be changed here."
            self._key.setEnabled(False)
        else:
            storage_note = (
                f"No OS credential store available (install the 'keyring' package). "
                f"The key will be saved with owner-only permissions in {config.key_file_path()}."
            )
        note = brand.muted("🔒 " + storage_note)
        note.setProperty("role", "hint")
        note.setWordWrap(True)
        form.addRow("", note)

        self._verify = QtWidgets.QCheckBox("Verify TLS certificates (recommended)", self)
        self._verify.setChecked(settings.verify_tls)
        form.addRow("Security", self._verify)

        ca_row = QtWidgets.QHBoxLayout()
        self._ca = QtWidgets.QLineEdit(settings.ca_bundle, self)
        self._ca.setPlaceholderText("Optional: PEM bundle for a self-hosted CA")
        browse = QtWidgets.QPushButton("Browse…", self)
        browse.clicked.connect(self._browse_ca)
        ca_row.addWidget(self._ca, 1)
        ca_row.addWidget(browse)
        form.addRow("CA bundle", ca_row)

        self._dashboard = QtWidgets.QLineEdit(settings.dashboard_url, self)
        self._dashboard.setPlaceholderText(f"Derived from the API host ({settings.dashboard_base_url})")
        form.addRow("Dashboard URL", self._dashboard)

        spacer = QtWidgets.QWidget(self)
        spacer.setFixedHeight(4)
        form.addRow(spacer)
        form.addRow(brand.section_label("Behaviour", self))

        self._poll = QtWidgets.QSpinBox(self)
        self._poll.setRange(5, 600)
        self._poll.setSuffix(" s")
        self._poll.setValue(settings.auto_poll_seconds)
        form.addRow("Poll interval", self._poll)

        self._auto_open = QtWidgets.QCheckBox("Open the panel automatically when a database is opened", self)
        self._auto_open.setToolTip("Otherwise open it with Ctrl-Shift-A or Edit > Plugins > Unknown Cyber.")
        self._auto_open.setChecked(settings.auto_open)
        form.addRow("Panel", self._auto_open)

        self._create_funcs = QtWidgets.QCheckBox("Create functions for unclaimed prologues", self)
        self._create_funcs.setToolTip(
            "During disassembly export, turn push ebp / mov ebp, esp sequences outside functions into functions (reverted afterwards)."
        )
        self._create_funcs.setChecked(settings.create_missing_functions)
        form.addRow("Export", self._create_funcs)

        self._appearance = QtWidgets.QComboBox(self)
        for text, value in (
            ("Unknown Cyber brand (ink cards)", "brand"),
            ("Match the host theme", "auto"),
            ("Plain host widgets", "plain"),
        ):
            self._appearance.addItem(text, value)
        index = self._appearance.findData((settings.appearance or "brand").lower())
        self._appearance.setCurrentIndex(max(0, index))
        self._appearance.setToolTip("Takes effect the next time the panel is opened.")
        form.addRow("Appearance", self._appearance)

        self._log_level = QtWidgets.QComboBox(self)
        self._log_level.addItems(["ERROR", "WARNING", "INFO", "DEBUG"])
        self._log_level.setCurrentText(settings.log_level.upper() if settings.log_level else "INFO")
        form.addRow("Log level", self._log_level)

        buttons = QtWidgets.QHBoxLayout()
        buttons.setSpacing(8)
        self._test = QtWidgets.QPushButton("Test connection", self)
        self._test.setProperty("role", "outline")
        self._test.setCursor(Qt.CursorShape.PointingHandCursor)
        cancel = QtWidgets.QPushButton("Cancel", self)
        self._save = brand.primary_button("Save", self)
        buttons.addWidget(self._test)
        buttons.addStretch(1)
        buttons.addWidget(cancel)
        buttons.addWidget(self._save)
        self._save.clicked.connect(self._on_save)
        cancel.clicked.connect(self.reject)
        self._test.clicked.connect(self._on_test)
        layout.addLayout(buttons)

        self._verify.toggled.connect(self._warn_insecure)
        self._warn_insecure(self._verify.isChecked())

    # -- helpers -------------------------------------------------------------
    def _browse_ca(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select CA bundle", "", "PEM files (*.pem *.crt *.cer);;All files (*)")
        if path:
            self._ca.setText(path)

    def _warn_insecure(self, checked: bool):
        if not checked:
            self._banner.warning("TLS verification is disabled. Your API key can be intercepted on the network.")
        elif self._banner.isVisible() and "TLS verification is disabled" in self._banner._label.text():
            self._banner.clear()

    def _collect(self) -> config.Settings:
        return config.Settings(
            api_host=self._host.text().strip() or config.DEFAULT_HOST,
            verify_tls=self._verify.isChecked(),
            ca_bundle=self._ca.text().strip(),
            dashboard_url=self._dashboard.text().strip(),
            auto_poll_seconds=int(self._poll.value()),
            create_missing_functions=self._create_funcs.isChecked(),
            auto_open=self._auto_open.isChecked(),
            log_level=self._log_level.currentText(),
            appearance=self._appearance.currentData(),
            api_key=self._key.text().strip() if self._key.isEnabled() else self._settings.api_key,
        )

    def _validate(self):
        candidate = self._collect()
        error = config.validate_host(candidate.api_host)
        if error:
            self._banner.error(error)
            return None
        if not candidate.api_key:
            self._banner.error("An API key is required.")
            return None
        if candidate.ca_bundle:
            import os

            if not os.path.isfile(candidate.ca_bundle):
                self._banner.error("The CA bundle path does not exist.")
                return None
        return candidate

    def _on_test(self):
        candidate = self._validate()
        if candidate is None:
            return
        self._test.setEnabled(False)
        self._banner.info("Contacting the server…")

        def work():
            client_mod.MagicClient(candidate).ping()

        self._tasks.run(
            work,
            on_success=lambda _: self._banner.success(f"Connected to {candidate.api_base_url}."),
            on_error=lambda exc: self._banner.error(str(exc)),
            on_finished=lambda: self._test.setEnabled(True),
        )

    def _on_save(self):
        candidate = self._validate()
        if candidate is None:
            return
        try:
            config.save(candidate)
            if self._key.isEnabled():
                config.store_api_key(candidate.api_host, candidate.api_key)
        except OSError as exc:
            self._banner.error(f"Could not save settings: {exc}")
            return
        self._settings = candidate
        self._saved = True
        self.accept()

    @property
    def settings(self) -> config.Settings:
        return self._settings

    @classmethod
    def edit(cls, settings: config.Settings, parent=None):
        dialog = cls(settings, parent)
        exec_dialog(dialog)
        return dialog.settings if dialog._saved else None
