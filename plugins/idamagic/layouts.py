"""Custom layouts used for widgets."""

from PyQt5.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QPushButton,
    QSpacerItem,
    QSizePolicy,
)

from .widgets.popups.popups import FileUploadPopup, FileUnpackPopup, FileNotFoundPopup
from .references import (
    get_version_hash,
    get_loaded_sha1,
    set_dropdown_widget,
    get_ida_version_valid,
)


class ProcsToggleLayout(QHBoxLayout):
    """Layout for procs_toggle QPushbutton widget."""

    def __init__(self, layout_parent):
        super().__init__()
        self.layout_parent = layout_parent
        self.procs_toggle = QPushButton("Hide Procedures Section")
        self.procs_toggle.clicked.connect(self.toggle_procs)
        self.addWidget(self.procs_toggle)
        spacer = QSpacerItem(
            0,
            0,
            QSizePolicy.Expanding,
            QSizePolicy.Minimum,
        )
        self.addItem(spacer)

    def toggle_procs(self):
        """Toggle collapse or expansion of procedures widget"""
        if self.procs_toggle.text() == "Hide Procedures Section":
            self.procs_toggle.setText("Show Procedures Section")
            self.hide_widgets()
        else:
            self.procs_toggle.setText("Hide Procedures Section")
            self.show_widgets()

    def show_widgets(self):
        """Set widgets to `show()`"""
        self.layout_parent.pushbutton.show()
        self.layout_parent.proc_table.show()
        if get_version_hash() != get_loaded_sha1():
            self.layout_parent.sync_warning.show()

    def hide_widgets(self):
        """Set widgets to `hide()`"""
        self.layout_parent.pushbutton.hide()
        self.layout_parent.sync_warning.hide()
        self.layout_parent.proc_table.hide()


class FilesButtonsLayout(QHBoxLayout):
    """Layout for files_toggle and upload QPushbutton widgets."""

    def __init__(self, layout_parent):
        super().__init__()
        self.layout_parent = layout_parent

        self.dropdown = QComboBox()

        self.files_toggle = QPushButton("Hide Files Section")
        self.files_toggle.setSizePolicy(
            QSizePolicy.MinimumExpanding,
            QSizePolicy.Fixed,
        )
        self.files_toggle.clicked.connect(self.toggle_files)
        self.upload_button = QPushButton("Upload File")
        self.upload_button.setSizePolicy(
            QSizePolicy.MinimumExpanding,
            QSizePolicy.Fixed,
        )
        self.upload_button.clicked.connect(self.main_upload_button_click)
        self.addWidget(self.dropdown)
        set_dropdown_widget(self.dropdown)
        self.addWidget(self.files_toggle)
        self.addWidget(self.upload_button)

    def toggle_files(self):
        """Toggle collapse or expansion of files widget"""
        if self.files_toggle.text() == "Hide Files Section":
            self.files_toggle.setText("Show Files Section")
            self.layout_parent.list_widget.hide()
        else:
            self.files_toggle.setText("Hide Files Section")
            self.layout_parent.list_widget.show()

    def main_upload_button_click(self):
        """Main upload button click behavior

        Renders a QMessageBox with all upload buttons
        """
        ida_version_valid = get_ida_version_valid()
        upload_popup = FileUploadPopup(self, ida_version_valid)
        upload_popup.exec_()

    def upload_binary_button_click(self):
        """Display check for `skip_unpack`"""
        unpack_popup = FileUnpackPopup(self)
        unpack_popup.exec_()

    def upload_idb_button_click(self):
        """Calls file upload passing in IDB file."""
        self.layout_parent.upload_idb()

    def upload_disassembly_button_click(self):
        """Calls disassembly upload."""
        self.layout_parent.upload_disassembled()

    def binary_skip_unpack(self):
        """Set skip_unpack arg to True. Send upload_file request method."""
        self.layout_parent.upload_binary(skip_unpack=True)

    def binary_unpack(self):
        """Set skip_unpack arg to False. Send upload_file request method."""
        self.layout_parent.upload_binary(skip_unpack=False)

    def show_file_not_found_popup(self):
        """Handles displaying the FileNotFound popup."""
        FileNotFoundPopup(self.main_upload_button_click)
