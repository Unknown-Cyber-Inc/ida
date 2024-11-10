import json
from PyQt5 import QtWidgets, QtCore
from PyQt5.QtWidgets import QTableWidgetItem

from idamagic.api import (
    add_procedure_tag,
    create_file_note,
    create_file_tag,
    create_procedure_note,
    create_procedure_genomics_note,
    create_procedure_genomics_tag,
    update_file_note,
    update_file_procedure_genomics,
    update_procedure_genomics_note,
    update_procedure_note,
)
from ..collection_elements.tree_nodes import ProcSimpleTextNode
from ..collection_elements.list_items import CustomListItem


class TextPopup(QtWidgets.QDialog):
    """Custom widget to edit text in a popup"""

    def __init__(self, fill_text=None, parent=None):
        """init method"""
        super().__init__(parent)
        self.fill_text = fill_text
        self.text_area = QtWidgets.QPlainTextEdit()
        self.parent = parent
        self.set_plain_text()
        self.init_ui()

    def init_ui(self):
        """Create widget and handle behavior"""

        # create button row
        button_row = QtWidgets.QDialogButtonBox()
        button_row.setStandardButtons(
            QtWidgets.QDialogButtonBox.Cancel
            | QtWidgets.QDialogButtonBox.Reset
            | QtWidgets.QDialogButtonBox.Save
        )
        button_row.setCenterButtons(False)
        button_row.button(QtWidgets.QDialogButtonBox.Cancel).clicked.connect(
            self.on_cancel_click
        )
        button_row.button(QtWidgets.QDialogButtonBox.Save).clicked.connect(
            self.on_save_click
        )
        button_row.button(QtWidgets.QDialogButtonBox.Reset).clicked.connect(
            self.on_reset_click
        )

        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(self.text_area)
        layout.addWidget(button_row)

    def set_plain_text(self):
        """Set the text of the QPlainTextEdit"""
        self.text_area.setPlainText(self.fill_text)

    def on_reset_click(self):
        """When edit popup's reset button is clicked"""
        self.set_plain_text()

    def on_cancel_click(self):
        """When edit popup's cancel button is clicked"""
        pass

    def on_save_click(self):
        """When edit popup's save button is clicked"""
        pass

    def save_create(self, text):
        """API call logic for `create` submissions"""
        pass

    def save_edit(self, text, item):
        """API call logic for `edit` submissions"""
        pass


class ProcTextPopup(TextPopup):
    """Popup for Proc tab's tree widget"""

    def __init__(
        self,
        fill_text,
        parent,
        listing_item=None,
        binary_id=None,
        rva=None,
        item_type=None,
        table_row=None,
        proc_table=None,
    ):
        """Init method"""
        super().__init__(fill_text, parent)
        self.parent = parent
        self.listing_item = listing_item
        self.binary_id = binary_id
        self.rva = rva
        self.item_type = item_type
        self.table_row = table_row
        self.proc_table = proc_table

    def on_cancel_click(self):
        """When edit popup's cancel button is clicked"""
        self.hide()

    def on_save_click(self):
        """When edit popup's save button is clicked"""
        text = self.text_area.toPlainText()

        if self.fill_text or self.item_type == "Proc Name":
            text = self.save_edit(text, self.listing_item)
            if self.item_type == "Proc Name":
                self.listing_item.setText(self.listing_item.rva + " - " + text)
                self.listing_item.full_name = (
                    self.listing_item.rva + " - " + text
                )

                table_item = self.proc_table.item(
                    self.listing_item.table_row, 0
                )
                data = table_item.data(1)
                data.procedure_name = text

                updated_item = QTableWidgetItem(data.start_ea + " - " + text)
                self.proc_table.setItem(
                    self.listing_item.table_row, 0, updated_item
                )
                table_item = self.proc_table.item(
                    self.listing_item.table_row, 0
                )
                table_item.setData(1, data)

            elif text:
                text = (
                    f"{text}\n"
                    f"    User: Current IDA User\n"
                    f"    Create time: Current Session"
                )
                self.listing_item.setText(text)
                self.listing_item.text = text
                self.listing_item.note = text
        else:
            text = self.save_create(text)

        if text is not None:
            self.hide()

    def save_create(self, text):
        """API call logic for `create` submissions"""
        if self.item_type == "Derived file note":
            response = create_file_note(
                binary_id=self.binary_id,
                text=text,
                info_msgs=[
                    "Could not create file Note."
                ]
            )
        elif self.item_type == "Derived file tag":
            response = create_file_tag(
                binary_id=self.binary_id,
                text=text,
                info_msgs=[
                    "Could not create file Tag."
                ]
            )
        elif self.item_type == "Notes":
            response = create_procedure_genomics_note(
                binary_id=self.binary_id,
                rva=self.rva,
                text=text,
                info_msgs=[
                    "Could not create Procedure Note."
                ]
            )
        elif self.item_type == "Tags":
            response = create_procedure_genomics_tag(
                binary_id=self.binary_id,
                rva=self.rva,
                text=text,
                info_msgs=[
                    "Could not create Procedure Tag."
                ]
            )
        elif self.item_type == "Procedure Group Notes":
            response = create_procedure_note(
                proc_hash=self.listing_item.hard_hash,
                text=text,
            )
        elif self.item_type == "Procedure Group Tags":
            response = add_procedure_tag(
                proc_hash=self.listing_item.hard_hash,
                text=text,
            )

        if 200 <= response.status <= 299:
            if (
                self.item_type == "Notes"
                or self.item_type == "Derived file note"
            ):
                self.listing_item.appendRow(
                    ProcSimpleTextNode(
                        hard_hash=self.listing_item.hard_hash,
                        node_id=response.resource.id,
                        text=(
                            f"{text}\n"
                            f"    User: {response.resource.username}\n"
                            f"    Create time: {response.resource.create_time}"
                        ),
                        binary_id=self.binary_id,
                        rva=self.rva,
                    )
                )
            elif self.item_type == "Procedure Group Notes":
                self.listing_item.appendRow(
                    ProcSimpleTextNode(
                        hard_hash=self.listing_item.hard_hash,
                        node_id=response.resource.id,
                        text=(
                            f"{text}\n"
                            f"    User: {response.resource.username}\n"
                            f"    Create time: {response.resource.create_time}"
                        ),
                        binary_id=None,
                        rva=None,
                    )
                )
            elif (
                self.item_type == "Tags"
                or self.item_type == "Derived file tag"
            ):
                self.listing_item.appendRow(
                    ProcSimpleTextNode(
                        hard_hash=self.listing_item.hard_hash,
                        node_id=response.resource.id,
                        text=response.resource.name,
                        binary_id=self.binary_id,
                        rva=self.rva,
                    )
                )
            elif self.item_type == "Procedure Group Tags":
                self.listing_item.appendRow(
                    ProcSimpleTextNode(
                        hard_hash=self.listing_item.hard_hash,
                        node_id=response.resource.id,
                        text=response.resource.name,
                        binary_id=None,
                        rva=None,
                    )
                )
            return text

    def save_edit(self, text, item):
        """API call logic for `edit` submissions"""
        if self.item_type == "Derived file note":
            response = update_file_note(
                binary_id=self.binary_id,
                note_id=item.node_id,
                text=text,
                info_msgs=[
                    "Could not update file Note."
                ]
            )
        elif self.item_type == "Notes":
            response = update_procedure_genomics_note(
                binary_id=self.binary_id,
                rva=self.rva,
                note_id=item.node_id,
                text=text,
                info_msgs=[
                    "Could not update Procedure Note."
                ]
            )
        elif self.item_type == "Procedure Group Notes":
            response = update_procedure_note(
                hard_hash=self.listing_item.hard_hash,
                note_id=item.node_id,
                text=text,
                info_msgs=[
                    "Could not update Procedure Group Note."
                ]
            )
        elif self.item_type == "Proc Name":
            response = update_file_procedure_genomics(
                binary_id=self.binary_id,
                rva=item.rva,
                text=text,
                info_msgs=["Could not update Procedure Name."]
            )

        return text


class FileTextPopup(TextPopup):
    """Popup for Files tab's list widget"""

    def __init__(self, fill_text, parent):
        """Init method"""
        super().__init__(fill_text, parent)

    def on_cancel_click(self):
        """When edit popup's cancel button is clicked"""
        self.parent.hide_popup()

    def on_save_click(self):
        """When edit popup's save button is clicked"""
        text = self.text_area.toPlainText()

        if self.fill_text:
            item = self.parent.list_widget.currentItem()
            text = self.save_edit(text, item)
            if text:
                text = (
                    f"{text}\n"
                    f"    User: Current IDA User\n"
                    f"    Create time: Current Session"
                )
                item.setText(text)
                item.proc_node.note = text
        else:
            text = self.save_create(text)

        if text is not None:
            self.parent.hide_popup()

    def save_create(self, text):
        """API call logic for `create` submissions"""
        if self.parent.list_widget_tab_bar.currentIndex() == 0:
            type_str = "Notes"
        elif self.parent.list_widget_tab_bar.currentIndex() == 1:
            type_str = "Tags"

        if "Notes" in type_str:
            response = create_file_note(
                binary_id=self.parent.binary_id,
                text=text,
                info_msgs=[
                    "Could not create file Note."
                ]
            )
        elif "Tags" in type_str:
            response = create_file_tag(
                binary_id=self.parent.binary_id,
                text=text,
                info_msgs=[
                    "Could not create file Tag."
                ]
            )
        if 200 <= response.status <= 299:
            if "Notes" in type_str:
                self.parent.list_widget.addItem(
                    CustomListItem(
                        ProcSimpleTextNode(
                            node_id=response.resource.id,
                            text=(
                                f"{text}\n"
                                f"    User: {response.resource.username}\n"
                                f"    Create time: {response.resource.create_time}"
                            ),
                        )
                    )
                )
            elif "Tags" in type_str:
                self.parent.list_widget.addItem(
                    CustomListItem(
                        ProcSimpleTextNode(
                            node_id=response.resource.id,
                            text=response.resource.name,
                        )
                    )
                )
            return text

    def save_edit(self, text, item):
        """API call logic for `edit` submissions"""
        if self.parent.list_widget_tab_bar.currentIndex() == 0:
            type_str = "Notes"
        elif self.parent.list_widget_tab_bar.currentIndex() == 1:
            type_str = "Tags"
        if "Notes" in type_str:
            response = update_file_note(
                binary_id=self.parent.binary_id,
                note_id=item.proc_node.node_id,
                text=text,
                info_msgs=[
                    "Could not update file Note."
                ]
            )
        return text


class FileUploadPopup(QtWidgets.QMessageBox):
    """Custom popup with file and disassembly upload buttons."""

    def __init__(self, widget_parent, ida_version_valid):
        super().__init__()
        self.widget_parent = widget_parent
        self.setWindowTitle("Upload")
        self.setText("Select the type of upload to perform.")
        self.setStandardButtons(QtWidgets.QMessageBox.Cancel)

        # Binary upload button
        binary_upload_button = self.addButton(
            "Binary", QtWidgets.QMessageBox.ActionRole
        )
        binary_upload_button.setEnabled(True)
        binary_upload_button.clicked.connect(
            self.widget_parent.upload_binary_button_click
        )
        if ida_version_valid:
            # idb upload button
            idb_upload_button = self.addButton(
                "IDB", QtWidgets.QMessageBox.ActionRole
            )
            idb_upload_button.setEnabled(True)
            idb_upload_button.clicked.connect(
                self.widget_parent.upload_idb_button_click
            )
            # Disassembly upload button
            disassembly_upload_button = self.addButton(
                "Disassembly", QtWidgets.QMessageBox.ActionRole
            )
            disassembly_upload_button.setEnabled(True)
            disassembly_upload_button.clicked.connect(
                self.widget_parent.upload_disassembly_button_click
            )


class FileUnpackPopup(QtWidgets.QMessageBox):
    """Custom popup with unpack and skip unpack buttons."""

    def __init__(self, widget_parent):
        super().__init__()
        self.widget_parent = widget_parent
        self.setWindowTitle("Skip unpacking?")
        self.setText("Skip unpacking the uploaded file?")
        self.setStandardButtons(QtWidgets.QMessageBox.Cancel)

        # skip unpack button
        skip_button = self.addButton(
            "YES, skip unpacking", QtWidgets.QMessageBox.ActionRole
        )
        skip_button.setEnabled(True)
        # unpack button
        unpack_button = self.addButton(
            "NO, unpack file", QtWidgets.QMessageBox.ActionRole
        )
        unpack_button.setEnabled(True)

        skip_button.clicked.connect(self.widget_parent.binary_skip_unpack)
        unpack_button.clicked.connect(self.widget_parent.binary_unpack)


class FileNotFoundPopup(QtWidgets.QWidget):
    """
    Widget for the popup displayed when the plugin is loaded with a file that
    has not yet been uploaded to UnknownCyber Magic. Prompts user to upload.
    """

    def __init__(self, func):
        super().__init__()
        self.message = (
            "You have not uploaded this file to UnknownCyber Magic. "
            + "Upload to have access to any plugin features."
        )
        self.button_function = func
        self.init_ui()

    def init_ui(self):
        """Create widgets and populate with data."""
        # main popup window
        popup = QtWidgets.QMessageBox()
        popup.setWindowTitle("Processed file not available.")
        popup.setText(self.message)

        # upload button
        upload_button = popup.addButton(
            "Upload file", QtWidgets.QMessageBox.ActionRole
        )
        upload_button.setEnabled(True)
        upload_button.clicked.connect(self.button_function)

        popup.exec_()


class DeleteConfirmationPopup(QtWidgets.QMessageBox):
    """Widget to display when delete is clicked."""

    def __init__(self, widget_parent):
        super().__init__()
        self.widget_parent = widget_parent
        self.setWindowTitle("Delete this item?")
        self.setText("Are you sure you want to delete this item?")
        self.setStandardButtons(
            QtWidgets.QMessageBox.Ok | QtWidgets.QMessageBox.Cancel
        )


class StatusPopup(QtWidgets.QMessageBox):
    """Popup to display uploaded file status"""

    PIPELINE_MAP = {
        "dashboard_report": "Label Inference",
        "ioc_handler": "Ioc Extraction",
        "ioc_extract_handler": "Ioc Extraction",
        "proc_hash_signatures": "Yara Generation",
        "reputation_handler": "Maliciousness Determination",
        "similarity_computation": "Similarity Matching",
        "srl_archive": "Archive Extraction",
        "srl_juice": "Genomic Juicing",
        "alt_juice_handler": "Disassembly Genomic Juicing",
        "srl_scanners": "AV Scan Report",
        "srl_unpacker": "Unpacking",
        "web_request_handler": "Filetype Discovery",
    }

    def __init__(self, resource_list, widget_parent):
        super(StatusPopup, self).__init__(parent=widget_parent)
        self.widget_parent = widget_parent
        self.setWindowTitle("Upload Status")

        new_text_list = []
        for resource in resource_list:
            if resource.sha1 and resource.status:
                mapped_pipelines = self.convert_pipeline_names(resource.pipeline)

                new_text_list.append(
                    "File hash: "
                    + resource.sha1
                    + "\n\nCreate time: "
                    + str(resource.create_time)
                    + "\n\nStatus: "
                    + str(resource.status).capitalize()
                    + "\n\n"
                    + str(mapped_pipelines)
                )

        results = "\n\n============================================\n\n".join(new_text_list)

        self.setText(results)
        self.setStandardButtons(QtWidgets.QMessageBox.Ok)

    def convert_pipeline_names(self, pipelines):
        """Map API response pipelines to user-friendly names."""
        return json.dumps(
            {
                self.PIPELINE_MAP.get(k, k): v for k, v in pipelines.to_dict().items()
                if v
            },
            indent=4
        )


class ErrorPopup(QtWidgets.QDialog):
    """Popup to display significant errors."""

    def __init__(self, info_msgs, error_msgs):
        super().__init__()
        final_msg = ""
        out_err_msg = ""
        if info_msgs:
            final_msg = "\n\n".join(info_msgs)
        if isinstance(error_msgs, dict) and "errors" in error_msgs:
            error_msg_list = [str(error["reason"]) for error in error_msgs["errors"]]
            out_err_msg = "\n\n".join(error_msg_list)
        elif isinstance(error_msgs, list):
            out_err_msg = "\n\n".join(error_msgs)
        if out_err_msg:
            final_msg += "\n\n" + out_err_msg

        # layout details
        layout = QtWidgets.QVBoxLayout(self)
        display_msg = QtWidgets.QTextEdit()
        display_msg.setReadOnly(True)
        display_msg.setText(final_msg)
        ok_button = QtWidgets.QPushButton("OK", self)
        ok_button.setSizePolicy(
            QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed
        )
        ok_button.clicked.connect(self.accept)

        # layout setup
        button_layout = QtWidgets.QHBoxLayout()
        button_layout.addStretch()
        button_layout.addWidget(ok_button)
        layout.addWidget(display_msg)
        layout.addLayout(button_layout)
        self.setLayout(layout)


class ComparePopup(QtWidgets.QDialog):
    """Popup to display procedure code from two procedures."""

    def __init__(self, orig_proc, derived_proc, parent=None):
        super(ComparePopup, self).__init__(parent)

        self.setWindowTitle("Procedure Comparison")
        self.resize(600, 400)

        orig_code = "\n\n".join(
            "\n".join(code_line for code_line in block.code)
            for block in orig_proc.blocks
            )
        derived_code = "\n\n".join(
            "\n".join(code_line for code_line in block.code)
            for block in derived_proc.blocks
            )

        main_layout = QtWidgets.QVBoxLayout(self)
        lock_layout = QtWidgets.QHBoxLayout()
        labels_layout = QtWidgets.QHBoxLayout()
        code_layout = QtWidgets.QHBoxLayout()
        lower_layout = QtWidgets.QHBoxLayout()

        self.lock_button = QtWidgets.QPushButton("Lock Scroll")
        self.lock_button.clicked.connect(self.toggle_scroll_lock)
        self.scroll_locked = False

        self.orig_label = QtWidgets.QLabel(
            f"File hash: {orig_proc.binary_id}\nAddress: {orig_proc.start_ea}"
        )
        self.derived_label = QtWidgets.QLabel(
            f"File hash: {derived_proc.binary_id}\nAddress: {derived_proc.start_ea}"
        )

        self.orig_code_area = QtWidgets.QTextEdit(self)
        self.derived_code_area = QtWidgets.QTextEdit(self)
        self.orig_code_area.setTextInteractionFlags(
            QtCore.Qt.TextSelectableByMouse | QtCore.Qt.TextSelectableByKeyboard
        )
        self.derived_code_area.setTextInteractionFlags(
            QtCore.Qt.TextSelectableByMouse | QtCore.Qt.TextSelectableByKeyboard
        )
        self.orig_code_area.setPlainText(orig_code)
        self.derived_code_area.setPlainText(derived_code)

        self.orig_code_area.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOn)
        self.orig_code_area.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOn)
        self.derived_code_area.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOn)
        self.derived_code_area.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOn)

        close_button = QtWidgets.QPushButton("Close", self)
        close_button.clicked.connect(self.accept)

        lock_layout.addWidget(self.lock_button)
        lock_layout.addStretch()

        labels_layout.addWidget(self.orig_label)
        labels_layout.addWidget(self.derived_label)

        code_layout.addWidget(self.orig_code_area)
        code_layout.addWidget(self.derived_code_area)

        lower_layout.addWidget(close_button)

        main_layout.addLayout(lock_layout)
        main_layout.addLayout(labels_layout)
        main_layout.addLayout(code_layout)
        main_layout.addLayout(lower_layout)

    def toggle_scroll_lock(self):
        self.scroll_locked = not self.scroll_locked
        if self.scroll_locked:
            # Connect the scroll bars
            self.orig_code_area.verticalScrollBar().valueChanged.connect(self.sync_scroll)
            self.derived_code_area.verticalScrollBar().valueChanged.connect(self.sync_scroll)
        else:
            # Disconnect the scroll bars
            self.orig_code_area.verticalScrollBar().valueChanged.disconnect(self.sync_scroll)
            self.derived_code_area.verticalScrollBar().valueChanged.disconnect(self.sync_scroll)

    def sync_scroll(self, value):
        # Determine the sender and the receiver
        sender = self.sender()
        if sender == self.orig_code_area.verticalScrollBar():
            receiver = self.derived_code_area.verticalScrollBar()
        else:
            receiver = self.orig_code_area.verticalScrollBar()

        # Calculate the percentage scrolled
        max_value = sender.maximum() - sender.minimum()
        percentage_scrolled = (value - sender.minimum()) / max_value if max_value else 0

        # Set the receiver's scroll position to the same percentage
        receiver_value = percentage_scrolled * (
            receiver.maximum() - receiver.minimum()
        ) + receiver.minimum()
        receiver.setValue(int(receiver_value))

class GenericPopup(QtWidgets.QDialog):
    """
    Generic popup that will display simple messages.
    """
    def __init__(self, message, parent=None):
        super().__init__()

        self.resize(500, 300)
        self.message = message
        self.parent = parent

        # layout details
        layout = QtWidgets.QVBoxLayout(self)
        display_msg = QtWidgets.QTextEdit()
        display_msg.setReadOnly(True)
        display_msg.setText(message)
        ok_button = QtWidgets.QPushButton("OK", self)
        ok_button.setSizePolicy(
            QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed
        )
        ok_button.clicked.connect(self.accept)

        # layout setup
        button_layout = QtWidgets.QHBoxLayout()
        button_layout.addStretch()
        button_layout.addWidget(ok_button)
        layout.addWidget(display_msg)
        layout.addLayout(button_layout)
        self.setLayout(layout)

class PopupWorker(QtCore.QThread):
    """
    Worker used to notify user of processes happening that may take extended time.
    """
    finished = QtCore.pyqtSignal()

    def __init__(self, process, *args, **kwargs):
        super().__init__()
        self.process = process
        self.args = args
        self.kwargs = kwargs

    def run(self):
        self.process(*self.args, **self.kwargs)
        self.finished.emit()
