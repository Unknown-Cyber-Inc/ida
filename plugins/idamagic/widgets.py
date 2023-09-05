"""Custom widgets"""
from PyQt5 import QtWidgets, Qt
import cythereal_magic
from cythereal_magic.rest import ApiException
import json
import traceback
import logging

logger = logging.getLogger(__name__)

magic_api_client = cythereal_magic.ApiClient()
magic_api_client.client_side_validation = False
ctmfiles = cythereal_magic.FilesApi(magic_api_client)


class BaseListWidget(QtWidgets.QWidget):
    """Base widget for lists"""

    def __init__(
        self, list_items, list_type="", parent=None, binary_id=None, popup=None
    ):
        super().__init__(parent)

        self.list_type = list_type
        self.list_items = list_items
        self.label = QtWidgets.QLabel(list_type)
        self.list_widget_tab_bar = QtWidgets.QTabBar()
        self.list_widget = QtWidgets.QListWidget()
        self.binary_id = binary_id
        self.popup = popup
        self.name = None

        # create, link to signals, and disable buttons
        self.create_button = QtWidgets.QPushButton("Create")
        self.edit_button = QtWidgets.QPushButton("Edit")
        self.delete_button = QtWidgets.QPushButton("Delete")

        self.init_ui()

    def init_ui(self):
        "Create widget and handle behavior"
        self.create_button.clicked.connect(self.on_create_click)
        self.create_button.setEnabled(False)
        self.edit_button.setEnabled(False)
        self.edit_button.clicked.connect(self.on_edit_click)
        self.delete_button.setEnabled(False)
        self.delete_button.clicked.connect(self.on_delete_click)

        # create button row for create/edit/delete buttons
        self.button_row = QtWidgets.QHBoxLayout()
        self.button_row.addWidget(self.create_button)
        self.button_row.addWidget(self.edit_button)
        self.button_row.addWidget(self.delete_button)

        # create layout and add sub-widgets
        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(self.label)
        layout.addWidget(self.list_widget_tab_bar)
        layout.addWidget(self.list_widget)
        layout.addLayout(self.button_row)

        # connect item selection signal
        self.list_widget.itemSelectionChanged.connect(
            lambda: self.on_item_select(
                self.create_button, self.edit_button, self.delete_button
            )
        )

    def on_create_click(self):
        pass

    def on_edit_click(self):
        pass

    def on_delete_click(self):
        pass

    def on_item_select(self, create, edit, delete):
        pass


class FileListWidget(BaseListWidget):
    """Custom widget to display notes/tags/matches for a file."""

    def __init__(self, list_items, list_type="", binary_id=None, parent=None):
        self.popup = None
        super().__init__(
            list_items=list_items,
            list_type=list_type,
            parent=parent,
            binary_id=binary_id,
            popup=self.popup,
        )
        self.update_widget()

    def update_widget(self):
        """Create widget and handle behavior"""
        self.popup = (FileTextPopup(fill_text=None, parent=self),)
        self.list_widget_tab_bar.addTab("NOTES")
        self.list_widget_tab_bar.addTab("TAGS")
        self.list_widget_tab_bar.addTab("MATCHES")
        self.list_widget_tab_bar.setTabEnabled(0, False)
        self.list_widget_tab_bar.setTabEnabled(1, False)
        self.list_widget_tab_bar.setTabEnabled(2, False)

    def on_item_select(self, create, edit, delete):
        """Handle item selection behavior"""

        # get selected items
        selected_items = self.list_widget.selectedItems()

        # check if any items were selected
        if selected_items and "Tags" in self.label.text():
            create.setEnabled(True)
            edit.setEnabled(False)
            delete.setEnabled(True)
        elif selected_items and "Notes" in self.label.text():
            create.setEnabled(True)
            edit.setEnabled(True)
            delete.setEnabled(True)
        else:
            create.setEnabled(False)
            edit.setEnabled(False)
            delete.setEnabled(False)

    def refresh_list_data(self, list_items, list_type):
        """Clear and repopulate list model"""

        # update list items and type
        self.list_items = list_items
        self.list_type = list_type

        # clear items
        self.list_widget.clear()

        # add new items
        for item in self.list_items:
            self.list_widget.addItem(CustomListItem(item))

        # update label
        self.label.setText(self.list_type)

    def show_popup(self, text):
        """Handle showing edit popup"""
        self.popup = FileTextPopup(fill_text=text, parent=self)
        self.popup.show()

    def hide_popup(self):
        """Handle hiding edit popup"""
        self.popup.hide()

    def on_edit_click(self):
        """Handle edit pushbutton click"""
        item = self.list_widget.currentItem()
        text = item.text()
        self.show_popup(text=text)

    def on_create_click(self):
        """Handle edit pushbutton click"""
        self.show_popup(text=None)

    def on_delete_click(self):
        """Handle delete pushbutton click"""
        item = self.list_widget.currentItem()
        api_call = None
        type_str = ""
        if "Notes" in self.label.text():
            type_str = "NOTE"
            api_call = ctmfiles.delete_file_note
        elif "Tags" in self.label.text():
            type_str = "TAG"
            api_call = ctmfiles.remove_file_tag

        try:
            if "Notes" in self.label.text():
                _, status, _ = api_call(
                    binary_id=self.binary_id,
                    note_id=item.proc_node.node_id,
                    force=True,
                    no_links=True,
                )
            elif "Tags" in self.label.text():
                _, status, _ = api_call(
                    binary_id=self.binary_id,
                    tag_id=item.proc_node.node_id,
                    force=True,
                    no_links=True,
                )
        except ApiException as exp:
            logger.debug(traceback.format_exc())
            print(f"Could not delete {type_str} from selected procedure.")
            for error in json.loads(exp.body).get("errors"):
                logger.info(error["reason"])
                print(f"{error['reason']}: {error['message']}")
            return None
        except Exception as exp:
            logger.debug(traceback.format_exc())
            print("Unknown Error occurred")
            print(f"<{exp.__class__}>: {str(exp)}")
            # exit if this call fails so user can retry
            # (this func always returns None anyway)
            return None
        else:
            if status >= 200 and status <= 299:
                print(
                    f"{type_str} removed from selected procedure successfully."
                )
            else:
                print(f"Error deleting {type_str}.")
                print(f"Status Code: {status}")
                # print(f"Error message: {ctmr.errors}")
                return None

        index = self.list_widget.row(item)
        self.list_widget.takeItem(index)


class CustomListItem(QtWidgets.QListWidgetItem):
    """Custom list items for ProcSimpleTextNode"""

    def __init__(self, proc_node):
        super().__init__(proc_node.text)
        self.proc_node = proc_node


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
        type=None,
    ):
        """Init method"""
        super().__init__(fill_text, parent)
        self.parent = parent
        self.listing_item = listing_item
        self.binary_id = binary_id
        self.rva = rva
        self.type = type

    def on_cancel_click(self):
        """When edit popup's cancel button is clicked"""
        self.hide()

    def on_save_click(self):
        """When edit popup's save button is clicked"""
        text = self.text_area.toPlainText()

        if self.fill_text:
            text = self.save_edit(text, self.listing_item)
            if text:
                self.listing_item.setText(text)
                self.listing_item.note = text
        else:
            text = self.save_create(text)

        if text is not None:
            self.hide()
            # update list here

    def save_create(self, text):
        """API call logic for `create` submissions"""
        if self.type == "Notes":
            type_str = "NOTE"
            api_call = ctmfiles.create_procedure_genomics_note
        elif self.type == "Tags":
            type_str = "TAG"
            api_call = ctmfiles.create_procedure_genomics_tag

        try:
            if type_str == "NOTE":
                ctmr = api_call(
                    binary_id=self.binary_id,
                    rva=self.rva,
                    note=text,
                    public=False,
                    no_links=True,
                )
            elif type_str == "TAG":
                ctmr = api_call(
                    binary_id=self.binary_id,
                    rva=self.rva,
                    name=text,
                    no_links=True,
                )
        except ApiException as exp:
            logger.debug(traceback.format_exc())
            print(f"Could not update {type_str} from selected procedure.")
            for error in json.loads(exp.body).get("errors"):
                logger.info(error["reason"])
                print(f"{error['reason']}: {error['message']}")
            return None
        except Exception as exp:
            logger.debug(traceback.format_exc())
            print("Unknown Error occurred")
            print(f"<{exp.__class__}>: {str(exp)}")
            # exit if this call fails so user can retry
            # (this func always returns None anyway)
            return None
        else:
            print(ctmr)
            if ctmr.status >= 200 and ctmr.status <= 299:
                from .IDA_interface._procTree import ProcSimpleTextNode

                print(
                    f"{type_str} from selected procedure created successfully."
                )
                if type_str == "NOTE":
                    self.listing_item.appendRow(
                        ProcSimpleTextNode(
                            hard_hash=self.listing_item.hard_hash,
                            node_id=ctmr.resource.id,
                            text=ctmr.resource.note,
                            binary_id=self.binary_id,
                            rva=self.rva,
                        )
                    )
                elif type_str == "TAG":
                    self.listing_item.appendRow(
                        ProcSimpleTextNode(
                            hard_hash=self.listing_item.hard_hash,
                            node_id=ctmr.resource.id,
                            text=ctmr.resource.name,
                            binary_id=self.binary_id,
                            rva=self.rva,
                        )
                    )
                return text
            else:
                print(f"Error updating {type_str}.")
                print(f"Status Code: {ctmr.status}")
                print(f"Error message: {ctmr.errors}")
                return None

    def save_edit(self, text, item):
        """API call logic for `edit` submissions"""
        if self.type == "Notes":
            type_str = "NOTE"
            api_call = ctmfiles.update_procedure_genomics_note
        elif self.type == "Proc Name":
            type_str = "PROCEDURE NAME"
            api_call = print(
                "API call not implemented for procedure name EDIT, faux call made instead."
            )

        try:
            if type_str == "NOTE":
                _, status, _ = api_call(
                    binary_id=self.binary_id,
                    rva=self.rva,
                    note_id=item.node_id,
                    note=text,
                    public=False,
                    no_links=True,
                    update_mask="note"
                )
            elif type_str == "PROCEDURE NAME":
                ctmr = api_call()
        except ApiException as exp:
            logger.debug(traceback.format_exc())
            print(f"Could not update {type_str} from selected procedure.")
            for error in json.loads(exp.body).get("errors"):
                logger.info(error["reason"])
                print(f"{error['reason']}: {error['message']}")
            return None
        except Exception as exp:
            logger.debug(traceback.format_exc())
            print("Unknown Error occurred")
            print(f"<{exp.__class__}>: {str(exp)}")
            # exit if this call fails so user can retry
            # (this func always returns None anyway)
            return None
        else:
            # remove this block once endpoint implemented
            if type_str == "PROCEDURE NAME":
                print(
                    "Endpoints for procedure name functionality not implemented."
                )
                return None
            if status >= 200 and status <= 299:
                print(
                    f"{type_str} from selected procedure updated successfully."
                )
                return text
            else:
                print(f"Error updating {type_str}.")
                print(f"Status Code: {status}")
                return None


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
                item.setText(text)
                item.proc_node.note = text
        else:
            text = self.save_create(text)

        if text is not None:
            self.parent.hide_popup()

    def save_create(self, text):
        """API call logic for `create` submissions"""
        if "Notes" in self.parent.label.text():
            type_str = "NOTE"
            api_call = ctmfiles.create_file_note
        elif "Tags" in self.parent.label.text():
            type_str = "TAG"
            api_call = ctmfiles.create_file_tag

        try:
            if type_str == "NOTE":
                ctmr = api_call(
                    binary_id=self.parent.binary_id,
                    note=text,
                    public=False,
                    no_links=True,
                )
            elif type_str == "TAG":
                ctmr = api_call(
                    binary_id=self.parent.binary_id,
                    name=text,
                    no_links=True,
                )
        except ApiException as exp:
            logger.debug(traceback.format_exc())
            print(f"Could not create {type_str} for File.")
            for error in json.loads(exp.body).get("errors"):
                logger.info(error["reason"])
                print(f"{error['reason']}: {error['message']}")
            return None
        except Exception as exp:
            logger.debug(traceback.format_exc())
            print("Unknown Error occurred")
            print(f"<{exp.__class__}>: {str(exp)}")
            # exit if this call fails so user can retry
            # (this func always returns None anyway)
            return None
        else:
            if ctmr.status >= 200 and ctmr.status <= 299:
                from .IDA_interface._procTree import ProcSimpleTextNode

                if type_str == "NOTE":
                    self.parent.list_widget.addItem(
                        CustomListItem(
                            ProcSimpleTextNode(
                                node_id=ctmr.resource.id,
                                text=ctmr.resource.note,
                            )
                        )
                    )
                elif type_str == "TAG":
                    self.parent.list_widget.addItem(
                        CustomListItem(
                            ProcSimpleTextNode(
                                node_id=ctmr.resource.id,
                                text=ctmr.resource.name,
                            )
                        )
                    )
                print(f"{type_str} for File created successfully.")
                return text
            else:
                print(f"Error updating {type_str}.")
                print(f"Status Code: {ctmr.status}")
                return None

    def save_edit(self, text, item):
        """API call logic for `edit` submissions"""
        if "Notes" in self.parent.label.text():
            type_str = "NOTE"
            api_call = ctmfiles.update_file_note

        try:
            if type_str == "NOTE":
                _, status, _ = api_call(
                    binary_id=self.parent.binary_id,
                    note_id=item.proc_node.node_id,
                    note=text,
                    public=False,
                    no_links=True,
                    update_mask="note"
                )
        except ApiException as exp:
            logger.debug(traceback.format_exc())
            print(f"Could not update File {type_str}.")
            for error in json.loads(exp.body).get("errors"):
                logger.info(error["reason"])
                print(f"{error['reason']}: {error['message']}")
            return None
        except Exception as exp:
            logger.debug(traceback.format_exc())
            print("Unknown Error occurred")
            print(f"<{exp.__class__}>: {str(exp)}")
            # exit if this call fails so user can retry
            # (this func always returns None anyway)
            return None
        else:
            if status >= 200 and status <= 299:
                print(f"File {type_str} updated successfully.")
                return text
            else:
                print(f"Error updating {type_str}.")
                print(f"Status Code: {status}")
                return None
