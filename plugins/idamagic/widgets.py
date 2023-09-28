"""Custom widgets"""
from PyQt5 import QtWidgets, Qt, QtGui, QtCore
import cythereal_magic
from cythereal_magic.rest import ApiException
from .helpers import create_proc_name
import json
import traceback
import logging
import ida_kernwin

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
        self.populate_widget()

    def populate_widget(self):
        """Create widget and handle behavior"""
        self.popup = (FileTextPopup(fill_text=None, parent=self),)
        self.list_widget_tab_bar.addTab("NOTES")
        self.list_widget_tab_bar.addTab("TAGS")
        self.list_widget_tab_bar.addTab("MATCHES")

    def disable_tab_bar(self):
        self.list_widget_tab_bar.setTabEnabled(0, False)
        self.list_widget_tab_bar.setTabEnabled(1, False)
        self.list_widget_tab_bar.setTabEnabled(2, False)

    def enable_tab_bar(self):
        self.list_widget_tab_bar.setTabEnabled(0, True)
        self.list_widget_tab_bar.setTabEnabled(1, True)
        self.list_widget_tab_bar.setTabEnabled(2, True)

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
        type_str = self.label.text()
        try:
            if "Notes" in type_str:
                api_call = ctmfiles.delete_file_note
                response = api_call(
                    binary_id=self.binary_id,
                    note_id=item.proc_node.node_id,
                    force=True,
                    no_links=True,
                    async_req=True,
                )
            elif "Tags" in type_str:
                api_call = ctmfiles.remove_file_tag
                response = api_call(
                    binary_id=self.binary_id,
                    tag_id=item.proc_node.node_id,
                    force=True,
                    no_links=True,
                    async_req=True,
                )
            response = response.get()
        except ApiException as exp:
            logger.debug(traceback.format_exc())
            print(f"Could not delete file {type_str}.")
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
            if 200 <= response[1] <= 299:
                print(f"File {type_str} removed successfully.")
            else:
                print(f"Error deleting {type_str}.")
                print(f"Status Code: {response[1]}")
                # print(f"Error message: {response.errors}")
                return None

        index = self.list_widget.row(item)
        self.list_widget.takeItem(index)


class CenterDisplayWidget(QtWidgets.QWidget):
    """Custom display widget for selected items"""

    def __init__(self):
        super().__init__()
        self.tabs_widget: QtWidgets.QTabWidget
        self.init_ui()

    def init_ui(self):
        """Create widget and handle behavior"""
        self.tabs_widget = QtWidgets.QTabWidget(self)
        self.tabs_widget.setTabsClosable(True)
        self.tabs_widget.setObjectName("tabs_widget")
        self.tab_bar = self.tabs_widget.tabBar()

        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(self.tabs_widget)
        self.create_tab("Default tab")

        self.tabs_widget.tabCloseRequested.connect(self.close_tab)

    def close_tab(self, index):
        """Close one of self.tabs_widget' tabs"""
        self.tabs_widget.removeTab(index)

        if self.count_tabs() == 0:
            self.create_tab("Default tab")

    def create_tab(self, tab_type, sha1=None, image_base=None, item=None):
        """Add a tab to self.tabs_widget"""
        if tab_type == "Original procedure":
            tab = QtWidgets.QWidget()
            layout = QtWidgets.QVBoxLayout(tab)
            proc_tree = ProcTreeWidget()

            self.populate(item, proc_tree, image_base, sha1)
            layout.addWidget(proc_tree)
            tab.setLayout(layout)

            self.tabs_widget.addTab(tab, item.start_ea)
            self.remove_default_tab()
            self.add_tab_visuals(tab_type)

        elif tab_type == "Derived procedure":
            # create derived procedure tab
            self.remove_default_tab()
            self.add_tab_visuals(tab_type)
        elif tab_type == "Derived file":
            # create derived file tab
            self.remove_default_tab()
            self.add_tab_visuals(tab_type)
        elif tab_type == "Default tab":
            tab = QtWidgets.QWidget()
            layout = QtWidgets.QVBoxLayout(tab)

            text_box = QtWidgets.QTextEdit()
            text_box.setReadOnly(True)
            text_box.setText(
                "Double click on a procedure address from the "
                + "table below to display note, tag, and "
                + "similarity information."
            )
            layout.addWidget(text_box)
            tab.setLayout(layout)
            self.tabs_widget.addTab(tab, "Get started")

    def remove_default_tab(self):
        """Removes the default tab if present"""
        if self.tabs_widget.tabText(0) == "Get started":
            self.close_tab(0)

    def populate(self, proc, proc_tree, image_base, sha1):
        """Create a ProcRootNode to display in the center widget"""
        start_ea = ida_kernwin.str2ea(proc.start_ea) + int(image_base, 16)

        from .IDA_interface._procTree import (
            ProcFilesNode,
            ProcListItem,
            ProcNotesNode,
            ProcRootNode,
            ProcSimilarityNode,
            ProcTagsNode,
        )

        # create root node
        procrootnode = ProcRootNode(
            proc.start_ea, create_proc_name(proc), start_ea
        )
        # populate with sub root nodes
        if proc.strings:
            procrootnode.appendRow(ProcListItem("Strings", proc.strings))

        if proc.api_calls:
            procrootnode.appendRow(ProcListItem("API Calls", proc.api_calls))

        procrootnode.appendRows(
            [
                ProcNotesNode(proc.hard_hash, sha1, proc.start_ea),
                ProcTagsNode(proc.hard_hash, sha1, proc.start_ea),
                ProcFilesNode(proc.hard_hash, proc.start_ea),
                ProcSimilarityNode(proc.hard_hash, sha1, proc.start_ea),
            ]
        )
        proc_tree.model().appendRow(procrootnode)

    def count_tabs(self):
        """Return a count of current tabs."""
        return self.tab_bar.count()

    def add_tab_visuals(self, tab_type: str):
        """Update the text color (and maybe icon) of a tab.
        """
        if tab_type == "Original procedure":
            self.tab_bar.setTabTextColor(
                self.count_tabs() - 1, QtGui.QColor("green")
            )
        elif tab_type == "Derived procedure":
            self.tab_bar.setTabTextColor(
                self.count_tabs() - 1, QtGui.QColor("blue")
            )
        elif tab_type == "Derived file":
            self.tab_bar.setTabTextColor(
                self.count_tabs() - 1, QtGui.QColor("red")
            )


class ProcTreeWidget(QtWidgets.QTreeView):
    """Custom widget to display procedure tree"""

    def __init__(self):
        super().__init__()
        self.setHeaderHidden(True)
        self.setModel(Qt.QStandardItemModel())


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
        item_type=None,
    ):
        """Init method"""
        super().__init__(fill_text, parent)
        self.parent = parent
        self.listing_item = listing_item
        self.binary_id = binary_id
        self.rva = rva
        self.item_type = item_type

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
                self.listing_item.text = text
                self.listing_item.note = text
        else:
            text = self.save_create(text)

        if text is not None:
            self.hide()

    def save_create(self, text):
        """API call logic for `create` submissions"""
        try:
            if self.item_type == "Notes":
                api_call = ctmfiles.create_procedure_genomics_note
                response = api_call(
                    binary_id=self.binary_id,
                    rva=self.rva,
                    note=text,
                    public=False,
                    no_links=True,
                    async_req=True,
                )
            elif self.item_type == "Tags":
                api_call = ctmfiles.create_procedure_genomics_tag
                response = api_call(
                    binary_id=self.binary_id,
                    rva=self.rva,
                    name=text,
                    no_links=True,
                    async_req=True,
                )
            response = response.get()
        except ApiException as exp:
            logger.debug(traceback.format_exc())
            print(
                f"Could not update {self.item_type} from selected procedure."
            )
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
            if 200 <= response.status <= 299:
                from .IDA_interface._procTree import ProcSimpleTextNode

                print(
                    f"{self.item_type} from selected procedure created successfully."
                )
                if self.item_type == "Notes":
                    self.listing_item.appendRow(
                        ProcSimpleTextNode(
                            hard_hash=self.listing_item.hard_hash,
                            node_id=response.resource.id,
                            text=response.resource.note,
                            binary_id=self.binary_id,
                            rva=self.rva,
                        )
                    )
                elif self.item_type == "Tags":
                    self.listing_item.appendRow(
                        ProcSimpleTextNode(
                            hard_hash=self.listing_item.hard_hash,
                            node_id=response.resource.id,
                            text=response.resource.name,
                            binary_id=self.binary_id,
                            rva=self.rva,
                        )
                    )
                return text
            else:
                print(f"Error updating {self.item_type}.")
                print(f"Status Code: {response.status}")
                print(f"Error message: {response.errors}")
                return None

    def save_edit(self, text, item):
        """API call logic for `edit` submissions"""
        try:
            if self.item_type == "Notes":
                api_call = ctmfiles.update_procedure_genomics_note
                response = api_call(
                    binary_id=self.binary_id,
                    rva=self.rva,
                    note_id=item.node_id,
                    note=text,
                    public=False,
                    no_links=True,
                    update_mask="note",
                    async_req=True,
                )
                response = response.get()
            elif self.item_type == "Proc Name" == "PROCEDURE NAME":
                api_call = print(
                    "API call not implemented for procedure name EDIT, faux call made instead."
                )
                response = api_call()
        except ApiException as exp:
            logger.debug(traceback.format_exc())
            print(
                f"Could not update {self.item_type} from selected procedure."
            )
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
            if self.item_type == "PROCEDURE NAME":
                print(
                    "Endpoints for procedure name functionality not implemented."
                )
                return None
            if 200 <= response.status <= 299:
                print(
                    f"{self.item_type} from selected procedure updated successfully."
                )
                return text
            else:
                print(f"Error updating {self.item_type}.")
                print(f"Status Code: {response.status}")
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
        parent_label = self.parent.label.text()
        try:
            if "Notes" in parent_label:
                api_call = ctmfiles.create_file_note
                response = api_call(
                    binary_id=self.parent.binary_id,
                    note=text,
                    public=False,
                    no_links=True,
                    async_req=True,
                )
            elif "Tags" in parent_label:
                api_call = ctmfiles.create_file_tag
                response = api_call(
                    binary_id=self.parent.binary_id,
                    name=text,
                    no_links=True,
                    async_req=True,
                )
            response = response.get()
        except ApiException as exp:
            logger.debug(traceback.format_exc())
            print(f"Could not create {parent_label} for File.")
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
            if 200 <= response.status <= 299:
                from .IDA_interface._procTree import ProcSimpleTextNode

                if "Notes" in parent_label:
                    self.parent.list_widget.addItem(
                        CustomListItem(
                            ProcSimpleTextNode(
                                node_id=response.resource.id,
                                text=response.resource.note,
                            )
                        )
                    )
                elif "Tags" in parent_label:
                    self.parent.list_widget.addItem(
                        CustomListItem(
                            ProcSimpleTextNode(
                                node_id=response.resource.id,
                                text=response.resource.name,
                            )
                        )
                    )
                print(f"{parent_label} for File created successfully.")
                return text
            else:
                print(f"Error updating {parent_label}.")
                print(f"Status Code: {response.status}")
                return None

    def save_edit(self, text, item):
        """API call logic for `edit` submissions"""
        parent_label = self.parent.label.text()
        try:
            if "Notes" in self.parent.label.text():
                api_call = ctmfiles.update_file_note
                response = api_call(
                    binary_id=self.parent.binary_id,
                    note_id=item.proc_node.node_id,
                    note=text,
                    public=False,
                    no_links=True,
                    update_mask="note",
                    async_req=True,
                )
                response = response.get()
        except ApiException as exp:
            logger.debug(traceback.format_exc())
            print(f"Could not update File {parent_label}.")
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
            if 200 <= response[1] <= 299:
                print(f"File {parent_label} updated successfully.")
                return text
            else:
                print(f"Error updating {parent_label}.")
                print(f"Status Code: {response[1]}")
                return None


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
