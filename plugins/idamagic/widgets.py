"""Custom widgets"""
from PyQt5 import QtWidgets, Qt, QtGui, QtCore
from PyQt5.QtWidgets import QTableWidgetItem
import cythereal_magic
from cythereal_magic.rest import ApiException
from .helpers import (
    create_proc_name,
    process_api_exception,
    process_regular_exception,
)
import json
import traceback
import logging
import ida_kernwin


logger = logging.getLogger(__name__)

magic_api_client = cythereal_magic.ApiClient()
magic_api_client.client_side_validation = False
ctmfiles = cythereal_magic.FilesApi(magic_api_client)
ctmprocs = cythereal_magic.ProceduresApi(magic_api_client)


class BaseListWidget(QtWidgets.QWidget):
    """Base widget for lists"""

    def __init__(self, list_items, parent=None, binary_id=None, popup=None):
        super().__init__(parent)

        self.list_items = list_items
        self.list_widget_tab_bar = QtWidgets.QTabBar()
        self.list_widget = QtWidgets.QListWidget()
        self.binary_id = binary_id
        self.popup = popup
        self.name = None
        self.pagination_selector = PaginationSelector(self)

        # create CRUD buttons
        self.create_button = QtWidgets.QPushButton("Create")
        self.edit_button = QtWidgets.QPushButton("Edit")
        self.delete_button = QtWidgets.QPushButton("Delete")

        self.init_ui()

    def init_ui(self):
        "Create widget and handle behavior"
        self.create_button.setEnabled(False)
        self.edit_button.setEnabled(False)
        self.delete_button.setEnabled(False)
        self.create_button.clicked.connect(self.on_create_click)
        self.edit_button.clicked.connect(self.on_edit_click)
        self.delete_button.clicked.connect(self.on_delete_click)

        # create button row for create/edit/delete buttons
        self.button_row = QtWidgets.QHBoxLayout()
        self.button_row.addWidget(self.create_button)
        self.button_row.addWidget(self.edit_button)
        self.button_row.addWidget(self.delete_button)

        # create layout and add sub-widgets
        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(self.list_widget_tab_bar)
        layout.addWidget(self.list_widget)
        layout.addWidget(self.pagination_selector)
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

    def __init__(self, list_items, binary_id=None, widget_parent=None):
        self.popup = None
        super().__init__(
            list_items=list_items,
            parent=widget_parent,
            binary_id=binary_id,
            popup=self.popup,
        )
        self.widget_parent = widget_parent
        self.populate_widget()

    def populate_widget(self):
        """Create widget and handle behavior"""
        self.popup = FileTextPopup(fill_text=None, parent=self)
        self.list_widget_tab_bar.addTab("NOTES")
        self.list_widget_tab_bar.addTab("TAGS")
        self.list_widget_tab_bar.addTab("MATCHES")
        self.disable_tab_bar()
        self.list_widget_tab_bar.currentChanged.connect(self.tab_changed)
        self.pagination_selector.first_button.clicked.connect(self.first_page)
        self.pagination_selector.back_button.clicked.connect(
            self.previous_page
        )
        self.pagination_selector.next_button.clicked.connect(self.next_page)

    def first_page(self):
        """Navigate to the first page."""
        if self.pagination_selector.current_page > 1:
            self.pagination_selector.update_page_number(1)
            self.widget_parent.make_list_api_call(
                "Matches", self.pagination_selector.current_page
            )
            self.pagination_selector.update_next_button()

    def previous_page(self):
        """Navigate to the previous page."""
        if self.pagination_selector.current_page > 1:
            self.pagination_selector.update_page_number(
                self.pagination_selector.current_page - 1
            )
            self.widget_parent.make_list_api_call(
                "Matches", self.pagination_selector.current_page
            )
            self.pagination_selector.update_next_button()

    def next_page(self):
        """Navigate to the next page."""
        self.pagination_selector.update_page_number(
            self.pagination_selector.current_page + 1
        )
        self.widget_parent.make_list_api_call(
            "Matches", self.pagination_selector.current_page
        )
        self.pagination_selector.update_next_button()

    def tab_changed(self, index):
        """Tab change behavior

        Index here is used to access the tab position.
        [<NoteTab>, <TagsTab>, <MatchesTab>]
        """
        self.edit_button.setEnabled(False)
        self.delete_button.setEnabled(False)
        if index == 0:
            self.widget_parent.make_list_api_call("Notes")
            self.create_button.setEnabled(True)
            self.pagination_selector.hide()
        elif index == 1:
            self.widget_parent.make_list_api_call("Tags")
            self.create_button.setEnabled(True)
            self.pagination_selector.hide()
        elif index == 2:
            self.widget_parent.make_list_api_call(
                "Matches", self.pagination_selector.current_page
            )
            self.create_button.setEnabled(False)
            self.pagination_selector.show()

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

        # Check if Notes (0) or  Tags (1) tab is visible.
        if selected_items and self.list_widget_tab_bar.currentIndex() == 0:
            edit.setEnabled(True)
            delete.setEnabled(True)
        elif selected_items and self.list_widget_tab_bar.currentIndex() == 1:
            delete.setEnabled(True)

    def refresh_list_data(self, list_items):
        """Clear and repopulate list model"""

        # update list items and type
        self.list_items = list_items

        # clear items
        self.list_widget.clear()

        # add new items
        for item in self.list_items:
            self.list_widget.addItem(CustomListItem(item))

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
        note_text = text.split("\n")[0]
        self.show_popup(text=note_text)

    def on_create_click(self):
        """Handle edit pushbutton click"""
        self.show_popup(text=None)

    def on_delete_click(self):
        """Handle delete pushbutton click"""
        confirmation_popup = DeleteConfirmationPopup(self)
        confirmation = confirmation_popup.exec_()
        if confirmation == QtWidgets.QMessageBox.Ok:
            item = self.list_widget.currentItem()
            if self.list_widget_tab_bar.currentIndex() == 0:
                type_str = "Notes"
            elif self.list_widget_tab_bar.currentIndex() == 1:
                type_str = "Tags"
            try:
                if "Notes" in type_str:
                    api_call = ctmfiles.delete_file_note
                    response = api_call(
                        binary_id=self.widget_parent.main_interface.hashes[
                            "ida_md5"
                        ],
                        note_id=item.proc_node.node_id,
                        force=True,
                        no_links=True,
                        async_req=True,
                    )
                elif "Tags" in type_str:
                    api_call = ctmfiles.remove_file_tag
                    response = api_call(
                        binary_id=self.widget_parent.main_interface.hashes[
                            "ida_md5"
                        ],
                        tag_id=item.proc_node.node_id,
                        force=True,
                        no_links=True,
                        async_req=True,
                    )
                response = response.get()
            except ApiException as exc:
                info_msgs = ["Could not delete file " + type_str + "."]
                process_api_exception(exc, False, info_msgs)
                return None
            except Exception as exc:
                process_regular_exception(exc, False, None)
                return None

            index = self.list_widget.row(item)
            self.list_widget.takeItem(index)

            self.create_button.setEnabled(False)
            self.edit_button.setEnabled(False)
            self.delete_button.setEnabled(False)
        else:
            return None


class FileSimpleTextNode(Qt.QStandardItem):
    """Node which contains only simple text information"""

    def __init__(self, node_id="", text="", binary_id="", uploaded=False):
        super().__init__()
        self.setEditable(False)
        self.setText(text)
        self.text = text
        self.node_id = node_id
        self.binary_id = binary_id
        self.uploaded = uploaded


class PaginationSelector(QtWidgets.QWidget):
    """Widget for page selection."""

    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.current_page = 1
        self.page_item_total = None
        self.initUI()

    def initUI(self):
        """Populate ui."""
        layout = QtWidgets.QHBoxLayout()
        layout.addStretch()

        self.first_button = QtWidgets.QPushButton("<<")
        self.first_button.setEnabled(False)
        self.back_button = QtWidgets.QPushButton("<")
        self.back_button.setEnabled(False)
        self.page_selector = QtWidgets.QLabel(f"{self.current_page}")
        self.next_button = QtWidgets.QPushButton(">")
        self.next_button.setEnabled(False)

        layout.addWidget(self.first_button)
        layout.addWidget(self.back_button)
        layout.addWidget(self.page_selector)
        layout.addWidget(self.next_button)

        self.setLayout(layout)

    def update_page_number(self, number):
        """Update page number."""
        self.current_page = number
        self.page_selector.setText(f"{self.current_page}")

        if self.current_page == 1:
            self.first_button.setEnabled(False)
            self.back_button.setEnabled(False)
        else:
            self.first_button.setEnabled(True)
            self.back_button.setEnabled(True)

    def update_next_button(self):
        """Enable/disable the next button based on item count on page."""
        if self.page_item_total <= 1 or not self.page_item_total:
            self.next_button.setEnabled(False)
        else:
            self.next_button.setEnabled(True)


class ProcTableItem(Qt.QStandardItem):
    """Generic form of items on the procs table.

    Contains default features for all table items based on QStandardItem class.
    """

    def __init__(self):
        super().__init__()
        self.setEditable(False)


class ProcRootNode(ProcTableItem):
    """Node representing the root of a single procedure

    Has information related to its start_ea for jumping to the procedure in IDA's view.
    """

    def __init__(
        self,
        node_name,
        full_name,
        start_ea,
        tree_type=None,
        binary_id=None,
        rva=None,
        table_row=None,
    ):
        super().__init__()
        self.node_name = node_name
        self.start_ea = start_ea
        self.full_name = full_name
        self.tree_type = tree_type
        self.binary_id = binary_id
        self.rva = rva
        self.table_row = table_row
        if self.full_name is not None:
            self.setText(full_name)
        else:
            self.setText(node_name)


class ProcSimpleTextNode(ProcTableItem):
    """Node which contains only simple text information"""

    def __init__(
        self, hard_hash="", node_id="", text="", binary_id="", rva=""
    ):
        super().__init__()
        self.setText(text)
        self.text = text
        self.node_id = node_id
        self.hard_hash = hard_hash
        self.binary_id = binary_id
        self.rva = rva


class ProcHeaderItem(ProcSimpleTextNode):
    """Node representing fields of produre calls which take form of str:str

    For example, dictionary key values will be printed as "key: value"
    """

    def __init__(self, key, value):
        super().__init__(text=(f"{key}: {value}"))


class ProcListItem(ProcSimpleTextNode):
    """Node representing fields of produre calls which take form of str:str

    For example, dictionary key values will be printed as "key: value"
    """

    def __init__(self, name, rows):
        super().__init__(name)
        self.setText(name)
        for item in rows:
            self.appendRow(ProcSimpleTextNode(text=item))


class TreeNotesNode(ProcTableItem):
    """Node representing the root of the "notes" category.

    Contains subnodes representing individual notes.
    """

    def __init__(self, hard_hash, binary_id, rva):
        super().__init__()
        self.setText("Notes")
        self.hard_hash = hard_hash
        self.isPopulated = False
        self.binary_id = binary_id
        self.rva = rva
        # empty item to be deleted when populated
        # expand button will not show unless it has at least one child
        self.appendRow(ProcSimpleTextNode())


class TreeTagsNode(ProcTableItem):
    """Node representing the root of the "tags" category.

    Contains subnodes representing individual tags.
    """

    def __init__(self, hard_hash, binary_id, rva):
        super().__init__()
        self.setText("Tags")
        self.hard_hash = hard_hash
        self.isPopulated = False
        self.binary_id = binary_id
        self.rva = rva
        # empty item to be deleted when populated
        # expand button will not show unless it has at least one child
        self.appendRow(ProcSimpleTextNode())


class TreeProcGroupNotesNode(ProcTableItem):
    """Node representing the root of the "notes" category.

    Contains subnodes representing individual notes.
    """

    def __init__(self, hard_hash, binary_id, rva):
        super().__init__()
        self.setText("Procedure Group Notes")
        self.hard_hash = hard_hash
        self.isPopulated = False
        self.binary_id = binary_id
        self.rva = rva
        # empty item to be deleted when populated
        # expand button will not show unless it has at least one child
        self.appendRow(ProcSimpleTextNode())


class TreeProcGroupTagsNode(ProcTableItem):
    """Node representing the root of the "tags" category.

    Contains subnodes representing individual tags.
    """

    def __init__(self, hard_hash, binary_id, rva):
        super().__init__()
        self.setText("Procedure Group Tags")
        self.hard_hash = hard_hash
        self.isPopulated = False
        self.binary_id = binary_id
        self.rva = rva
        # empty item to be deleted when populated
        # expand button will not show unless it has at least one child
        self.appendRow(ProcSimpleTextNode())


class ProcFilesNode(ProcTableItem):
    """Node representing the root of the "files" category.

    Contains subnodes representing individual files.
    """

    def __init__(self, hard_hash, rva):
        super().__init__()
        self.setText("Containing Files")
        self.hard_hash = hard_hash
        self.isPopulated = False
        self.rva = rva
        # empty item to be deleted when populated
        # expand button will not show unless it has at least one child
        self.appendRow(ProcSimpleTextNode())


class ProcSimilarityNode(ProcTableItem):
    """Node representing the root of the "similarity" category.

    Contains subnodes representing similar functions.
    """

    def __init__(self, hard_hash, binary_id, rva):
        super().__init__()
        self.setText("Similarity Locations")
        self.hard_hash = hard_hash
        self.isPopulated = False
        self.binary_id = binary_id
        self.rva = rva
        # empty item to be deleted when populated
        # expand button will not show unless it has at least one child
        self.appendRow(ProcSimpleTextNode())


class BaseCenterTab(QtWidgets.QWidget):
    """Base for all tabs to be used within the CenterDisplayWidget.tab_bar."""

    def __init__(self, center_widget):
        super().__init__()
        self.center_widget = center_widget
        layout = QtWidgets.QVBoxLayout(self)

        self.tab_tree = TabTreeWidget(self.center_widget)
        self.tab_tree.expanded.connect(self.onTreeExpand)
        self.tab_tree.clicked.connect(self.item_selected)

        layout.addWidget(self.tab_tree)
        self.setLayout(layout)

    def item_selected(self, index):
        self.center_widget.create_button.setEnabled(False)
        self.center_widget.edit_button.setEnabled(False)
        self.center_widget.delete_button.setEnabled(False)

        tab_index = self.center_widget.tabs_widget.currentIndex()
        tab_color = self.center_widget.tabs_widget.tabBar().tabTextColor(
            tab_index
        )
        if index.parent().data() is None and tab_color.green() == 128:
            # selecting a procedure of ProcRootNode
            self.center_widget.edit_button.setEnabled(True)
        elif (
            index.data() == "Tags"
            or index.data() == "Notes"
            or index.data() == "Procedure Group Notes"
            or index.data() == "Procedure Group Tags"
        ):
            # selecting the TreeTagsNode or TreeNotesNode
            self.center_widget.create_button.setEnabled(True)
        elif (
            index.parent().data() == "Tags"
            or index.parent().data() == "Procedure Group Tags"
        ):
            # selecting a tag node of ProcSimpleTextNode
            self.center_widget.create_button.setEnabled(True)
            self.center_widget.delete_button.setEnabled(True)
        elif (
            index.parent().data() == "Notes"
            or index.parent().data() == "Procedure Group Notes"
        ):
            # selecting a note node of ProcSimpleTextNode
            self.center_widget.create_button.setEnabled(True)
            self.center_widget.edit_button.setEnabled(True)
            self.center_widget.delete_button.setEnabled(True)

    def onTreeExpand(self, index):
        self.center_widget.create_button.setEnabled(False)
        self.center_widget.edit_button.setEnabled(False)
        self.center_widget.delete_button.setEnabled(False)
        tab_index = self.center_widget.tabs_widget.currentIndex()
        tab = self.center_widget.tabs_widget.widget(tab_index)
        tab_tree = tab.findChildren(TabTreeWidget)[0]
        item = tab_tree.model().itemFromIndex(index)

        item_type = type(item)
        if item_type is ProcFilesNode:
            self.center_widget.populate_proc_files(item)
        elif item_type is TreeNotesNode:
            self.center_widget.populate_proc_notes(item)
        elif item_type is TreeTagsNode:
            self.center_widget.populate_proc_tags(item)
        elif item_type is TreeProcGroupNotesNode:
            self.center_widget.populate_proc_group_notes(item)
        elif item_type is TreeProcGroupTagsNode:
            self.center_widget.populate_proc_group_tags(item)
        elif item_type is ProcSimilarityNode:
            self.center_widget.populate_proc_similarities(item)


class CenterProcTab(BaseCenterTab):
    """
    Tab to be used within the CenterDisplayWidget.tab_bar.
    Created from a procedure located within the file loaded into IDA.
    """

    def __init__(self, center_widget, item, table_row):
        super().__init__(center_widget)
        self.item = item

        self.center_widget.populate_tab_tree(
            item, self.tab_tree, self.center_widget.sha1, table_row
        )
        self.center_widget.tabs_widget.addTab(self, item.start_ea)


class CenterDerivedFileTab(BaseCenterTab):
    """
    Tab to be used within the CenterDisplayWidget.tab_bar.
    Created from a procedure NOT located within the file loaded into IDA.
    """

    def __init__(self, center_widget, item):
        super().__init__(center_widget)

        self.center_widget.populate_tab_tree(
            item, self.tab_tree, "Derived file"
        )
        self.center_widget.tabs_widget.addTab(self, item.binary_id)


class CenterDerivedProcTab(BaseCenterTab):
    """
    Tab to be used within the CenterDisplayWidget.tab_bar.
    Created from a procedure NOT located within the file loaded into IDA.
    """

    def __init__(
            self, center_widget,
            item,
            orig_file_hash,
            orig_proc_rva,
            derived_file_hash,
            derived_proc_rva,
        ):
        super().__init__(center_widget)
        self.orig_file_hash = orig_file_hash
        self.orig_proc_rva = orig_proc_rva
        self.derived_file_hash = derived_file_hash
        self.derived_proc_rva = derived_proc_rva

        self.center_widget.populate_tab_tree(
            item, self.tab_tree, "Derived procedure"
        )
        self.center_widget.tabs_widget.addTab(self, item.rva)


class CenterDisplayWidget(QtWidgets.QWidget):
    """Custom display widget for selected items"""

    def __init__(self, widget_parent):
        super().__init__()
        self.tabs_widget: QtWidgets.QTabWidget
        self.widget_parent = widget_parent
        self.sha1 = self.widget_parent.main_interface.hashes["version_hash"]
        self.popups = []
        self.init_ui()
        self.tab_bar.currentChanged.connect(self.update_tab_color)

    def init_ui(self):
        """Create widget and handle behavior"""
        self.tabs_widget = QtWidgets.QTabWidget(self)
        self.tabs_widget.setTabsClosable(True)
        self.tabs_widget.setObjectName("tabs_widget")
        self.tab_bar = self.tabs_widget.tabBar()
        self.tab_color = None

        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(self.tabs_widget)
        self.create_tab("Default tab")

        self.tabs_widget.tabCloseRequested.connect(self.close_tab)

        self.create_button = QtWidgets.QPushButton("Create")
        self.create_button.setMinimumSize(30, 30)
        self.edit_button = QtWidgets.QPushButton("Edit")
        self.edit_button.setMinimumSize(30, 30)
        self.delete_button = QtWidgets.QPushButton("Delete")
        self.delete_button.setMinimumSize(30, 30)
        self.compare_button = QtWidgets.QPushButton("Compare Procedures")
        self.compare_button.hide()

        # link button to clicked functions and set default 'enabled' to False
        self.create_button.setEnabled(False)
        self.edit_button.setEnabled(False)
        self.delete_button.setEnabled(False)
        self.compare_button.setEnabled(False)
        self.create_button.clicked.connect(self.on_create_click)
        self.edit_button.clicked.connect(self.on_edit_click)
        self.delete_button.clicked.connect(self.on_delete_click)
        self.compare_button.clicked.connect(self.on_compare_click)

        # create button row for create/edit/delete buttons
        self.button_row = QtWidgets.QHBoxLayout()
        self.button_row.addWidget(self.create_button)
        self.button_row.addWidget(self.edit_button)
        self.button_row.addWidget(self.delete_button)
        layout.addLayout(self.button_row)
        layout.addWidget(self.compare_button)

    def update_sha1(self, hash):
        """Update the has for center display widget."""
        self.sha1 = hash

    def update_tab_color(self, index):
        """Update the value stored in self.tab_color to the current tab's."""
        self.create_button.setEnabled(False)
        self.edit_button.setEnabled(False)
        self.delete_button.setEnabled(False)
        self.tab_color = self.tab_bar.tabTextColor(index)

        # enable/disable and hide/show compare button based on tab color
        if self.tab_color.blue() == 255:
            self.compare_button.setEnabled(True)
            self.compare_button.show()
        else:
            self.compare_button.setEnabled(False)
            self.compare_button.hide()

    def close_tab(self, index):
        """Close one of self.tabs_widget' tabs"""
        self.tabs_widget.removeTab(index)

        if self.count_tabs() == 0:
            self.create_tab("Default tab")

    def create_tab(self, tab_type, item=None, table_row=None):
        """Add a tab to self.tabs_widget"""
        if tab_type == "Original procedure":
            tab = CenterProcTab(self, item, table_row)
            self.remove_default_tab()
            if self.tab_bar.count() == 1:
                self.tab_color.setGreen(128)
            self.add_tab_visuals(tab_type)
        elif tab_type == "Derived procedure":
            original_tab = self.tabs_widget.currentWidget()
            original_proc = original_tab.item
            tab = CenterDerivedProcTab(
                self,
                item,
                original_proc.binary_id,
                original_proc.start_ea,
                item.binary_id,
                item.rva,
            )
            self.remove_default_tab()
            self.add_tab_visuals(tab_type)
        elif tab_type == "Derived file":
            tab = CenterDerivedFileTab(self, item)
            self.remove_default_tab()
            self.add_tab_visuals(tab_type)
        elif tab_type == "Default tab":
            tab = QtWidgets.QWidget()
            layout = QtWidgets.QVBoxLayout(tab)

            text_box = QtWidgets.QTextEdit()
            text_box.setReadOnly(True)
            text_box.setText(
                "Double click on a procedure address from the "
                + "table below to display notes, tags, and "
                + "similarity information."
            )
            layout.addWidget(text_box)
            tab.setLayout(layout)
            self.tabs_widget.addTab(tab, "Get started")
        self.tab_bar.setCurrentIndex(self.tab_bar.count() - 1)

    def remove_default_tab(self):
        """Removes the default tab if present"""
        if self.tabs_widget.tabText(0) == "Get started":
            self.close_tab(0)

    def populate_tab_tree(
        self, item, tab_tree, tree_type=None, table_row=None
    ):
        """Create a ProcRootNode to display in the center widget"""

        if tree_type == "Derived file":
            rootnode = ProcRootNode(item.binary_id, None, None, tree_type)

            rootnode.appendRows(
                [
                    TreeNotesNode(None, item.binary_id, item.rva),
                    TreeTagsNode(None, item.binary_id, item.rva),
                ]
            )
        elif tree_type == "Derived procedure":
            rootnode = ProcRootNode(
                item.rva, None, None, tree_type, item.binary_id, item.rva
            )

            rootnode.appendRows(
                [
                    TreeNotesNode(None, item.binary_id, item.rva),
                    TreeTagsNode(None, item.binary_id, item.rva),
                ]
            )
        else:
            # create root node
            rootnode = ProcRootNode(
                item.start_ea,
                create_proc_name(item),
                item.start_ea,
                tree_type="Procedure",
                binary_id=item.binary_id,
                rva=item.start_ea,
                table_row=table_row,
            )
            # populate with sub root nodes
            if item.strings:
                rootnode.appendRow(ProcListItem("Strings", item.strings))

            if item.api_calls:
                rootnode.appendRow(ProcListItem("API Calls", item.api_calls))

            rootnode.appendRows(
                [
                    TreeNotesNode(item.hard_hash, self.sha1, item.start_ea),
                    TreeTagsNode(item.hard_hash, self.sha1, item.start_ea),
                    ProcFilesNode(item.hard_hash, item.start_ea),
                    TreeProcGroupNotesNode(item.hard_hash, None, None),
                    TreeProcGroupTagsNode(item.hard_hash, None, None),
                    ProcSimilarityNode(
                        item.hard_hash, self.sha1, item.start_ea
                    ),
                ]
            )
        tab_tree.model().appendRow(rootnode)

    def populate_proc_files(self, filesRootNode: ProcFilesNode):
        """populates a selected procedure's 'files' node with recieved files

        PARAMETERS
        ----------
        filesRootNode: ProcFilesNode
            Represents the procedure node which is to be populated with files.
        """
        if not filesRootNode.isPopulated:
            returned_vals = self.make_list_api_call(filesRootNode)
            # start adding file information
            for file in returned_vals:
                sha1 = file.sha1

                if file.sha1 != self.sha1:
                    filename = sha1
                    if file.filenames:
                        filename = file.filenames[0]
                else:
                    filename = f"Current file - {sha1}"

                # build a fileNode
                filesRootNode.appendRow(
                    ProcSimpleTextNode(text=filename, binary_id=sha1)
                )

            # remove the empty init child
            filesRootNode.removeRows(0, 1)
            filesRootNode.isPopulated = True

    def populate_proc_notes(self, notesRootNode: TreeNotesNode):
        """populates a selected procedure's 'notes' node with recieved notes

        PARAMETERS
        ----------
        notesRootNode: TreeNotesNode
            Represents the procedure node which is to be populated with notes.
        """
        if not notesRootNode.isPopulated:
            returned_vals = self.make_list_api_call(notesRootNode)

            # start adding note information
            for note in returned_vals:
                notesRootNode.appendRow(
                    ProcSimpleTextNode(
                        hard_hash=notesRootNode.hard_hash,
                        node_id=note.id,
                        text=(
                            f"{note.note}\n"
                            f"    User:{note.username}\n"
                            f"    Create time: {note.create_time}"
                        ),
                        binary_id=notesRootNode.binary_id,
                        rva=notesRootNode.rva,
                    )
                )
            # remove the empty init child
            notesRootNode.removeRows(0, 1)
            notesRootNode.isPopulated = True

    def populate_proc_tags(self, tagsRootNode: TreeTagsNode):
        """populates a selected procedure's 'tags' node with recieved tags

        PARAMETERS
        ---------
        tagsRootNode: TreeTagsNode
            Represents the procedure node which is to be populated with tags.
        """
        if not tagsRootNode.isPopulated:
            returned_vals = self.make_list_api_call(tagsRootNode)

            for tag in returned_vals:
                tagsRootNode.appendRow(
                    ProcSimpleTextNode(
                        hard_hash=tagsRootNode.hard_hash,
                        node_id=tag.id,
                        text=tag.name,
                        binary_id=tagsRootNode.binary_id,
                        rva=tagsRootNode.rva,
                    )
                )

            # remove the empty init child
            tagsRootNode.removeRows(0, 1)
            tagsRootNode.isPopulated = True

    def populate_proc_group_notes(
        self, notes_root_node: TreeProcGroupNotesNode
    ):
        """populates a selected procedure's 'Proc Group Notes' node with received notes

        PARAMETERS
        ----------
        notes_root_node: TreeProcGroupNotesNode
            Represents the procedure node which is to be populated with notes.
        """
        if not notes_root_node.isPopulated:
            returned_vals = self.make_list_api_call(notes_root_node)

            # start adding note information
            for note in returned_vals:
                notes_root_node.appendRow(
                    ProcSimpleTextNode(
                        hard_hash=notes_root_node.hard_hash,
                        node_id=note["id"],
                        text=(
                            f"{note['note']}\n"
                            f"    User:{note['username']}\n"
                            f"    Create time: {note['create_time']}"
                        ),
                        binary_id=None,
                        rva=None,
                    )
                )
            # remove the empty init child
            notes_root_node.removeRows(0, 1)
            notes_root_node.isPopulated = True

    def populate_proc_group_tags(self, tags_root_node: TreeProcGroupTagsNode):
        """populates a selected procedure's 'Proc Group Tags' node with received tags

        PARAMETERS
        ---------
        tags_root_node: TreeProcGroupTagsNode
            Represents the subroot node which is to be populated with tags.
        """
        if not tags_root_node.isPopulated:
            returned_vals = self.make_list_api_call(tags_root_node)

            for tag in returned_vals:
                tags_root_node.appendRow(
                    ProcSimpleTextNode(
                        hard_hash=tags_root_node.hard_hash,
                        node_id=tag["id"],
                        text=tag["name"],
                        binary_id=None,
                        rva=None,
                    )
                )

            # remove the empty init child
            tags_root_node.removeRows(0, 1)
            tags_root_node.isPopulated = True

    def populate_proc_similarities(
        self, similarityRootNode: ProcSimilarityNode
    ):
        """Populates a selected procedure's "similarity" node with similar
           procedures.

        PARAMETERS
        ---------
        nameRootNode: ProcSimilarityNode
            Represents the procedure node which is to be populated with
            similarites.
        """
        if not similarityRootNode.isPopulated:
            returned_vals = self.make_list_api_call(similarityRootNode)
            proc_dict = {}
            for proc in returned_vals:
                bin_id = proc.binary_id
                ea = proc.start_ea
                blocks = proc.block_count
                code = proc.code_count
                if bin_id in proc_dict:
                    proc_dict[bin_id].append(f"{ea}, Blocks:{blocks}, Code:{code}")
                else:
                    proc_dict[bin_id] = [f"{ea}, Blocks:{blocks}, Code:{code}"]

            for bin_id, eas in proc_dict.items():
                if (
                    self.sha1 == bin_id
                ):
                    similarityRootNode.appendRow(
                        ProcSimpleTextNode(
                            hard_hash=similarityRootNode.hard_hash,
                            text=f"Current File - {bin_id}",
                            binary_id=bin_id,
                            rva=None,
                        )
                    )
                else:
                    similarityRootNode.appendRow(
                        ProcSimpleTextNode(
                            hard_hash=similarityRootNode.hard_hash,
                            text=f"{bin_id}",
                            binary_id=bin_id,
                            rva=None,
                        )
                    )
                for ea in eas:
                    rva = ea.split(",", 1)
                    rva = rva[0]
                    similarityRootNode.appendRow(
                    ProcSimpleTextNode(
                        hard_hash=similarityRootNode.hard_hash,
                        text=f"       {ea}",
                        binary_id=bin_id,
                        rva=rva,
                    )
                )
            # remove the empty init child
            similarityRootNode.removeRows(0, 1)
            similarityRootNode.isPopulated = True

    def make_list_api_call(self, node):
        """Make api call and handle exceptions"""
        plain_calls = ["Notes", "Tags", "Derived proc notes", "Derived proc tags"]

        node_type = type(node)
        api_call = None
        type_str = None
        read_mask = None

        if node_type is ProcFilesNode:
            api_call = ctmprocs.list_procedure_files
            type_str = "Files"
            read_mask = "sha1,sha256,filename"
        elif node_type is TreeProcGroupNotesNode:
            api_call = ctmprocs.list_procedure_notes
            type_str = "Procedure Group Notes"
            expand_mask = "notes"
        elif node_type is TreeProcGroupTagsNode:
            api_call = ctmprocs.list_procedure_tags
            type_str = "Procedure Group Tags"
            expand_mask = "tags"
        elif node_type is TreeNotesNode and self.tab_color.red() == 255:
            api_call = ctmfiles.list_file_notes
            type_str = "File notes"
        elif node_type is TreeNotesNode and self.tab_color.blue() == 255:
            api_call = ctmfiles.list_procedure_genomics_notes
            type_str = "Derived proc notes"
        elif node_type is TreeNotesNode and self.tab_color.green() == 128:
            api_call = ctmfiles.list_procedure_genomics_notes
            type_str = "Notes"
        elif node_type is TreeTagsNode and self.tab_color.red() == 255:
            api_call = ctmfiles.list_file_tags
            type_str = "File tags"
            expand_mask = "tags"
        elif node_type is TreeTagsNode and self.tab_color.blue() == 255:
            api_call = ctmfiles.list_procedure_genomics_tags
            type_str = "Derived proc tags"
        elif node_type is TreeTagsNode and self.tab_color.green() == 128:
            api_call = ctmfiles.list_procedure_genomics_tags
            type_str = "Tags"
        elif node_type is ProcSimilarityNode:
            api_call = ctmfiles.list_procedure_similarities
            type_str = "Similarities"
            read_mask="block_count,code_count,binary_id,start_ea"

        try:
            if type_str == "Files":
                response = api_call(
                    node.hard_hash,
                    read_mask=read_mask,
                    expand_mask=type_str.lower(),
                    no_links=True,
                    async_req=True,
                )
            elif (
                type_str == "Procedure Group Notes"
                or type_str == "Procedure Group Tags"
            ):
                response = api_call(
                    proc_hash=node.hard_hash,
                    expand_mask=expand_mask,
                    no_links=True,
                    async_req=True,
                )
            elif type_str == "File notes":
                response = api_call(
                    binary_id=node.binary_id,
                    no_links=True,
                    async_req=True,
                )
            elif type_str == "File tags":
                response = api_call(
                    binary_id=node.binary_id,
                    expand_mask=expand_mask,
                    no_links=True,
                    async_req=True,
                )
            elif type_str in plain_calls:
                response = api_call(
                    binary_id=node.binary_id,
                    rva=node.rva,
                    no_links=True,
                    async_req=True,
                )
            elif type_str == "Similarities":
                response = api_call(
                    binary_id=node.binary_id,
                    rva=node.rva,
                    no_links=True,
                    async_req=True,
                    read_mask=read_mask,
                )
            response = response.get()
        except ApiException as exc:
            process_api_exception(exc, False, None)
            return None
        except Exception as exc:
            process_regular_exception(exc, False, None)
            return None
        else:
            if (
                type_str == "Procedure Group Notes"
                or type_str == "Procedure Group Tags"
            ):
                return response["resources"]
        return response.resources

    def show_popup(
        self,
        text,
        parent,
        listing_item=None,
        binary_id=None,
        rva=None,
        item_type=None,
        table_row=None,
    ):
        """Handle showing edit popup"""
        self.popup = ProcTextPopup(
            listing_item=listing_item,
            fill_text=text,
            parent=parent,
            binary_id=binary_id,
            rva=rva,
            item_type=item_type,
            table_row=table_row,
            proc_table=self.widget_parent.proc_table,
        )
        self.popup.show()

    def on_edit_click(self):
        """Handle edit pushbutton click"""
        tab_index = self.tabs_widget.currentIndex()
        tab = self.tabs_widget.widget(tab_index)
        proc_tree = tab.findChildren(TabTreeWidget)[0]
        index = proc_tree.selectedIndexes()[0]
        item = index.model().itemFromIndex(index)
        text = item.text

        if isinstance(item, ProcRootNode):
            if self.tab_color.red() == 255:
                item_type = "Derived file name"
            else:
                item_type = "Proc Name"
            if item.full_name is not None:
                # for a procedure with a full_name (node_name, padding, and
                # procedure name), get the procedure_name by skipping the
                # node name and added padding.
                text = item.full_name[(len(item.node_name) + 3) :]
            else:
                text = None
            self.show_popup(
                listing_item=item,
                text=text,
                parent=item.parent(),
                binary_id=self.sha1,
                rva=None,
                item_type=item_type,
            )
        elif isinstance(item.parent(), TreeNotesNode):
            if self.tab_color.red() == 255:
                item_type = "Derived file note"
            else:
                item_type = "Notes"
            text = text.split("\n")[0]
            self.show_popup(
                listing_item=item,
                text=text,
                parent=item.parent().parent().parent(),
                binary_id=item.parent().binary_id,
                rva=item.parent().rva,
                item_type=item_type,
            )
        elif isinstance(item.parent(), TreeProcGroupNotesNode):
            item_type = "Procedure Group Notes"
            self.show_popup(
                listing_item=item,
                text=text.split("\n")[0],
                parent=item.parent().parent().parent(),
                item_type=item_type,
            )

    def on_create_click(self):
        """Handle edit pushbutton click"""
        tab_index = self.tabs_widget.currentIndex()
        tab = self.tabs_widget.widget(tab_index)
        proc_tree = tab.findChildren(TabTreeWidget)[0]
        index = proc_tree.selectedIndexes()[0]
        item = index.model().itemFromIndex(index)

        if isinstance(item, TreeNotesNode):
            if self.tab_color.red() == 255:
                item_type = "Derived file note"
            else:
                item_type = "Notes"
            self.show_popup(
                listing_item=item,
                text=None,
                parent=item.parent().parent(),
                binary_id=item.binary_id,
                rva=item.rva,
                item_type=item_type,
            )
        elif isinstance(item, TreeTagsNode):
            if self.tab_color.red() == 255:
                item_type = "Derived file tag"
            else:
                item_type = "Tags"
            self.show_popup(
                listing_item=item,
                text=None,
                parent=item.parent().parent(),
                binary_id=item.binary_id,
                rva=item.rva,
                item_type=item_type,
            )
        elif isinstance(item, TreeProcGroupNotesNode):
            item_type = "Procedure Group Notes"
            self.show_popup(
                listing_item=item,
                text=None,
                parent=item.parent().parent(),
                item_type=item_type,
            )
        elif isinstance(item, TreeProcGroupTagsNode):
            item_type = "Procedure Group Tags"
            self.show_popup(
                listing_item=item,
                text=None,
                parent=item.parent().parent(),
                item_type=item_type,
            )
        elif isinstance(item.parent(), TreeNotesNode):
            if self.tab_color.red() == 255:
                item_type = "Derived file note"
            else:
                item_type = "Notes"
            self.show_popup(
                listing_item=item.parent(),
                text=None,
                parent=item.parent().parent().parent(),
                binary_id=item.parent().binary_id,
                rva=item.parent().rva,
                item_type=item_type,
            )
        elif isinstance(item.parent(), TreeTagsNode):
            if self.tab_color.red() == 255:
                item_type = "Derived file tag"
            else:
                item_type = "Tags"
            self.show_popup(
                listing_item=item.parent(),
                text=None,
                parent=item.parent().parent().parent(),
                binary_id=item.parent().binary_id,
                rva=item.parent().rva,
                item_type=item_type,
            )
        elif isinstance(item.parent(), TreeProcGroupNotesNode):
            item_type = "Procedure Group Notes"
            self.show_popup(
                listing_item=item.parent(),
                text=None,
                parent=item.parent().parent().parent(),
                item_type=item_type,
            )
        elif isinstance(item.parent(), TreeProcGroupTagsNode):
            item_type = "Procedure Group Tags"
            self.show_popup(
                listing_item=item.parent(),
                text=None,
                parent=item.parent().parent().parent(),
                item_type=item_type,
            )

    def on_delete_click(self):
        """Handle delete pushbutton click"""
        tab_index = self.tabs_widget.currentIndex()
        tab = self.tabs_widget.widget(tab_index)
        proc_tree = tab.findChildren(TabTreeWidget)[0]
        index = proc_tree.selectedIndexes()[0]
        item = index.model().itemFromIndex(index)
        type_str = index.parent().data()

        confirmation_popup = DeleteConfirmationPopup(self)
        confirmation = confirmation_popup.exec_()
        if confirmation == QtWidgets.QMessageBox.Ok:
            try:
                if type_str == "Notes":
                    if self.tab_color.red() == 255:
                        api_call = ctmfiles.delete_file_note
                        response = api_call(
                            binary_id=item.binary_id,
                            note_id=item.node_id,
                            force=True,
                            no_links=True,
                            async_req=True,
                        )
                    else:
                        api_call = ctmfiles.delete_procedure_genomics_note
                        response = api_call(
                            binary_id=item.binary_id,
                            note_id=item.node_id,
                            rva=item.rva,
                            force=True,
                            no_links=True,
                            async_req=True,
                        )
                if type_str == "Tags":
                    if self.tab_color.red() == 255:
                        api_call = ctmfiles.remove_file_tag
                        response = api_call(
                            binary_id=item.binary_id,
                            tag_id=item.node_id,
                            force=True,
                            no_links=True,
                            async_req=True,
                        )
                    else:
                        api_call = ctmfiles.delete_procedure_genomics_tag_by_id
                        response = api_call(
                            binary_id=item.binary_id,
                            tag_id=item.node_id,
                            rva=item.rva,
                            force=True,
                            no_links=True,
                            async_req=True,
                        )
                if type_str == "Procedure Group Notes":
                    api_call = ctmprocs.delete_procedure_note
                    response = api_call(
                        proc_hash=item.hard_hash,
                        note_id=item.node_id,
                        force=True,
                        no_links=True,
                        async_req=True,
                    )
                elif type_str == "Procedure Group Tags":
                    api_call = ctmprocs.delete_procedure_tag
                    response = api_call(
                        proc_hash=item.hard_hash,
                        tag_id=item.node_id,
                        force=True,
                        no_links=True,
                        async_req=True,
                    )
                response = response.get()
            except ApiException as exc:
                info_msgs = [
                    "Could not delete "
                    + type_str
                    + " from selected procedure."
                ]
                process_api_exception(exc, False, info_msgs)
                return None
            except Exception as exc:
                process_regular_exception(exc, False, None)
                return None
            else:
                if 200 <= response[1] <= 299:
                    item.parent().removeRow(item.row())
                
                self.create_button.setEnabled(False)
                self.edit_button.setEnabled(False)
                self.delete_button.setEnabled(False)
                self.tabs_widget.currentWidget().tab_tree.clear_selection()
        else:
            return None

    def on_compare_click(self):
        """
        Display a procedure comparison popup.
        Make the API calls to fill the text areas.
        """
        tab_index = self.tabs_widget.currentIndex()
        tab = self.tabs_widget.widget(tab_index)
        orig_file_hash = tab.orig_file_hash
        orig_proc_rva = tab.orig_proc_rva
        derived_file_hash = tab.derived_file_hash
        derived_proc_rva = tab.derived_proc_rva

        try:
            orig_response = ctmfiles.list_file_procedure_genomics(
                binary_id=orig_file_hash,
                rva=orig_proc_rva,
                no_links=True,
                async_req=True,
            )
            orig_response = orig_response.get()
            orig_proc = orig_response.resource

            derived_response = ctmfiles.list_file_procedure_genomics(
                binary_id=derived_file_hash,
                rva=derived_proc_rva,
                no_links=True,
                async_req=True,
            )
            derived_response = derived_response.get()
            derived_proc = derived_response.resource
        except ApiException as exc:
            info_msgs = ["Unable to fetch procedure code."]
            process_api_exception(exc, False, info_msgs)
            return None
        except Exception as exc:
            process_regular_exception(exc, False, None)
            return None
        else:
            popup = ComparePopup(orig_proc, derived_proc)
            popup.finished.connect(lambda: self.popups.remove(popup))
            popup.show()
            self.popups.append(popup)

    def count_tabs(self):
        """Return a count of current tabs."""
        return self.tab_bar.count()

    def add_tab_visuals(self, tab_type: str):
        """Update the text color (and maybe icon) of a tab."""
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


class ProcTableWidget(QtWidgets.QTableWidget):
    """Custom table widget for procedures"""

    def __init__(self, widget_parent):
        super().__init__()
        self.widget_parent = widget_parent
        self.setColumnCount(7)
        self.setHorizontalHeaderLabels(
            [
                "Address",
                "Occurrence #",
                "Blocks",
                "Code Count",
                "Type",
                "Notes",
                "Tags",
            ]
        )
        self.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.setSortingEnabled(True)
        self.verticalHeader().setVisible(False)
        self.itemDoubleClicked.connect(self.on_address_col_double_click)

    def on_address_col_double_click(self, item):
        """Handle proc table row double clicks."""
        self.widget_parent.center_widget.create_tab(
            "Original procedure",
            item=item.data(1),
            table_row=item.row(),
        )
        self.proc_tree_jump_to_hex(item.data(1).start_ea)

    def proc_tree_jump_to_hex(self, start_ea):
        """From item address in table view, jump IDA to that position."""
        start_ea = ida_kernwin.str2ea(start_ea)
        found_ea = ida_kernwin.jumpto(start_ea)
        if not found_ea:
            start_ea = start_ea + self.widget_parent.image_base
            ida_kernwin.jumpto(start_ea)

    def reset_table(self):
        """Reset the table data, replacing the header labels."""
        self.clearContents()
        self.setRowCount(0)

class ProcTableAddressItem(QtWidgets.QTableWidgetItem):
    """
    Custom QTableWidgetItem for procedure address/name.

    This allows proper sorting based on the integer value of the address instead
    of string value.
    """
    def __lt__(self, other):
        def extract_value(item):
            text = item.text()
            start_index = text.find("x") + 1
            end_index = text.find(" ", start_index)
            if end_index == -1:
                end_index = len(text)
            sortable_string = text[start_index:end_index]
            return int(sortable_string, 16)
        return extract_value(self) < extract_value(other)

class ProcTableIntegerItem(QtWidgets.QTableWidgetItem):
    """
    Custom QTableWidgetItem for integers.
    
    This allows proper sorting based on integer value instead of string value.
    """
    def __lt__(self, other):
        return int(self.text()) < int(other.text())

class TabTreeWidget(QtWidgets.QTreeView):
    """
    Custom widget to display procedure tree

    widget_parent can be: CenterDisplayWidget
    """

    def __init__(self, center_widget):
        super().__init__()
        self.setHeaderHidden(True)
        self.setModel(Qt.QStandardItemModel())
        self.center_widget = center_widget
        self.doubleClicked.connect(self.tree_item_double_clicked)

    def tree_item_double_clicked(self, index):
        """
        Handles when an item in the tree is double clicked.

        This is set to only react to double clicks on files and start_ea.
        """
        if index.parent().data() == "Similarity Locations":
            item = self.model().itemFromIndex(index)

            if "x" in index.data():
                self.center_widget.create_tab(
                    "Derived procedure",
                    item=item,
                )
            else:
                self.center_widget.create_tab("Derived file", item=item)

    def clear_selection(self):
        """Clears the trees current selection."""
        self.selectionModel().clearSelection()


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
        try:
            if self.item_type == "Derived file note":
                api_call = ctmfiles.create_file_note
                response = api_call(
                    binary_id=self.binary_id,
                    note=text,
                    public=False,
                    no_links=True,
                    async_req=True,
                )
            elif self.item_type == "Derived file tag":
                api_call = ctmfiles.create_file_tag
                response = api_call(
                    binary_id=self.binary_id,
                    name=text,
                    no_links=True,
                    async_req=True,
                )
            elif self.item_type == "Notes":
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
            elif self.item_type == "Procedure Group Notes":
                api_call = ctmprocs.create_procedure_note
                response = api_call(
                    proc_hash=self.listing_item.hard_hash,
                    note=text,
                    public=False,
                    no_links=True,
                    async_req=True,
                )
            elif self.item_type == "Procedure Group Tags":
                api_call = ctmprocs.add_procedure_tag
                response = api_call(
                    proc_hash=self.listing_item.hard_hash,
                    name=text,
                    no_links=True,
                    async_req=True,
                )
            response = response.get()
        except ApiException as exc:
            info_msgs = ["Could not update " + self.item_type + "."]
            process_api_exception(exc, False, info_msgs)
            return None
        except Exception as exc:
            process_regular_exception(exc, False, None)
            return None
        else:
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
        try:
            if self.item_type == "Derived file note":
                api_call = ctmfiles.update_file_note
                response = api_call(
                    binary_id=self.binary_id,
                    note_id=item.node_id,
                    note=text,
                    public=False,
                    no_links=True,
                    update_mask="note",
                    async_req=True,
                )
            elif self.item_type == "Notes":
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
            elif self.item_type == "Procedure Group Notes":
                api_call = ctmprocs.update_procedure_note
                response = api_call(
                    proc_hash=self.listing_item.hard_hash,
                    note_id=item.node_id,
                    note=text,
                    public=False,
                    no_links=True,
                    update_mask="note",
                    async_req=True,
                )
            elif self.item_type == "Proc Name":
                api_call = ctmfiles.update_file_procedure_genomics
                response = api_call(
                    binary_id=self.binary_id,
                    rva=item.rva,
                    procedure_name=text,
                    update_mask="procedure_name",
                    no_links=True,
                    async_req=True,
                )
            response = response.get()
        except ApiException as exc:
            info_msgs = ["Could not update " + self.item_type + "."]
            process_api_exception(exc, False, info_msgs)
            return None
        except Exception as exc:
            process_regular_exception(exc, False, None)
            return None
        else:
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
        try:
            if "Notes" in type_str:
                api_call = ctmfiles.create_file_note
                response = api_call(
                    binary_id=self.parent.binary_id,
                    note=text,
                    public=False,
                    no_links=True,
                    async_req=True,
                )
            elif "Tags" in type_str:
                api_call = ctmfiles.create_file_tag
                response = api_call(
                    binary_id=self.parent.binary_id,
                    name=text,
                    no_links=True,
                    async_req=True,
                )
            response = response.get()
        except ApiException as exc:
            info_msgs = ["Could not create " + type_str + " for File."]
            process_api_exception(exc, False, info_msgs)
            return None
        except Exception as exc:
            process_regular_exception(exc, False, None)
            return None
        else:
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
        try:
            if "Notes" in type_str:
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
        except ApiException as exc:
            logger.debug(traceback.format_exc())
            info_msgs = ["Could not update File " + type_str + "."]
            process_api_exception(exc, False, info_msgs)
            return None
        except Exception as exc:
            process_regular_exception(exc, False, None)
            return None
        else:
            return text


class FileUploadPopup(QtWidgets.QMessageBox):
    """Custom popup with file and disassembly upload buttons."""

    def __init__(self, widget_parent):
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
        self.setWindowTitle("Upload Statuses")

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
