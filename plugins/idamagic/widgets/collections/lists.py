from PyQt5 import QtWidgets

from idamagic.api import delete_file_note, remove_file_tag
from ..buttons.pagination import PaginationSelector
from ..popups.popups import FileTextPopup, DeleteConfirmationPopup
from ..collection_elements.list_items import CustomListItem

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
            if "Notes" in type_str:
                response = delete_file_note(
                    binary_id=self.widget_parent.main_interface.hashes[
                        "ida_md5"
                    ],
                    note_id=item.proc_node.node_id,
                    info_msgs=[
                        "Could not delete file Note."
                    ]
                )
            elif "Tags" in type_str:
                response = remove_file_tag(
                    binary_id=self.widget_parent.main_interface.hashes[
                        "ida_md5"
                    ],
                    tag_id=item.proc_node.node_id,
                    info_msgs = [
                        "Could not delete file Tag."
                    ]
                )

            index = self.list_widget.row(item)
            self.list_widget.takeItem(index)

            self.create_button.setEnabled(True)
            self.edit_button.setEnabled(False)
            self.delete_button.setEnabled(False)
        else:
            return None
