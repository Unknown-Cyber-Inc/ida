from PyQt5 import QtWidgets, QtGui

from idamagic.helpers import create_proc_name
from idamagic.api import (
    delete_file_note,
    delete_procedure_genomics_note,
    remove_file_tag,
    delete_procedure_genomics_tag_by_id,
    delete_procedure_note,
    delete_procedure_tag,
    list_procedure_genomics_notes,
    list_procedure_genomics_tags,
    list_procedure_files,
    list_procedure_notes,
    list_procedure_tags,
    list_file_notes,
    list_file_tags,
    list_procedure_similarities,
    list_file_procedure_genomics,
)
from ..tabs.tabs import (
    CenterProcTab,
    CenterDerivedFileTab,
    CenterDerivedProcTab,
)
from ..collection_elements.tree_nodes import (
    ProcRootNode,
    TreeNotesNode,
    TreeTagsNode,
    ProcListItem,
    ProcFilesNode,
    TreeProcGroupNotesNode,
    TreeProcGroupTagsNode,
    ProcSimilarityNode,
    ProcSimpleTextNode,
)
from ..collections.trees import TabTreeWidget
from ..popups.popups import (
    ComparePopup,
    DeleteConfirmationPopup,
    ProcTextPopup
)

class CenterDisplayWidget(QtWidgets.QWidget):
    """Custom display widget for selected items"""

    def __init__(self, widget_parent):
        super().__init__()
        self.tabs_widget: QtWidgets.QTabWidget
        self.widget_parent = widget_parent
        self.sha1 = self.widget_parent.main_interface.hashes["version_hash"]
        self.ida_md5 = self.widget_parent.main_interface.hashes["ida_md5"]
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
            CenterProcTab(self, item, table_row)
            self.remove_default_tab()
            if self.tab_bar.count() == 1:
                self.tab_color.setGreen(128)
            self.add_tab_visuals(tab_type)
        elif tab_type == "Derived procedure":
            original_tab = self.tabs_widget.currentWidget()
            original_proc = original_tab.item
            CenterDerivedProcTab(
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
            CenterDerivedFileTab(self, item)
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
                            binary_id=self.ida_md5,
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

        if node_type is ProcFilesNode:
            type_str = "Files"
        elif node_type is TreeProcGroupNotesNode:
            type_str = "Procedure Group Notes"
        elif node_type is TreeProcGroupTagsNode:
            type_str = "Procedure Group Tags"
        elif node_type is TreeNotesNode and self.tab_color.red() == 255:
            type_str = "File notes"
        elif node_type is TreeNotesNode and self.tab_color.blue() == 255:
            api_call = list_procedure_genomics_notes
            type_str = "Derived proc notes"
        elif node_type is TreeNotesNode and self.tab_color.green() == 128:
            api_call = list_procedure_genomics_notes
            type_str = "Notes"
        elif node_type is TreeTagsNode and self.tab_color.red() == 255:
            type_str = "File tags"
        elif node_type is TreeTagsNode and self.tab_color.blue() == 255:
            api_call = list_procedure_genomics_tags
            type_str = "Derived proc tags"
        elif node_type is TreeTagsNode and self.tab_color.green() == 128:
            api_call = list_procedure_genomics_tags
            type_str = "Tags"
        elif node_type is ProcSimilarityNode:
            type_str = "Similarities"

        if type_str == "Files":
            response = list_procedure_files(
                hard_hash=node.hard_hash,
                read_mask="sha1,sha256,filename",
                expand_mask="files",
            )
        elif type_str == "Procedure Group Notes":
            response = list_procedure_notes(
                hard_hash=node.hard_hash,
            )
        elif type_str == "Procedure Group Tags":
            response = list_procedure_tags(
                hard_hash=node.hard_hash,
            )
        elif type_str == "File notes":
            response = list_file_notes(
                binary_id=node.binary_id,
            )
        elif type_str == "File tags":
            response = list_file_tags(
                binary_id=node.binary_id,
            )
        elif type_str in plain_calls:
            response = api_call(
                binary_id=node.binary_id,
                rva=node.rva,
            )
        elif type_str == "Similarities":
            response = list_procedure_similarities(
                binary_id=node.binary_id,
                rva=node.rva,
                read_mask="block_count,code_count,binary_id,start_ea",
            )

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
            if type_str == "Notes":
                if self.tab_color.red() == 255:
                    response = delete_file_note(
                        binary_id=item.binary_id,
                        note_id=item.node_id,
                        info_msgs=[
                            "Could not delete file Note."
                        ]
                    )
                else:
                    response = delete_procedure_genomics_note(
                        binary_id=item.binary_id,
                        note_id=item.node_id,
                        rva=item.rva,
                        info_msgs=[
                            "Could not delete Note from selected procedure."
                        ]
                    )
            if type_str == "Tags":
                if self.tab_color.red() == 255:
                    response = remove_file_tag(
                        binary_id=item.binary_id,
                        tag_id=item.node_id,
                        info_msgs=[
                            "Could not delete Tag from selected file."
                        ]
                    )
                else:
                    response = delete_procedure_genomics_tag_by_id(
                        binary_id=item.binary_id,
                        tag_id=item.node_id,
                        rva=item.rva,
                        info_msgs=[
                            "Could not delete Tag from selected procedure."
                        ]
                    )
            if type_str == "Procedure Group Notes":
                response = delete_procedure_note(
                    hard_hash=item.hard_hash,
                    note_id=item.node_id,
                    info_msgs=[
                        "Could not delete selected Procedure Group Note."
                    ]
                )
            elif type_str == "Procedure Group Tags":
                response = delete_procedure_tag(
                    hard_hash=item.hard_hash,
                    tag_id=item.node_id,
                    info_msgs=[
                        "Could not delete Tag from selected Procedure Group."
                    ]
                )

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

        orig_response = list_file_procedure_genomics(
            binary_id=orig_file_hash,
            rva=orig_proc_rva,
            info_msgs=[
                "Unable to fetch procedure code."
            ]
        )
        orig_response = orig_response.get()
        orig_proc = orig_response.resource

        derived_response = list_file_procedure_genomics(
            binary_id=derived_file_hash,
            rva=derived_proc_rva,
            info_msgs=[
                "Unable to fetch procedure code."
            ]
        )
        derived_response = derived_response.get()
        derived_proc = derived_response.resource

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
