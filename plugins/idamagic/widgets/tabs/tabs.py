from PyQt5 import QtWidgets

from ..collections.trees import TabTreeWidget
from ..collection_elements.tree_nodes import (
    ProcFilesNode,
    TreeNotesNode,
    TreeTagsNode,
    TreeProcGroupNotesNode,
    TreeProcGroupTagsNode,
    ProcSimilarityNode,
)

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
