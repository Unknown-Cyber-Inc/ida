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
from ...core.enums import TabKind, ItemType


class BaseCenterTab(QtWidgets.QWidget):
    """Base for all tabs to be used within the CenterDisplayWidget.tab_bar.

    Subclasses set ``kind`` (a TabKind member). The base provides
    ``current_tab_kind`` helper for dispatch decisions that need to
    know which kind of tab is active.
    """

    #: Concrete tab classes override this.
    kind: TabKind = None  # type: ignore[assignment]

    def __init__(self, center_widget):
        super().__init__()
        self.center_widget = center_widget
        layout = QtWidgets.QVBoxLayout(self)

        self.tab_tree = TabTreeWidget(self.center_widget)
        self.tab_tree.expanded.connect(self.onTreeExpand)
        self.tab_tree.clicked.connect(self.item_selected)

        layout.addWidget(self.tab_tree)
        self.setLayout(layout)

    @staticmethod
    def current_tab_kind(center_widget) -> TabKind:
        """Return the TabKind of the currently active tab, or None.

        Replaces the original QColor-based detection. Looks up the
        active tab widget and reads its ``kind`` class attribute.
        """
        tab_index = center_widget.tabs_widget.currentIndex()
        if tab_index < 0:
            return None
        tab = center_widget.tabs_widget.widget(tab_index)
        return getattr(tab, "kind", None)

    def item_selected(self, index):
        self.center_widget.create_button.setEnabled(False)
        self.center_widget.edit_button.setEnabled(False)
        self.center_widget.delete_button.setEnabled(False)

        kind = self.current_tab_kind(self.center_widget)
        data = index.data()
        parent_data = index.parent().data()

        if index.parent().data() is None and kind is TabKind.DERIVED_PROC:
            # selecting a procedure of ProcRootNode
            self.center_widget.edit_button.setEnabled(True)
            return

        # Section headers (Notes / Tags / Procedure Group Notes/Tags) → Create button only
        try:
            section = ItemType.from_string(data) if isinstance(data, str) else None
        except ValueError:
            section = None
        if section in (ItemType.TAGS, ItemType.NOTES,
                       ItemType.PROC_GROUP_NOTES, ItemType.PROC_GROUP_TAGS):
            self.center_widget.create_button.setEnabled(True)
            return

        # Items beneath a section
        try:
            parent_section = ItemType.from_string(parent_data) if isinstance(parent_data, str) else None
        except ValueError:
            parent_section = None
        if parent_section in (ItemType.TAGS, ItemType.PROC_GROUP_TAGS):
            # selecting a tag: create + delete
            self.center_widget.create_button.setEnabled(True)
            self.center_widget.delete_button.setEnabled(True)
        elif parent_section in (ItemType.NOTES, ItemType.PROC_GROUP_NOTES):
            # selecting a note: create + edit + delete
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

    kind = TabKind.PROC_ORIGINAL

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

    kind = TabKind.DERIVED_FILE

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

    kind = TabKind.DERIVED_PROC

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
