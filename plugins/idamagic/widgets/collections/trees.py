from PyQt5 import QtWidgets, Qt

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
