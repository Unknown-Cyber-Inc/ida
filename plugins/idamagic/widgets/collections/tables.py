import ida_kernwin
from PyQt5 import QtWidgets

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
