from PyQt5 import QtWidgets

class CustomListItem(QtWidgets.QListWidgetItem):
    """Custom list items for ProcSimpleTextNode"""

    def __init__(self, proc_node):
        super().__init__(proc_node.text)
        self.proc_node = proc_node
