from PyQt5 import Qt

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
