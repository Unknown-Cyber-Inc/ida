from PyQt5 import QtWidgets

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
