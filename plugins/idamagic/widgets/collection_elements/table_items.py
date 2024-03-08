from PyQt5 import QtWidgets

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
