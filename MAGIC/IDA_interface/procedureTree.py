# IDA and UI imports
from PyQt5 import Qt

class ProcTableItem(Qt.QStandardItem):
    """Generic form of items on the procs table.

    Contains default features for all table items based on QStandardItem class.
    """
    def __init__(self):
        super().__init__()
        self.setEditable(False)

class ProcRootNode(ProcTableItem):
    """Node representing the root of a single procedure

    Has information related to its start_ea for jumping to the procedure in IDA's view.
    """
    def __init__(self,node_name,start_ea:int):
        super().__init__()
        self.setText(node_name)
        self.start_ea = start_ea

class ProcSimpleTextNode(ProcTableItem):
    """Node which contains only simple text information
    """
    def __init__(self,text=''):
        super().__init__()
        self.setText(text)

class ProcHeaderItem(ProcSimpleTextNode):
    """Node representing fields of produre calls which take form of str:str

    For example, dictionary key values will be printed as "key: value"
    """
    def __init__(self,key,value):
        super().__init__(key + ":\t" + value)

class ProcListItem(ProcSimpleTextNode):
    """Node representing fields of produre calls which take form of str:str

    For example, dictionary key values will be printed as "key: value"
    """
    def __init__(self,name,list):
        super().__init__(name)
        for item in list:
            self.appendRow(ProcSimpleTextNode(item))

class ProcNotesNode(ProcTableItem):
    """Node representing the root of the "notes" category.
    
    Contains subnodes representing individual notes.
    """
    def __init__(self,hard_hash):
        super().__init__()
        self.setText("Notes")
        self.hard_hash = hard_hash
        self.isPopulated = False
        # empty item to be deleted when populated
        self.appendRow(ProcSimpleTextNode()) # expand button will not show unless it has at least one child

class ProcTagsNode(ProcTableItem):
    """Node representing the root of the "tags" category.
    
    Contains subnodes representing individual tags.
    """
    def __init__(self,hard_hash):
        super().__init__()
        self.setText("Tags")
        self.hard_hash = hard_hash
        self.isPopulated = False
        # empty item to be deleted when populated
        self.appendRow(ProcSimpleTextNode()) # expand button will not show unless it has at least one child

class ProcFilesNode(ProcTableItem):
    """Node representing the root of the "files" category.
    
    Contains subnodes representing individual files.
    """
    def __init__(self,hard_hash):
        super().__init__()
        self.setText("Files")
        self.hard_hash = hard_hash
        self.isPopulated = False
        # empty item to be deleted when populated
        self.appendRow(ProcSimpleTextNode()) # expand button will not show unless it has at least one child  