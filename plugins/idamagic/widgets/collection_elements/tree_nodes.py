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

    def __init__(
        self,
        node_name,
        full_name,
        start_ea,
        tree_type=None,
        binary_id=None,
        rva=None,
        table_row=None,
    ):
        super().__init__()
        self.node_name = node_name
        self.start_ea = start_ea
        self.full_name = full_name
        self.tree_type = tree_type
        self.binary_id = binary_id
        self.rva = rva
        self.table_row = table_row
        if self.full_name is not None:
            self.setText(full_name)
        else:
            self.setText(node_name)


class ProcSimpleTextNode(ProcTableItem):
    """Node which contains only simple text information"""

    def __init__(
        self, hard_hash="", node_id="", text="", binary_id="", rva=""
    ):
        super().__init__()
        self.setText(text)
        self.text = text
        self.node_id = node_id
        self.hard_hash = hard_hash
        self.binary_id = binary_id
        self.rva = rva


class ProcHeaderItem(ProcSimpleTextNode):
    """Node representing fields of produre calls which take form of str:str

    For example, dictionary key values will be printed as "key: value"
    """

    def __init__(self, key, value):
        super().__init__(text=(f"{key}: {value}"))


class ProcListItem(ProcSimpleTextNode):
    """Node representing fields of produre calls which take form of str:str

    For example, dictionary key values will be printed as "key: value"
    """

    def __init__(self, name, rows):
        super().__init__(name)
        self.setText(name)
        for item in rows:
            self.appendRow(ProcSimpleTextNode(text=item))


class TreeNotesNode(ProcTableItem):
    """Node representing the root of the "notes" category.

    Contains subnodes representing individual notes.
    """

    def __init__(self, hard_hash, binary_id, rva):
        super().__init__()
        self.setText("Notes")
        self.hard_hash = hard_hash
        self.isPopulated = False
        self.binary_id = binary_id
        self.rva = rva
        # empty item to be deleted when populated
        # expand button will not show unless it has at least one child
        self.appendRow(ProcSimpleTextNode())


class TreeTagsNode(ProcTableItem):
    """Node representing the root of the "tags" category.

    Contains subnodes representing individual tags.
    """

    def __init__(self, hard_hash, binary_id, rva):
        super().__init__()
        self.setText("Tags")
        self.hard_hash = hard_hash
        self.isPopulated = False
        self.binary_id = binary_id
        self.rva = rva
        # empty item to be deleted when populated
        # expand button will not show unless it has at least one child
        self.appendRow(ProcSimpleTextNode())


class TreeProcGroupNotesNode(ProcTableItem):
    """Node representing the root of the "notes" category.

    Contains subnodes representing individual notes.
    """

    def __init__(self, hard_hash, binary_id, rva):
        super().__init__()
        self.setText("Procedure Group Notes")
        self.hard_hash = hard_hash
        self.isPopulated = False
        self.binary_id = binary_id
        self.rva = rva
        # empty item to be deleted when populated
        # expand button will not show unless it has at least one child
        self.appendRow(ProcSimpleTextNode())


class TreeProcGroupTagsNode(ProcTableItem):
    """Node representing the root of the "tags" category.

    Contains subnodes representing individual tags.
    """

    def __init__(self, hard_hash, binary_id, rva):
        super().__init__()
        self.setText("Procedure Group Tags")
        self.hard_hash = hard_hash
        self.isPopulated = False
        self.binary_id = binary_id
        self.rva = rva
        # empty item to be deleted when populated
        # expand button will not show unless it has at least one child
        self.appendRow(ProcSimpleTextNode())


class ProcFilesNode(ProcTableItem):
    """Node representing the root of the "files" category.

    Contains subnodes representing individual files.
    """

    def __init__(self, hard_hash, rva):
        super().__init__()
        self.setText("Containing Files")
        self.hard_hash = hard_hash
        self.isPopulated = False
        self.rva = rva
        # empty item to be deleted when populated
        # expand button will not show unless it has at least one child
        self.appendRow(ProcSimpleTextNode())


class ProcSimilarityNode(ProcTableItem):
    """Node representing the root of the "similarity" category.

    Contains subnodes representing similar functions.
    """

    def __init__(self, hard_hash, binary_id, rva):
        super().__init__()
        self.setText("Similarity Locations")
        self.hard_hash = hard_hash
        self.isPopulated = False
        self.binary_id = binary_id
        self.rva = rva
        # empty item to be deleted when populated
        # expand button will not show unless it has at least one child
        self.appendRow(ProcSimpleTextNode())

