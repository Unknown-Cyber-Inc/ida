"""
Main scroll widget at the highest level. 

This is the scaffolding of a simplecustviewer_t for the purpose of 
testing out how certain functions can be synced.
"""

# IDA and UI imports
import ida_nalt, ida_kernwin
from PyQt5 import QtWidgets, Qt, QtGui 

#cythereal magic for calling API
import cythereal_magic

# load_dotenv sources the below environment variables from .env
import os
PLUGIN_DEBUG = True if os.getenv("PLUGIN_DEBUG") == "True" else False

class PluginScrHooks(ida_kernwin.UI_Hooks):
    def __init__(self, *args):
        super().__init__(*args)

    def screen_ea_changed(self, ea, prev_ea):
        print(hex(ea))

class ProcTableItemModel(Qt.QStandardItem):
    def __init__(self,procInfo):
        super().__init__()
        self.setText(procInfo['hard_hash'])
        self.setEditable(False)
        
        # more specific entries
        signatureAddrNode = ProcTableSubItem("signature (address)")
        for i,signature in enumerate(procInfo["example_blockEAs"]):
            indexNode = ProcTableSubItem("block " + str(i+1) +":")
            indexNode.appendRows([ProcTableHexAddrItem("start EA: ",signature['startEA']),
                                  ProcTableHexAddrItem("end EA: ",signature['endEA'])
            ])
            signatureAddrNode.appendRow(indexNode)

        signatureNode = ProcTableSubItem("signature (byte)")
        if procInfo["signature"]:
            for i,signature in enumerate(procInfo["signature"]):
                indexNode = ProcTableSubItem("block " + str(i+1) +":")
                indexNode.appendRows([ProcTableSubItem(byte) for byte in signature])
                signatureNode.appendRow(indexNode)

        signatureAssemblyNode = ProcTableSubItem("signature (assembly)")
        for i,signature in enumerate(procInfo["example_procedure"]):
            indexNode = ProcTableSubItem("block " + str(i+1) +":")
            indexNode.appendRows([ProcTableSubItem(byte) for byte in signature])
            signatureAssemblyNode.appendRow(indexNode)

        # headers
        self.appendRows([
            ProcTableSubItem("occurrances: "+str(procInfo['occurrence_counts'])),
            ProcTableSubItem("library: "+str(procInfo['is_library'])),
            ProcTableSubItem("signatures: "+str(procInfo['signature_count'])),
            ProcTableSubItem("total blocks: "+str(procInfo['block_counts'])),
            ProcTableSubItem("total instructions: "+str(procInfo['instr_counts'])),
            ProcTableSubItem("total bytes: "+str(procInfo['byte_counts'])),
        ])

        self.appendRows([signatureAddrNode,signatureNode,signatureAssemblyNode])

class ProcTableSubItem(Qt.QStandardItem):
    """Item below a TableItemModel

    May be grouped more logically with 'delegates'!
    """
    def __init__(self,entry:str):
        super().__init__()
        self.setText(entry) 
        self.setEditable(False)           

class ProcTableHexAddrItem(ProcTableSubItem):
    """Item below a TableItemModel. Contains IDA hex item as 'ea' attr.

    May be grouped more logically with 'delegates'!
    """
    def __init__(self,entry:str,hexAddr:str):
        super().__init__(entry+hexAddr)
        self.ea = ida_kernwin.str2ea(hexAddr)

class MAGICPluginScrClass(ida_kernwin.PluginForm):
    """
    Highest level of the plugin Scroll UI Object. Inherits ida_kernwin.PluginForm which wraps IDA's Form object as a PyQt object.
    """

    """
    functions for PluginForm object functionality.
    """
    def __init__(self, title, magic_api_client):
        super().__init__()
        self.sha256 = ida_nalt.retrieve_input_file_sha256().hex()
        self.title:str = title
        self.ctmfiles = cythereal_magic.FilesApi(magic_api_client)

        self.hooks = PluginScrHooks()
        self.hooks.hook()

        # show widget on creation of new form
        self.Show()

        # dock this widget on the rightmost side of IDA, ensure this by setting dest_ctrl to an empty string
        ida_kernwin.set_dock_pos(self.title,"",ida_kernwin.DP_RIGHT)
        """
        A 'QSplitter' is created which can handle the default creation size.
        Through testing I have found out which widget this is relative to self.
        It is handled by IDA and doesn't have a simple reference.
        The number here is a relative size ratio between two widgets (between the scroll widget and the widgets to the left)
        """
        self.parent.parent().parent().setSizes([700,1])

    def OnCreate(self, form):
        """
        Called when the widget is created.
        """
        # Convert form to PyQt obj
        self.parent = self.FormToPyQtWidget(form)

        self.load_scroll_view()

        # strictly for testing
        for i in range(1000):
            self.textbrowser.append("Line " + str(i) + ": ")
     
    def OnClose(self, form):
        """
        Called when the widget is closed.
        """
        self.hooks.unhook()
        return

    def Show(self):
        #show with intrinsic title, specific options
        return super().Show(
            self.title,
            options=(
            # for some reason the options appear to only work once after resetting desktop in IDA
            ida_kernwin.PluginForm.WOPN_DP_SZHINT
            # | ida_kernwin.PluginForm.WOPN_RESTORE
            # | ida_kernwin.PluginForm.WCLS_CLOSE_LATER
            # | ida_kernwin.PluginForm.WCLS_SAVE
            ),
        )

    
    """
    functions for building and displaying pyqt.
    """
    def load_scroll_view(self):
        """
        Create form items then populate page with them.
        """
        self.init_scroll_view()
        self.populate_scroll_view()

    def populate_scroll_view(self):
        """
        After individual form items are initialized, populate the form with them.
        """
        # Create layout object
        layout = QtWidgets.QVBoxLayout()

        #adding widgets to layout, order here matters
        layout.addWidget(self.t1)
        layout.addWidget(self.t2)
        layout.addWidget(self.pushbutton)
        layout.addWidget(self.proc_tree)
        layout.addWidget(self.textbrowser)

        # set main widget's layout based on the above items
        self.parent.setLayout(layout)

    def init_scroll_view(self):
        """
        Initialize individual items which will be added to the form.
        """
        #personalizing QT items, in order of appearance (order is set by layout though)
        self.t1 = QtWidgets.QLabel("Lorem Ipsum <font color=red>Cythereal</font>")
        self.t2 = QtWidgets.QLabel("Lorem Ipsum <font color=blue>MAGIC</font>")

        self.pushbutton = QtWidgets.QPushButton("request procedures")
        self.pushbutton.setCheckable(False)

        self.proc_tree = QtWidgets.QTreeView()
        self.proc_tree.setHeaderHidden(True)
        self.proc_tree.setModel(Qt.QStandardItemModel())
        self.proc_tree.doubleClicked.connect(self.proc_tree_jump_to_hex) # let widget handle doubleclicks

        self.textbrowser = QtWidgets.QTextEdit()
        self.textbrowser.setReadOnly(True)

        #connecting events to items if necessary, in order of appearance
        self.pushbutton.clicked.connect(self.pushbutton_click) 
    
    def populate_proc_table(self, resources):
        """ populates the procedures table with recieved procedures
        
        @param resources: dict
        May also be responsible for providing IDA with dict in form of {"startEA":"procHash"}.
        This is so we can jump to that EA when we reach that item in IDA window
        Note: is there any difference in performance from many appendRow and one appendRows?
        """
        rootNode = self.proc_tree.model().invisibleRootItem()

        for resource in resources:
            rootNode.appendRow(ProcTableItemModel(resource))

    """
    functions for connecting pyqt signals
    """
    def proc_tree_jump_to_hex(self,index):
        """ If double-clicked item is a hex item in tree view, jump IDA to that position. 
        
        see ProcTableHexAddrItem for "ea" attr
        """
        item = self.proc_tree.selectedIndexes()[0]
        if hasattr(item.model().itemFromIndex(index),"ea"):
            ida_kernwin.jumpto(item.model().itemFromIndex(index).ea)

    def pushbutton_click(self):
        self.textbrowser.clear()
        self.proc_tree.model().clear()

        try:
            ctmr = self.ctmfiles.list_file_procedures(self.sha256,read_mask="*") # request resources

            resources = ctmr['resources'] # get 'resources' from the returned
            self.populate_proc_table(resources) # populate qtreeview with processes

            self.textbrowser.append('Resources gathered successfully.')
        except:
            self.textbrowser.append('No resources could be gathered.')
            if PLUGIN_DEBUG: 
                import traceback
                self.textbrowser.append(traceback.format_exc())