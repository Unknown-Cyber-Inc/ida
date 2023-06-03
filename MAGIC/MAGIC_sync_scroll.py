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
PLUGIN_DEVELOP = True if os.getenv("PLUGIN_DEBUG") == "True" else False

class ProcRootNode(Qt.QStandardItem):
    """Node representing the root of a single procedure

    """
    def __init__(self,node_name,start_ea,end_ea):
        super().__init__()
        self.setText(node_name)
        self.eas = [ida_kernwin.str2ea(start_ea),ida_kernwin.str2ea(end_ea)]
        self.setEditable(False)

class ProcHeaderItem(Qt.QStandardItem):
    """Node representing fields of produes calls which take form of str:str

    """
    def __init__(self,key,value):
        super().__init__()
        self.setText(key + ":\t" + value)
        self.setEditable(False)

class ProcFilesNode(Qt.QStandardItem):
    """Node representing the root of the "files" category. Contains subnodes representing individual files
    """
    def __init__(self,fileInfo):
        super().__init__()
        self.setText("files")
        self.isPopulated = False
        self.setEditable(False)

class PluginScrHooks(ida_kernwin.UI_Hooks):
        """Hooks necessary for the functionality of this form
        
        Connect to IDA's screen_ea_changed hook
        """
        def __init__(self, proc_tree, procedureEADict, *args):
            super().__init__(*args)
            # needs to be able to access the process_treeview once generated
            self.proc_tree = proc_tree
            self.procedureEADict = procedureEADict

        def screen_ea_changed(self, ea, prev_ea):
            eaKey = ida_kernwin.ea2str(ea).split(":")[1]
            eaKey = int(eaKey,16)
            if eaKey in self.procedureEADict:
                procedureQIndexItem = self.procedureEADict[eaKey].index()
                self.proc_tree.setCurrentIndex(procedureQIndexItem) # highlight and select it
                if not self.proc_tree.isExpanded(procedureQIndexItem): # do not expand before checking if expanded, see proc_tree_jump_to_hex for info
                    self.proc_tree.expand(procedureQIndexItem)
                # 3 is an enum telling the widget to open with the item in the center
                self.proc_tree.scrollTo(procedureQIndexItem,3) # jump to and center it
                

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
        self.procedureEADict = {} # dict solution to jump from IDA ea to plugin procedure

        # show widget on creation of new form
        self.Show()

        # hook into the IDA code
        self.hooks = PluginScrHooks(self.proc_tree,self.procedureEADict)
        self.hooks.hook()

        # dock this widget on the rightmost side of IDA, ensure this by setting dest_ctrl to an empty string
        ida_kernwin.set_dock_pos(self.title,"",ida_kernwin.DP_RIGHT)
        """
        A 'QSplitter' is created which can handle the default creation size.
        Through testing I have found out which widget this is relative to self.
        It is handled by IDA and doesn't have a simple reference.
        The number here is a relative size ratio between two widgets (between the scroll widget and the widgets to the left)
        """
        self.parent.parent().parent().setSizes([600,1])

        if PLUGIN_DEVELOP:
            self.pushbutton_click()

    def OnCreate(self, form):
        """
        Called when the widget is created.
        """
        # Convert form to PyQt obj
        self.parent = self.FormToPyQtWidget(form)

        self.load_scroll_view()
     
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
        self.proc_tree.expanded.connect(self.populate_proc_files) # handle certain expand events

        self.textbrowser = QtWidgets.QTextEdit()
        self.textbrowser.setReadOnly(True)

        #connecting events to items if necessary, in order of appearance
        self.pushbutton.clicked.connect(self.pushbutton_click) 

    def populate_proc_table(self, procedureInfo):
        """ populates the procedures table with recieved procedures
        
        @param resources: dict containing procedures return request
        Note: is there any difference in performance from many appendRow and one appendRows?
        """

        for proc in procedureInfo:
            start_ea = proc['example_startEA']

            procrootnode = ProcRootNode(proc['example_procedure_id'],start_ea,proc['example_endEA'])
            self.procedureEADict[int(start_ea,16)] = procrootnode # add node to dict to avoid looping through all objects in PluginScrHooks

            procrootnode.appendRows([
                ProcHeaderItem("Occurrences",str(proc["occurrence_counts"])),
                ProcHeaderItem("Library",str(proc["is_library"])),
                ProcHeaderItem("Group Type",proc["status"]),
            ])

            self.proc_tree.model().appendRow(procrootnode) # add root node to tree

    """
    functions for connecting pyqt signals
    """
    def proc_tree_jump_to_hex(self,index):
        """ If double-clicked item is a hex item in tree view, jump IDA to that position. 
        
        see ProcTableHexAddrItem for "ea" attr
        """
        item = self.proc_tree.model().itemFromIndex(index)
        if type(item) is ProcRootNode:
            if self.procedureEADict[item.eas[0]]:
                # this jump will note the ea and try to expand even though we doubleclicked
                # therefore, set as expanded and check this expression in the hook feature
                self.proc_tree.setExpanded(index,True)
                ida_kernwin.jumpto(item.eas[0])
                self.proc_tree.setExpanded(index,False)

    def populate_proc_files(self,index):
        return
        print(index)

    def pushbutton_click(self):
        self.textbrowser.clear()
        self.proc_tree.model().clear()

        try:
            ctmr = self.ctmfiles.list_file_procedures(self.sha256) # request resources

            resources = ctmr['resources'] # get 'resources' from the returned

            self.populate_proc_table(resources)

            self.textbrowser.append('Resources gathered successfully.')
        except:
            self.textbrowser.append('No resources could be gathered.')
            if PLUGIN_DEBUG: 
                import traceback
                self.textbrowser.append(traceback.format_exc())