"""
Main scroll widget at the highest level. 

This is the scaffolding of a simplecustviewer_t for the purpose of 
testing out how certain functions can be synced.
"""

# IDA and UI imports
import ida_nalt, ida_kernwin
from PyQt5 import QtWidgets, Qt, QtGui 

#cythereal magic for calling API and related modules
import cythereal_magic
from ..MAGIC_hooks import PluginScrHooks
from .procedureTree import * # contains classes related to different types of nodes in the tree

# load_dotenv sources the below environment variables from .env
import os
PLUGIN_DEBUG = True if os.getenv("PLUGIN_DEBUG") == "True" else False
PLUGIN_DEVELOP = True if os.getenv("PLUGIN_DEBUG") == "True" else False

class MAGICPluginScrClass(ida_kernwin.PluginForm):
    """
    Highest level of the plugin Scroll UI Object. Inherits ida_kernwin.PluginForm which wraps IDA's Form object as a PyQt object.
    """

    """
    functions for PluginForm object functionality.
    """
    def __init__(self, title, magic_api_client):
        """Initialializes the form object

        Additionally, sets a few member variables necessary to the function of the plugin.
        A few are variables which are determined by IDA.
        """
        super().__init__()
        self.sha256 = ida_nalt.retrieve_input_file_sha256().hex()
        self.baseRVA = ida_nalt.get_imagebase()
        self.title:str = title
        self.ctmfiles = cythereal_magic.FilesApi(magic_api_client)
        self.ctmprocs = cythereal_magic.ProceduresApi(magic_api_client)
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
        """
        Take created widget object and display it on IDA's GUI
        """
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
        """Initialize individual items which will be added to the form.
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
        self.proc_tree.expanded.connect(self.onTreeExpand) # handle certain expand events

        self.textbrowser = QtWidgets.QTextEdit()
        self.textbrowser.setReadOnly(True)

        #connecting events to items if necessary, in order of appearance
        self.pushbutton.clicked.connect(self.pushbutton_click) 

    def populate_proc_table(self, procedureInfo):
        """ populates the procedures table with recieved procedures
        
        @param resources: dict containing procedures return request
        Note: is there any difference in performance from many appendRow and one appendRows?
        """
        procedures = procedureInfo['procedures']

        for proc in procedures:
            start_ea = ida_kernwin.str2ea(proc['startEA']) + int(procedureInfo['image_base'],16)
            hard_hash = proc['hard_hash']
            strings = proc['strings']
            apiCalls = proc['api_calls']
            
            procrootnode = ProcRootNode(proc['startEA'],start_ea)
            self.procedureEADict[start_ea] = procrootnode # add node to dict to avoid looping through all objects in PluginScrHooks

            procrootnode.appendRows([
                ProcHeaderItem("Group Occurrences",str(proc["occurrence_count"])),
                ProcHeaderItem("Library","\t"+str(proc["is_library"])), # tab is ignored for boolean for some reason
                ProcHeaderItem("Group Type",proc["status"]),
            ])

            if strings:
                procrootnode.appendRow(ProcListItem("Strings",strings))

            if apiCalls:
                procrootnode.appendRow(ProcListItem("API Calls",apiCalls))

            procrootnode.appendRows([
                ProcNotesNode(hard_hash),
                ProcTagsNode(hard_hash),
                ProcFilesNode(hard_hash),
            ])

            self.proc_tree.model().appendRow(procrootnode) # add root node to tree
    
    def populate_proc_files(self, filesRootNode:ProcFilesNode):
        """ populates a selected procedure's 'files' node with recieved files
        
        @param filesRootNode: ProcFilesNode represents the procedure node which is to be populated with files.
        Note: is there any difference in performance from many appendRow and one appendRows?
        """

        if not filesRootNode.isPopulated:
            read_mask='sha1,sha256,filenames'
            expand_mask='files'
            page_size=0

            try: 
                ctmr = self.ctmprocs.list_procedure_files(filesRootNode.hard_hash,read_mask=read_mask,expand_mask=expand_mask,page_size=page_size)['resources']
            except:
                self.textbrowser.append('No files could be gathered from selected procedure.')
                if PLUGIN_DEBUG: 
                    import traceback
                    self.textbrowser.append(traceback.format_exc())
                return None # exit if this call fails so user can retry (this func always returns None anyway)
            else:
                self.textbrowser.append('Files gathered from selected procedure successfully.')

            filesRootNode.removeRows(0,1) # remove the empty init child

            for file in ctmr: # start adding file information
                if file['sha256'] != self.sha256: # don't display current file, that's implicit
                    sha1 = file['sha1']
                    filename = sha1
                    if file['filenames']:
                        filename = file['filenames'][0]

                    fileNode = ProcSimpleTextNode(filename) # build a fileNode
                    fileNode.appendRow(ProcSimpleTextNode(sha1))

                    filesRootNode.appendRow(fileNode)
                
            filesRootNode.isPopulated = True

    def populate_proc_notes(self, notesRootNode:ProcNotesNode):
        """ populates a selected procedure's 'notes' node with recieved notes
        
        @param notesRootNode: ProcNotesNode represents the procedure node which is to be populated with notes.
        """
        if not notesRootNode.isPopulated:
            expand_mask='notes'

            try: 
                ctmr = self.ctmprocs.list_procedure_notes(notesRootNode.hard_hash,expand_mask=expand_mask)['resources']
            except:
                self.textbrowser.append('No notes could be gathered from selected procedure.')
                if PLUGIN_DEBUG: 
                    import traceback
                    self.textbrowser.append(traceback.format_exc())
                return None # exit if this call fails so user can retry (this func always returns None anyway)
            else:
                self.textbrowser.append('Notes gathered from selected procedure successfully.')

            for note in ctmr: # start adding note information

                notesRootNode.appendRow(ProcSimpleTextNode(note['note'])) # display note

            notesRootNode.removeRows(0,1) # remove the empty init child

            notesRootNode.isPopulated = True

    def populate_proc_tags(self, tagsRootNode:ProcTagsNode):
        """ populates a selected procedure's 'tags' node with recieved tags
        
        @param tagsRootNode: ProcTagsNode represents the procedure node which is to be populated with tags.
        """
        if not tagsRootNode.isPopulated:

            tagsRootNode.removeRows(0,1) # remove the empty init child

            tagsRootNode.isPopulated = True

    """
    functions for connecting pyqt signals
    """
    def proc_tree_jump_to_hex(self,index):
        """ If double-clicked item is a hex item in tree view, jump IDA to that position. 
        
        see ProcRootNode for "ea" attr
        """
        item = self.proc_tree.model().itemFromIndex(index)
        if type(item) is ProcRootNode:
            if self.procedureEADict[item.start_ea]:
                # this jump will note the ea and try to expand even though we doubleclicked
                # therefore, set as expanded and check this expression in the hook feature
                # afterwards, unset expanded
                if not self.proc_tree.isExpanded(index):
                    self.proc_tree.setExpanded(index,True)
                    ida_kernwin.jumpto(item.start_ea)
                    self.proc_tree.setExpanded(index,False)

    def onTreeExpand(self,index):
        """ What to do when a tree item is expanded. 
        
        @param index: 'QModelIndex' is a pyqt object which represents where the item is in the tree.
        This function is connected to the tree's 'expand' signal.
        Check what type of object was expand and call the function related to handling the population of that type.
        """
        item = self.proc_tree.model().itemFromIndex(index)
        itemType = type(item)

        if itemType is ProcFilesNode:
            self.populate_proc_files(item)
        elif itemType is ProcNotesNode:
            self.populate_proc_notes(item)
        elif itemType is ProcTagsNode:
            self.populate_proc_tags(item)

    def pushbutton_click(self):
        """ What to do when the 'request procedures' button is clicked. 
        
        GET from procedures and list all procedures associated with file.
        """
        self.textbrowser.clear()
        self.proc_tree.model().clear()

        # explicitly stating readmask to not request extraneous info
        genomics_read_mask = 'start_ea,is_library,status,procedure_hash,occurrence_count,strings,api_calls'
        page_size=0
        order_by='start_ea'

        try:
            ctmr = self.ctmfiles.list_file_genomics(self.sha256,read_mask=genomics_read_mask,order_by=order_by,page_size=page_size)['resources'] # get 'resources' from the returned
        except:
            self.textbrowser.append('No procedures could be gathered.')
            if PLUGIN_DEBUG: 
                import traceback
                self.textbrowser.append(traceback.format_exc())
        else:
            self.textbrowser.append('Procedures gathered successfully.')
            self.populate_proc_table(ctmr) # on a successful call, populate table