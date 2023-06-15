"""
Methods and classes in the MAGICPluginScrClass related to populating the procedure tree.
"""

# IDA and UI imports
import ida_kernwin
from PyQt5 import Qt

# load_dotenv sources the below environment variables from .env
import os
PLUGIN_DEBUG = True if os.getenv("PLUGIN_DEBUG") == "True" else False

"""
Nodes in the proctree
"""
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

"""
Methods in the MAGICPluginScrClass related to populating the procedure tree
"""
class _ScrClassMethods:

    """
    functions for building and displaying pyqt.
    """
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