"""
Methods and classes in the MAGICPluginScrClass related to populating the procedure tree.
"""

import ida_kernwin
import json
import logging
import traceback

from cythereal_magic.rest import ApiException
from PyQt5 import Qt

logger = logging.getLogger(__name__)


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

    def __init__(self, node_name, start_ea: int):
        super().__init__()
        self.setText(node_name)
        self.start_ea = start_ea


class ProcSimpleTextNode(ProcTableItem):
    """Node which contains only simple text information"""

    def __init__(self, text=""):
        super().__init__()
        self.setText(text)


class ProcHeaderItem(ProcSimpleTextNode):
    """Node representing fields of produre calls which take form of str:str

    For example, dictionary key values will be printed as "key: value"
    """

    def __init__(self, key, value):
        super().__init__(key + ":\t" + value)


class ProcListItem(ProcSimpleTextNode):
    """Node representing fields of produre calls which take form of str:str

    For example, dictionary key values will be printed as "key: value"
    """

    def __init__(self, name, rows):
        super().__init__(name)
        for item in rows:
            self.appendRow(ProcSimpleTextNode(item))


class ProcNotesNode(ProcTableItem):
    """Node representing the root of the "notes" category.

    Contains subnodes representing individual notes.
    """

    def __init__(self, hard_hash):
        super().__init__()
        self.setText("Notes")
        self.hard_hash = hard_hash
        self.isPopulated = False
        # empty item to be deleted when populated
        # expand button will not show unless it has at least one child
        self.appendRow(ProcSimpleTextNode())


class ProcTagsNode(ProcTableItem):
    """Node representing the root of the "tags" category.

    Contains subnodes representing individual tags.
    """

    def __init__(self, hard_hash):
        super().__init__()
        self.setText("Tags")
        self.hard_hash = hard_hash
        self.isPopulated = False
        # empty item to be deleted when populated
        # expand button will not show unless it has at least one child
        self.appendRow(ProcSimpleTextNode())


class ProcFilesNode(ProcTableItem):
    """Node representing the root of the "files" category.

    Contains subnodes representing individual files.
    """

    def __init__(self, hard_hash):
        super().__init__()
        self.setText("Files")
        self.hard_hash = hard_hash
        self.isPopulated = False
        # empty item to be deleted when populated
        # expand button will not show unless it has at least one child
        self.appendRow(ProcSimpleTextNode())


class _ScrClassMethods:
    """
    Methods in the MAGICPluginScrClass related to populating the procedure tree
    """

    """
    functions for building and displaying pyqt.
    """

    def populate_proc_table(self, procedureInfo):
        """populates the procedures table with recieved procedures

        @param resources: dict containing procedures return request
        Note: is there any difference in performance from many appendRow and one appendRows?
        """
        procedures = procedureInfo["procedures"]

        for proc in procedures:
            start_ea = ida_kernwin.str2ea(proc["startEA"]) + int(
                procedureInfo["image_base"], 16
            )
            hard_hash = proc["hard_hash"]
            strings = proc["strings"]
            apiCalls = proc["api_calls"]

            procrootnode = ProcRootNode(proc["startEA"], start_ea)
            # add node to dict to avoid looping through all objects in PluginScrHooks
            self.procedureEADict[start_ea] = procrootnode

            procrootnode.appendRows(
                [
                    ProcHeaderItem(
                        "Group Occurrences", str(proc["occurrence_count"])
                    ),
                    # tab is ignored for boolean for some reason
                    ProcHeaderItem("Library", "\t" + str(proc["is_library"])),
                    ProcHeaderItem("Group Type", proc["status"]),
                ]
            )

            if strings:
                procrootnode.appendRow(ProcListItem("Strings", strings))

            if apiCalls:
                procrootnode.appendRow(ProcListItem("API Calls", apiCalls))

            procrootnode.appendRows(
                [
                    ProcNotesNode(hard_hash),
                    ProcTagsNode(hard_hash),
                    ProcFilesNode(hard_hash),
                ]
            )

            # add root node to tree
            self.proc_tree.model().appendRow(procrootnode)

    def populate_proc_files(self, filesRootNode: ProcFilesNode):
        """populates a selected procedure's 'files' node with recieved files

        PARAMETERS
        ----------
        filesRootNode: ProcFilesNode
            Represents the procedure node which is to be populated with files.
        """

        if not filesRootNode.isPopulated:
            read_mask = "sha1,sha256,filenames"
            expand_mask = "files"
            page_size = 0

            try:
                ctmr = self.ctmprocs.list_procedure_files(
                    filesRootNode.hard_hash,
                    read_mask=read_mask,
                    expand_mask=expand_mask,
                    page_size=page_size,
                )["resources"]
            except ApiException as e:
                logger.debug(traceback.format_exc())
                self.textbrowser.append(
                    "No files could be gathered from selected procedure."
                )
                for error in json.loads(e.body).get("errors"):
                    logger.info(error["reason"])
                    self.textbrowser.append(
                        f"{error['reason']}: {error['message']}"
                    )
            except Exception as e:
                logger.debug(traceback.format_exc())
                self.textbrowser.append("Unknown Error occurred")
                self.textbrowser.append(f"<{e.__class__}>: {str(e)}")
                # exit if this call fails so user can retry
                # (this func always returns None anyway)
                return None
            else:
                self.textbrowser.append(
                    "Files gathered from selected procedure successfully."
                )

            # remove the empty init child
            filesRootNode.removeRows(0, 1)

            # start adding file information
            for file in ctmr:
                # don't display current file, that's implicit
                if file["sha256"] != self.sha256:
                    sha1 = file["sha1"]
                    filename = sha1
                    if file["filenames"]:
                        filename = file["filenames"][0]

                    # build a fileNode
                    fileNode = ProcSimpleTextNode(filename)
                    fileNode.appendRow(ProcSimpleTextNode(sha1))

                    filesRootNode.appendRow(fileNode)

            filesRootNode.isPopulated = True

    def populate_proc_notes(self, notesRootNode: ProcNotesNode):
        """populates a selected procedure's 'notes' node with recieved notes

        PARAMETERS
        ----------
        notesRootNode: ProcNotesNode
            Represents the procedure node which is to be populated with notes.
        """
        if not notesRootNode.isPopulated:
            expand_mask = "notes"

            try:
                ctmr = self.ctmprocs.list_procedure_notes(
                    notesRootNode.hard_hash, expand_mask=expand_mask
                )["resources"]
            except ApiException as e:
                logger.debug(traceback.format_exc())
                self.textbrowser.append(
                    "No notes could be gathered from selected procedure."
                )
                for error in json.loads(e.body).get("errors"):
                    logger.info(error["reason"])
                    self.textbrowser.append(
                        f"{error['reason']}: {error['message']}"
                    )
            except Exception as e:
                logger.debug(traceback.format_exc())
                self.textbrowser.append("Unknown Error occurred")
                self.textbrowser.append(f"<{e.__class__}>: {str(e)}")
                # exit if this call fails so user can retry
                # (this func always returns None anyway)
                return None
            else:
                self.textbrowser.append(
                    "Notes gathered from selected procedure successfully."
                )

            # start adding note information
            for note in ctmr:
                # display note
                notesRootNode.appendRow(ProcSimpleTextNode(note["note"]))

            # remove the empty init child
            notesRootNode.removeRows(0, 1)

            notesRootNode.isPopulated = True

    def populate_proc_tags(self, tagsRootNode: ProcTagsNode):
        """populates a selected procedure's 'tags' node with recieved tags

        PARAMETERS
        ---------
        tagsRootNode: ProcTagsNode
            Represents the procedure node which is to be populated with tags.
        """
        if not tagsRootNode.isPopulated:
            # remove the empty init child
            tagsRootNode.removeRows(0, 1)

            tagsRootNode.isPopulated = True

    """
    functions for connecting pyqt signals
    """

    def proc_tree_jump_to_hex(self, index):
        """If double-clicked item is a hex item in tree view, jump IDA to that position.

        see ProcRootNode for "ea" attr
        """
        item = self.proc_tree.model().itemFromIndex(index)
        if type(item) is ProcRootNode:
            if self.procedureEADict[item.start_ea]:
                # this jump will note the ea and try to expand even though we doubleclicked
                # therefore, set as expanded and check this expression in the hook feature
                # afterwards, unset expanded
                if not self.proc_tree.isExpanded(index):
                    self.proc_tree.setExpanded(index, True)
                    ida_kernwin.jumpto(item.start_ea)
                    self.proc_tree.setExpanded(index, False)

    def onTreeExpand(self, index):
        """What to do when a tree item is expanded.

        @param index: 'QModelIndex' is a pyqt object which represents where the item is in the tree.
        This function is connected to the tree's 'expand' signal.
        Check what type of object was expand and call the function
        related to handling the population of that type.
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
        """What to do when the 'request procedures' button is clicked.

        GET from procedures and list all procedures associated with file.
        """
        self.textbrowser.clear()
        self.proc_tree.model().clear()

        # explicitly stating readmask to not request extraneous info
        genomics_read_mask = "start_ea,is_library,status,procedure_hash,occurrence_count,strings,api_calls"
        page_size = 0
        order_by = "start_ea"

        try:
            ctmr = self.ctmfiles.list_file_genomics(
                self.sha256,
                read_mask=genomics_read_mask,
                order_by=order_by,
                page_size=page_size,
            )["resources"]
        except ApiException as e:
            logger.debug(traceback.format_exc())
            self.textbrowser.append("No procedures could be gathered.")
            for error in json.loads(e.body).get("errors"):
                logger.info(error["reason"])
                self.textbrowser.append(
                    f"{error['reason']}: {error['message']}"
                )
        except Exception as e:
            logger.debug(traceback.format_exc())
            self.textbrowser.append("Unknown Error occurred")
            self.textbrowser.append(f"<{e.__class__}>: {str(e)}")
            # exit if this call fails so user can retry
            # (this func always returns None anyway)
            return None
        else:
            self.textbrowser.append("Procedures gathered successfully.")
            # on a successful call, populate table
            self.populate_proc_table(ctmr)
