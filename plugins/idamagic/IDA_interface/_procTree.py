"""
Methods and classes in the MAGICPluginScrClass related to populating the
procedure list.
"""

import ida_kernwin
import json
import logging
import traceback

from cythereal_magic.rest import ApiException
from PyQt5 import Qt

from ..widgets import ProcTextPopup

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

    def __init__(self, node_name, full_name, start_ea: int):
        super().__init__()
        self.node_name = node_name
        self.start_ea = start_ea
        self.full_name = full_name
        if self.full_name is not None:
            self.setText(full_name)
        else:
            self.setText(node_name)


class ProcSimpleTextNode(ProcTableItem):
    """Node which contains only simple text information"""

    def __init__(
        self, hard_hash="", node_id="", text="", sha1="", binary_id="", rva=""
    ):
        super().__init__()
        self.setText(text)
        self.text = text
        self.node_id = node_id
        self.hard_hash = hard_hash
        self.sha1 = sha1
        self.binary_id = binary_id
        self.rva = rva


class ProcHeaderItem(ProcSimpleTextNode):
    """Node representing fields of produre calls which take form of str:str

    For example, dictionary key values will be printed as "key: value"
    """

    def __init__(self, key, value):
        super().__init__(text=(key + ":\t" + value))


class ProcListItem(ProcSimpleTextNode):
    """Node representing fields of produre calls which take form of str:str

    For example, dictionary key values will be printed as "key: value"
    """

    def __init__(self, name, rows):
        super().__init__(name)
        for item in rows:
            self.appendRow(ProcSimpleTextNode(text=item))


class ProcNotesNode(ProcTableItem):
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


class ProcTagsNode(ProcTableItem):
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


class ProcFilesNode(ProcTableItem):
    """Node representing the root of the "files" category.

    Contains subnodes representing individual files.
    """

    def __init__(self, hard_hash, rva):
        super().__init__()
        self.setText("Files")
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
        self.setText("Similarities")
        self.hard_hash = hard_hash
        self.isPopulated = False
        self.binary_id = binary_id
        self.rva = rva
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
        for proc in procedureInfo.procedures:
            start_ea = ida_kernwin.str2ea(proc.start_ea) + int(
                procedureInfo.image_base, 16
            )
            hard_hash = proc.hard_hash
            strings = proc.strings
            apiCalls = proc.api_calls
            proc_name = getattr(proc, "procedure_name", None)
            if proc_name:
                full_name = f"{proc.start_ea} - {proc_name}"
            else:
                full_name = None
            procrootnode = ProcRootNode(proc.start_ea, full_name, start_ea)
            # add node to dict to avoid looping through all objects in PluginScrHooks
            self.procedureEADict[start_ea] = procrootnode

            procrootnode.appendRows(
                [
                    ProcHeaderItem(
                        "Occurrence count", str(proc.occurrence_count)
                    ),
                    # tab is ignored for boolean for some reason
                    # ProcHeaderItem("Library", "\t" + str(proc.is_library)),
                    ProcHeaderItem("Type", proc.status),
                ]
            )

            if strings:
                procrootnode.appendRow(ProcListItem("Strings", strings))

            if apiCalls:
                procrootnode.appendRow(ProcListItem("API Calls", apiCalls))

            procrootnode.appendRows(
                [
                    ProcNotesNode(hard_hash, self.sha256, proc.start_ea),
                    ProcTagsNode(hard_hash, self.sha256, proc.start_ea),
                    ProcFilesNode(hard_hash, proc.start_ea),
                    ProcSimilarityNode(
                        hard_hash, self.sha256, proc.start_ea
                    ),
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
            returned_vals = self.make_list_api_call(filesRootNode)
            # start adding file information
            for file in returned_vals:
                sha1 = file.sha1

                if file.sha256 != self.sha256:
                    filename = sha1
                    if file.filenames:
                        filename = file["filenames"][0]
                else:
                    filename = f"Current file - {sha1}"

                # build a fileNode
                filesRootNode.appendRow(
                    ProcSimpleTextNode(text=filename, sha1=sha1)
                )

            # remove the empty init child
            filesRootNode.removeRows(0, 1)
            filesRootNode.isPopulated = True

    def populate_proc_notes(self, notesRootNode: ProcNotesNode):
        """populates a selected procedure's 'notes' node with recieved notes

        PARAMETERS
        ----------
        notesRootNode: ProcNotesNode
            Represents the procedure node which is to be populated with notes.
        """
        if not notesRootNode.isPopulated:
            returned_vals = self.make_list_api_call(notesRootNode)

            # start adding note information
            for note in returned_vals:
                notesRootNode.appendRow(
                    ProcSimpleTextNode(
                        hard_hash=notesRootNode.hard_hash,
                        node_id=note.id,
                        text=note.note,
                        binary_id=notesRootNode.binary_id,
                        rva=notesRootNode.rva,
                    )
                )
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
            returned_vals = self.make_list_api_call(tagsRootNode)

            for tag in returned_vals:
                tagsRootNode.appendRow(
                    ProcSimpleTextNode(
                        hard_hash=tagsRootNode.hard_hash,
                        node_id=tag.id,
                        text=tag.name,
                        binary_id=tagsRootNode.binary_id,
                        rva=tagsRootNode.rva,
                    )
                )

            # remove the empty init child
            tagsRootNode.removeRows(0, 1)
            tagsRootNode.isPopulated = True

    def populate_proc_similarities(
        self, similarityRootNode: ProcSimilarityNode
    ):
        """Populates a selected procedure's "similarity" node with similar
           procedures.

        PARAMETERS
        ---------
        nameRootNode: ProcSimilarityNode
            Represents the procedure node which is to be populated with
            similarites.
        """
        if not similarityRootNode.isPopulated:
            returned_vals = self.make_list_api_call(similarityRootNode)

            file_sha1 = self.retrieve_file_sha1(similarityRootNode.binary_id)

            node_text = ""
            for proc in returned_vals:
                if (
                    file_sha1 == proc.binary_id
                    and similarityRootNode.rva == proc.start_ea
                ):
                    node_text = (
                        f"Current function - sha1: {proc.binary_id},"
                        f" startEA: {proc.start_ea}"
                    )
                else:
                    node_text = f"sha1: {proc.binary_id}, startEA: {proc.start_ea}"
                similarityRootNode.appendRow(
                    ProcSimpleTextNode(
                        hard_hash=similarityRootNode.hard_hash, text=node_text
                    )
                )

            # remove the empty init child
            similarityRootNode.removeRows(0, 1)
            similarityRootNode.isPopulated = True

    #
    # functions for connecting pyqt signals
    #

    def make_list_api_call(self, node):
        """Make api call and handle exceptions"""
        node_type = type(node)
        api_call = None
        type_str = None
        read_mask = None

        if node_type is ProcFilesNode:
            api_call = self.ctmprocs.list_procedure_files
            type_str = "Files"
            read_mask = "sha1,sha256,filenames"
        elif node_type is ProcNotesNode:
            api_call = self.ctmfiles.list_procedure_genomics_notes
            type_str = "Notes"
        elif node_type is ProcTagsNode:
            api_call = self.ctmfiles.list_procedure_genomics_tags
            type_str = "Tags"
        elif node_type is ProcSimilarityNode:
            api_call = self.ctmfiles.list_procedure_similarities
            type_str = "Similarities"

        try:
            if type_str == "Files":
                ctmr = api_call(
                    node.hard_hash,
                    read_mask=read_mask,
                    expand_mask=type_str.lower(),
                    no_links=True,
                )
            else:
                ctmr = api_call(
                    binary_id=node.binary_id,
                    rva=node.rva,
                    no_links=True,
                )
        except ApiException as exp:
            logger.debug(traceback.format_exc())
            print(
                f"No {type_str.lower()} could be gathered from selected procedure."
            )
            for error in json.loads(exp.body).get("errors"):
                logger.info(error["reason"])
                print(f"{error['reason']}: {error['message']}")
        except Exception as exp:
            logger.debug(traceback.format_exc())
            print("Unknown Error occurred")
            print(f"<{exp.__class__}>: {str(exp)}")
            # exit if this call fails so user can retry
            # (this func always returns None anyway)
            return None
        else:
            if ctmr.status >= 200 and ctmr.status <= 299:
                print(
                    f"{type_str} gathered from selected procedure successfully."
                )
            else:
                print(f"Error gathering {type_str}.")
                print(f"Status Code: {ctmr.status}")
                print(f"Error message: {ctmr.errors}")
        return ctmr.resources

    def retrieve_file_sha1(self, binary_id):
        """Get the sha1 for a given file."""
        read_mask = "sha1"

        try:
            response = self.ctmfiles.get_file(
                binary_id=binary_id, read_mask=read_mask, no_links=True,
            )
        except ApiException as exp:
            logger.debug(traceback.format_exc())
            print("File GET failed.")
            for error in json.loads(exp.body).get("errors"):
                logger.info(error["reason"])
                print(f"{error['reason']}: {error['message']}")
        except Exception as exp:
            logger.debug(traceback.format_exc())
            print("Unknown Error occurred")
            print(f"<{exp.__class__}>: {str(exp)}")
            # exit if this call fails so user can retry
            # (this func always returns None anyway)
            return None
        else:
            if response.status >= 200 and response.status <= 299:
                print("File GET successful.")
            else:
                print("Error with file GET.")
                print(f"Status Code: {response.status}")
                print(f"Error message: {response.errors}")

        return response.resource.sha1

    def proc_tree_jump_to_hex(self, index):
        """If double-clicked item is a hex item in tree view, jump IDA to that position.

        see ProcRootNode for "ea" attr
        """
        item = self.proc_tree.model().itemFromIndex(index)
        if isinstance(item, ProcRootNode):
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
        self.create_button.setEnabled(False)
        self.edit_button.setEnabled(False)
        self.delete_button.setEnabled(False)
        item = self.proc_tree.model().itemFromIndex(index)
        itemType = type(item)

        if itemType is ProcFilesNode:
            self.populate_proc_files(item)
        elif itemType is ProcNotesNode:
            self.populate_proc_notes(item)
        elif itemType is ProcTagsNode:
            self.populate_proc_tags(item)
        elif itemType is ProcSimilarityNode:
            self.populate_proc_similarities(item)

    def item_selected(self, index):
        if index.parent().data() == None:
            self.create_button.setEnabled(False)
            self.edit_button.setEnabled(True)
            self.delete_button.setEnabled(False)
        elif index.data() == "Tags":
            self.create_button.setEnabled(True)
            self.edit_button.setEnabled(False)
            self.delete_button.setEnabled(False)
        elif index.parent().data() == "Tags":
            self.create_button.setEnabled(True)
            self.edit_button.setEnabled(False)
            self.delete_button.setEnabled(True)
        elif index.data() == "Notes":
            self.create_button.setEnabled(True)
            self.edit_button.setEnabled(False)
            self.delete_button.setEnabled(False)
        elif index.parent().data() == "Notes":
            self.create_button.setEnabled(True)
            self.edit_button.setEnabled(True)
            self.delete_button.setEnabled(True)
        else:
            self.create_button.setEnabled(False)
            self.edit_button.setEnabled(False)
            self.delete_button.setEnabled(False)

    def show_popup(
        self, text, parent, listing_item=None, binary_id=None, rva=None, type=None
    ):
        """Handle showing edit popup"""
        self.popup = ProcTextPopup(
            listing_item=listing_item,
            fill_text=text,
            parent=parent,
            binary_id=binary_id,
            rva=rva,
            type=type,
        )
        self.popup.show()

    def on_edit_click(self):
        """Handle edit pushbutton click"""
        index = self.proc_tree.selectedIndexes()[0]
        item = index.model().itemFromIndex(index)
        text = item.text

        if isinstance(item, ProcRootNode):
            type = "Proc Name"
            if item.full_name is not None:
                text = item.full_name[(len(item.node_name)+ 3):]
            else:
                text = None
            self.show_popup(
                listing_item=item,
                text=text,
                parent=item.parent(),
                binary_id=None,
                rva=None,
                type=type,
            )
        elif isinstance(item.parent(), ProcNotesNode):
            type = "Notes"
            self.show_popup(
                listing_item=item,
                text=text,
                parent=item.parent().parent().parent(),
                binary_id=item.parent().binary_id,
                rva=item.parent().rva,
                type=type,
            )

    def on_create_click(self):
        """Handle edit pushbutton click"""
        index = self.proc_tree.selectedIndexes()[0]
        item = index.model().itemFromIndex(index)

        if isinstance(item, ProcNotesNode):
            type = "Notes"
            self.show_popup(
                listing_item=item,
                text=None,
                parent=item.parent().parent(),
                binary_id=item.binary_id,
                rva=item.rva,
                type=type,
            )
        elif isinstance(item, ProcTagsNode):
            type = "Tags"
            self.show_popup(
                listing_item=item,
                text=None,
                parent=item.parent().parent(),
                binary_id=item.binary_id,
                rva=item.rva,
                type=type,
            )
        elif isinstance(item.parent(), ProcNotesNode):
            type = "Notes"
            self.show_popup(
                listing_item=item.parent(),
                text=None,
                parent=item.parent().parent().parent(),
                binary_id=item.parent().binary_id,
                rva=item.parent().rva,
                type=type,
            )
        elif isinstance(item.parent(), ProcTagsNode):
            type = "Tags"
            self.show_popup(
                listing_item=item.parent(),
                text=None,
                parent=item.parent().parent().parent(),
                binary_id=item.parent().binary_id,
                rva=item.parent().rva,
                type=type,
            )

    def on_delete_click(self):
        """Handle delete pushbutton click"""
        index = self.proc_tree.selectedIndexes()[0]
        item = index.model().itemFromIndex(index)
        api_call = None
        type_str = ""

        if index.parent().data() == "Notes":
            type_str = "NOTE"
            api_call = self.ctmfiles.delete_procedure_genomics_note
        elif index.parent().data() == "Tags":
            type_str = "TAG"
            api_call = self.ctmfiles.delete_procedure_genomics_tag_by_id

        try:
            if index.parent().data() == "Notes":
                _, status, _ = api_call(
                    binary_id=item.binary_id,
                    note_id=item.node_id,
                    rva=item.rva,
                    force=True,
                    no_links=True,
                )
            elif index.parent().data() == "Tags":
                _, status, _ = api_call(
                    binary_id=item.binary_id,
                    rva=item.rva,
                    tag_id=item.node_id,
                    force=True,
                    no_links=True,
                )
        except ApiException as exp:
            logger.debug(traceback.format_exc())
            print(f"Could not delete {type_str} from selected procedure.")
            for error in json.loads(exp.body).get("errors"):
                logger.info(error["reason"])
                print(f"{error['reason']}: {error['message']}")

            return None
        except Exception as exp:
            logger.debug(traceback.format_exc())
            print("Unknown Error occurred")
            print(f"<{exp.__class__}>: {str(exp)}")
            # exit if this call fails so user can retry
            # (this func always returns None anyway)

            return None
        else:
            if status >= 200 and status <= 299:
                item.parent().removeRow(item.row())
                print(
                    f"{type_str} removed from selected procedure successfully."
                )
            else:
                print(f"Error deleting {type_str}.")
                print(f"Status Code: {status}")
                # print(f"Error message: {ctmr.errors}")
                return None

    def pushbutton_click(self):
        """What to do when the 'Get Procedures' button is clicked.

        GET from procedures and list all procedures associated with file.
        """

        # explicitly stating readmask to not request extraneous info
        genomics_read_mask = (
            "cfg,start_ea,is_library,status,procedure_hash,"
            + "occurrence_count,strings,api_calls,procedure_name"
        )
        order_by = "start_ea"

        try:
            ctmr = self.ctmfiles.list_file_genomics(
                binary_id=self.sha256,
                read_mask=genomics_read_mask,
                order_by=order_by,
                no_links=True,
                page_size=250,
            )
        except ApiException as exp:
            logger.debug(traceback.format_exc())
            print("No procedures could be gathered.")
            for error in json.loads(exp.body).get("errors"):
                logger.info(error["reason"])
                print(f"{error['reason']}: {error['message']}")
        except Exception as exp:
            logger.debug(traceback.format_exc())
            print("Unknown Error occurred")
            print(f"<{exp.__class__}>: {str(exp)}")
            print(traceback.format_exc())
            # exit if this call fails so user can retry
            # (this func always returns None anyway)
            return None
        else:
            if ctmr.status >= 200 and ctmr.status <= 299:
                print("Procedures gathered successfully.")
                # on a successful call, populate table
                self.populate_proc_table(ctmr.resource)
            else:
                print("Error gathering Procedures.")
                print(f"Status Code: {ctmr.status}")
                print(f"Error message: {ctmr.errors}")
