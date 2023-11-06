"""
Methods and classes in the MAGICPluginFormClass related to populating the files table.
"""

import logging
import json
import os
# import shutil
import traceback
import hashlib

from cythereal_magic.rest import ApiException
from ..helpers import (
    encode_file,
    get_linked_binary_expected_path,
)
from ..widgets import FileSimpleTextNode
from ..helpers import create_idb_file

IDA_LOGLEVEL = str(os.getenv("IDA_LOGLEVEL", "INFO")).upper()
logger = logging.getLogger(__name__)


class _MAGICFormClassMethods:
    """
    Methods in the MAGICPluginFormClass related to populating the files table
    """

    """
    functions for building and displaying pyqt.
    """

    def init_and_populate(self):
        """
        Helper, initialize and populate items in analysis tab widget
        """
        self.check_idb_uploaded()
        if self.file_exists:
            self.make_list_api_call("Matches")
            self.list_widget.enable_tab_bar()
            self.list_widget.binary_id = self.hashes["version_sha1"]
        else:
            self.process_file_nonexistent()
    #
    # methods for connecting pyqt signals
    #

    def populate_file_notes(self, list_items):
        """Populates the File list 'Notes' tab with recieved notes"""
        notes = []
        # start adding note information
        for note in list_items:
            notes.append(
                FileSimpleTextNode(
                    node_id=note.id,
                    text=(
                        f"{note.note}\n"
                        f"    User:{note.username}\n"
                        f"    Create time: {note.create_time}"
                    ),
                )
            )
        self.update_list_widget(self.list_widget, notes, "Notes")

    def populate_file_tags(self, list_items):
        """Populates the File list 'Tags' tab with recieved tags"""
        tags = []
        for tag in list_items:
            tags.append(
                FileSimpleTextNode(
                    node_id=tag.id,
                    text=tag.name,
                )
            )
        self.update_list_widget(self.list_widget, tags, "Tags")

    def populate_file_matches(self, list_items):
        """Populates the File list 'Matches' tab with recieved matches"""
        matches = []
        for match in list_items:
            if match["sha1"] != self.hashes["version_sha1"]:
                filename = f"sha1: {match['sha1']}"
            else:
                filename = f"Current file - sha1: {match['sha1']}"

            matches.append(
                FileSimpleTextNode(
                    text=(
                        f"{filename},\n   Max Similarity: {match['max_similarity']}"
                    )
                )
            )
        self.list_widget.list_widget.clear()
        self.update_list_widget(self.list_widget, matches, "Matches")

    def make_list_api_call(self, list_type):
        """Make api call and handle exceptions"""
        api_call = None

        if list_type == "Notes":
            api_call = self.ctmfiles.list_file_notes
        elif list_type == "Tags":
            api_call = self.ctmfiles.list_file_tags
            expand_mask = "tags"
        elif list_type == "Matches":
            api_call = self.ctmfiles.list_file_matches
            expand_mask = "matches"

        try:
            if list_type != "Notes":
                response = api_call(
                    binary_id=self.hashes["version_sha1"],
                    expand_mask=expand_mask,
                    no_links=True,
                    async_req=True,
                )
            else:
                response = api_call(
                    binary_id=self.hashes["version_sha1"], no_links=True, async_req=True
                )
            response = response.get()
        except ApiException as exp:
            logger.debug(traceback.format_exc())
            print(f"No {list_type.lower()} could be gathered from File.")
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
            if list_type == "Matches":
                if 200 <= response["status"] <= 299:
                    print(f"{list_type} gathered from File successfully.")
                    self.populate_file_matches(response["resources"])
                else:
                    print(f"Error gathering {list_type}.")
                    print(f"Status Code: {response['status']}")
                    print(f"Error message: {response['errors']}")
                    self.populate_file_matches(list())
                return None
            if 200 <= response.status <= 299:
                print(f"{list_type} gathered from File successfully.")
                if list_type == "Notes":
                    self.populate_file_notes(response.resources)
                elif list_type == "Tags":
                    self.populate_file_tags(response.resources)

    def set_version_sha1(self, sha1):
        """
        Set the hash for "version" sha1
        """
        self.hashes["version_sha1"] = sha1

    def check_idb_uploaded(self):
        """
        Call the api at `get_file` to check for idb's pervious upload.
        If not, check for original binary's pervious upload.
        """
        self.file_exists = False
        read_mask = "sha1,children.*"
        expand_mask = "children"
        try:
            sha1 = self.hashes["loaded_sha1"]
            response = self.ctmfiles.get_file(
                binary_id=sha1,
                no_links=True,
                read_mask=read_mask,
                expand_mask=expand_mask,
                async_req=True
            )
            response = response.get()
        except ApiException as exp:
            logger.debug(traceback.format_exc())
            print(
                "Previous IDB upload match failed. Checking for binary or it's child content files."
            )
            linked_uploaded = self.check_linked_binary_object_exists(read_mask, expand_mask)
            if not linked_uploaded:
                self.set_version_sha1(self.hashes["loaded_sha1"])
                for error in json.loads(exp.body).get("errors"):
                    logger.info(error["reason"])
                    print(f"{error['reason']}: {error['message']}")
        except Exception as exp:
            logger.debug(traceback.format_exc())
            print("Unknown Error occurred")
            print(f"<{exp.__class__}>: {str(exp)}")
            return None
        else:
            if 200 <= response.status <= 299:
                print("IDB uploaded previously.")
                self.file_exists = True
                self.list_widget.enable_tab_bar()
                self.set_version_sha1(response.resource.sha1)

    def check_linked_binary_object_exists(self, read_mask, expand_mask):
        """
        Call the api at `get_file` to check for the real IDB-linked binary's
          pervious upload with IDA hash md5.
        If not, check for any content file children in response.
        If content children, return the sha1 of the most recent.
        """
        try:
            print("ida md5:", self.hashes["ida_md5"])
            md5 = self.hashes["ida_md5"]
            response = self.ctmfiles.get_file(
                binary_id=md5,
                no_links=True,
                read_mask=read_mask,
                expand_mask=expand_mask,
                async_req=True
            )
            response = response.get()
        except ApiException as exp:
            logger.debug(traceback.format_exc())
            print("IDB-linked binary nor any IDBs from this binary uploaded yet.")
            for error in json.loads(exp.body).get("errors"):
                logger.info(error["reason"])
                print(f"{error['reason']}: {error['message']}")
            return False
        except Exception as exp:
            logger.debug(traceback.format_exc())
            print("Unknown Error occurred")
            print(f"<{exp.__class__}>: {str(exp)}")
            return False
        # content_child = self.get_latest_content_child(response.resource)
        # if content_child:
        #     self.set_version_sha1(content_child.sha1)
        #     self.file_exists = True
        #     return True
        # elif self.verify_linked_binary_sha1(response.resource):
        #     self.set_version_sha1(response.resource.sha1)
        #     self.file_exists = True
        #     return True

        # REMOVE THESE LINES ONCE THE ABOVE IS UNCOMMENTED
        if response.resource.md5 and response.resource.sha256:
            print("original md5:", response.resource.md5)
            print("original sha256:", response.resource.sha256)
            if self.verify_linked_binary_sha1(response.resource):
                self.set_version_sha1(response.resource.sha1)
                self.file_exists = True
                return True
        return False

    def get_latest_content_child(self, file):
        """
        Check the file object for any content children.
        If they exist, return the most recent one.
        """
        if file.get("children", None):
            return file.children[-1]
        return None

    def verify_linked_binary_sha1(self, file):
        """
        Verify the sha1 of the returned file is not a hash of the md5 + sha256.
        If it is, it will not have any genomics attached.
        """
        sha1_prestring = (file.md5 + file.sha256).encode('utf-8')
        sha1 = hashlib.sha1(sha1_prestring).hexdigest()

        try:
            response = self.ctmfiles.get_file(
                binary_id=sha1, no_links=True, async_req=True
            )
            response = response.get()
        except ApiException:
            logger.debug(traceback.format_exc())
            print("Linked binary previously uploaded.")
            return True
        except Exception as exp:
            logger.debug(traceback.format_exc())
            print("Unknown Error occurred")
            print(f"<{exp.__class__}>: {str(exp)}")
        return False

    def get_linked_binary_and_children(self, file):
        """
        Return a list of children files linked to the original binary.
        """
        for parent in file.parents:
            if parent.sha1 == self.hashes["ida_md5"]:
                self.content_versions["Original File"] = parent.sha1
        for child in file.children:
            self.content_versions[child.service_data.task_trace.timestamp] = child.sha1

    def process_file_nonexistent(self):
        """Disables FileListWidget's tabbar and displays FileNotFound popup."""
        self.list_widget.disable_tab_bar()
        self.files_buttons_layout.show_file_not_found_popup()

    # def create_temp_file(self, file_path):
    #     """
    #     Package a file into a temp file for upload.
    #     """
    #     temp_filename = "temp_" + os.path.basename(file_path)
    #     temp_path = os.path.join(os.getcwd(), temp_filename)
    #     with open(temp_path, "wb") as outfile, open(file_path, "rb") as infile:
    #         shutil.copyfileobj(infile, outfile)
    #     return temp_path

    def upload_idb(self, skip_unpack):
        idb = create_idb_file()
        self.upload_file(idb, skip_unpack)

    def upload_binary(self, skip_unpack):
        try:
            binary_path = get_linked_binary_expected_path()
        except Exception:
            print(f"Binary file not found at path: {get_linked_binary_expected_path()}.")
            print("To upload this binary, move to this file path.")
        self.upload_file(binary_path, skip_unpack)

    def upload_file(self, file_path, skip_unpack):
        """Upload file button click behavior

        POST to upload_file
        """
        api_call = self.ctmfiles.upload_file
        tags = []
        notes = []
        # temp_file_path = self.create_temp_file(file_path)
        filedata = encode_file(file_path)

        try:
            response = api_call(
                filedata=[filedata],
                password="",
                tags=tags,
                notes=notes,
                skip_unpack=skip_unpack,
                no_links=True,
                b64=True,
                async_req=True,
            )
            response = response.get()
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
            # exit if this call fails so user can retry
            # (this func always returns None anyway)
            return None
        else:
            if response.status == 200:
                self.file_exists = True
                # TODO: Change this to the sha1 of the parent RegularFile
                self.hashes["version_sha1"] = response.resources[0].sha1
                self.list_widget.binary_id = self.hashes["version_sha1"]
                self.list_widget.list_widget_tab_bar.setTabEnabled(0, True)
                self.list_widget.list_widget_tab_bar.setTabEnabled(1, True)
                self.list_widget.list_widget_tab_bar.setTabEnabled(2, True)
                print("File previously uploaded and available.")
                print("File hash:", self.hashes["version_sha1"])
            elif response.status >= 201 and response.status <= 299:
                self.file_exists = True
                # TODO: Change this to the sha1 of the parent RegularFile
                self.hashes["version_sha1"] = response.resources[0].sha1
                self.list_widget.binary_id = self.hashes["version_sha1"]
                self.list_widget.list_widget_tab_bar.setTabEnabled(0, True)
                self.list_widget.list_widget_tab_bar.setTabEnabled(1, True)
                self.list_widget.list_widget_tab_bar.setTabEnabled(2, True)
                print("Upload Successful.")
        # finally:
        #     os.remove(temp_file_path)

    def update_list_widget(
        self,
        widget,
        list_items,
        list_type,
    ):
        """Handle updating the list widget"""
        widget.refresh_list_data(list_items, list_type)

        if "Matches" not in widget.label.text():
            widget.create_button.setEnabled(True)
        else:
            widget.create_button.setEnabled(False)
        widget.update()
