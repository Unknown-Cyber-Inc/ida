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
from ..widgets import FileSimpleTextNode, StatusPopup
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
            self.list_widget.binary_id = self.hashes["ida_md5"]
        else:
            self.process_file_nonexistent()
    #
    # methods for connecting pyqt signals
    #

    def populate_file_notes(self, list_items):
        """Populates the File list 'Notes' tab with recieved notes"""
        print("POPULATING FILE NOTES FOR BINARY WITH HASH:", self.hashes["ida_md5"])
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
        self.update_list_widget(self.list_widget, notes)

    def populate_file_tags(self, list_items):
        """Populates the File list 'Tags' tab with recieved tags"""
        print("POPULATING FILE TAGS FOR BINARY WITH HASH:", self.hashes["ida_md5"])
        tags = []
        for tag in list_items:
            tags.append(
                FileSimpleTextNode(
                    node_id=tag.id,
                    text=tag.name,
                )
            )
        self.update_list_widget(self.list_widget, tags)

    def populate_file_matches(self, list_items):
        """Populates the File list 'Matches' tab with recieved matches"""
        print("POPULATING FILE MATCHES FOR HASH:", self.hashes["version_hash"])
        matches = []
        for match in list_items:
            if match["sha1"] != self.hashes["version_hash"]:
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
        self.update_list_widget(self.list_widget, matches)

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
            if list_type == "Tags":
                response = api_call(
                    binary_id=self.hashes["ida_md5"],
                    expand_mask=expand_mask,
                    no_links=True,
                    async_req=True,
                )
            elif list_type == "Matches":
                response = api_call(
                    binary_id=self.hashes["version_hash"],
                    expand_mask=expand_mask,
                    no_links=True,
                    async_req=True,
                )
            else:
                response = api_call(
                    binary_id=self.hashes["ida_md5"], no_links=True, async_req=True
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

    def set_version_hash(self, new_hash):
        """
        Set the hash for "version".
        """
        self.hashes["version_hash"] = new_hash

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
            self.file_exists = False
            linked_uploaded = self.check_linked_binary_object_exists(False)
            if not linked_uploaded:
                self.set_version_hash(self.hashes["loaded_sha1"])
                self.list_widget.disable_tab_bar()
                for error in json.loads(exp.body).get("errors"):
                    logger.info(error["reason"])
                    print(f"{error['reason']}: {error['message']}")
        except Exception as exp:
            logger.debug(traceback.format_exc())
            print("Unknown Error occurred")
            print(f"<{exp.__class__}>: {str(exp)}")
            self.list_widget.disable_tab_bar()
            return None
        else:
            if 200 <= response.status <= 299:
                print("IDB uploaded previously.")
                self.file_exists = True
                self.list_widget.enable_tab_bar()
                original_exists = self.check_linked_binary_object_exists(True)
                if not original_exists:
                    self.set_version_hash(response.resource.sha1)

    def check_linked_binary_object_exists(self, idb_uploaded):
        """
        Call the api at `get_file` to check for the real IDB-linked binary's
          pervious upload with IDA hash md5.
        If not, check for any content file children in response.
        If content children, return the sha1 of the most recent.
        """
        read_mask = "*,children.*"
        expand_mask = "children"
        try:
            response = self.ctmfiles.get_file(
                binary_id=self.hashes["ida_md5"],
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
        print("IDB-Linked Binary Found. Checking for content-children.")
        self.populate_content_versions(response.resource)
        if not idb_uploaded:
            content_child_sha1 = list(self.content_versions.items())[-1][-1]
            if content_child_sha1:
                count = self.files_buttons_layout.dropdown.count()
                self.files_buttons_layout.dropdown.setCurrentIndex(count-1)
                self.set_version_hash(content_child_sha1)
                self.file_exists = True
                return True
            elif self.verify_linked_binary_sha1(response.resource):
                print("No content-children found. Updating set_version_hash to linked-binary's")
                self.set_version_hash(response.resource.sha1)
                self.file_exists = True
                return True
            return False

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

    def populate_content_versions(self, file):
        """
        Takes a file object in the form of an api response.resource from `get_file`.
        If this file object has children files with a sha1, timestamp, and service
          name of "<SOME NAME FOR IDA IDB CONTENTS>", add it to the `content_versions`
          dict.
        Call `populate_versions` to process `content_versions` and add items to the
          dropdown.
        """
        self.content_versions["Original File"] = file.sha1
        for child in file.children:
            if child.get('sha1'):
                sha1 = child.get('sha1')
                service_data = child.get("service_data", {})
                task_trace = service_data.get("task_trace", {})
                timestamp = task_trace.get("timestamp", {})
                if sha1 and timestamp:
                    print("GOLDEN CHILD FOUND: ", child)
                    self.content_versions[timestamp] = sha1
        self.populate_dropdown()

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
        print("Attempting IDB file upload.")
        self.upload_file(idb, skip_unpack)

    def upload_binary(self, skip_unpack):
        try:
            binary_path = get_linked_binary_expected_path()
        except Exception:
            print(f"Binary file not found at path: {get_linked_binary_expected_path()}.")
            print("To upload this binary, move to this file path.")
        print("Attempting binary file upload.")
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
                self.set_version_hash(response.resources[0].sha1)
                self.hashes["upload_hash"] = response.resources[0].sha1
                self.status_button.setEnabled(True)
                self.set_status_label("pending")
                self.list_widget.list_widget_tab_bar.setTabEnabled(0, True)
                self.list_widget.list_widget_tab_bar.setTabEnabled(1, True)
                self.list_widget.list_widget_tab_bar.setTabEnabled(2, True)
                print("File previously uploaded and available.")
            elif response.status >= 201 and response.status <= 299:
                self.file_exists = True
                self.set_version_hash(response.resources[0].sha1)
                self.hashes["upload_hash"] = response.resources[0].sha1
                self.status_button.setEnabled(True)
                self.set_status_label("pending")
                self.list_widget.list_widget_tab_bar.setTabEnabled(0, True)
                self.list_widget.list_widget_tab_bar.setTabEnabled(1, True)
                self.list_widget.list_widget_tab_bar.setTabEnabled(2, True)
                print("Upload Successful.")
        # finally:
        #     os.remove(temp_file_path)

    def get_file_status(self):
        """Get the status of an uploaded file."""
        read_mask = "status,pipeline"
        try:
            response = self.ctmfiles.get_file(
                binary_id=self.hashes["upload_hash"],
                no_links=True,
                read_mask=read_mask,
                async_req=True
            )
            response = response.get()
        except ApiException as exp:
            logger.debug(traceback.format_exc())
            for error in json.loads(exp.body).get("errors"):
                logger.info(error["reason"])
                print(f"{error['reason']}: {error['message']}")
            self.set_status_label("api failure")
            return None
        except Exception as exp:
            logger.debug(traceback.format_exc())
            print("Unknown Error occurred")
            print(f"<{exp.__class__}>: {str(exp)}")
            self.set_status_label("api failure")
            return None
        else:
            if 200 <= response.status <= 299:
                self.set_status_label(response.resource.status)
                self.status_popup = StatusPopup(response.resource, self)
                self.status_popup.show()

    def update_list_widget(
        self,
        widget,
        list_items,
    ):
        """Handle updating the list widget"""
        widget.refresh_list_data(list_items)
        widget.update()
