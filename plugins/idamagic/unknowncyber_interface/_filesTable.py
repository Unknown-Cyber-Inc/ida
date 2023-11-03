"""
Methods and classes in the MAGICPluginFormClass related to populating the files table.
"""

import logging
import json
import os
import traceback

from cythereal_magic.rest import ApiException
from ..helpers import (
    hash_file,
    parse_binary,
    getUnixFileType,
    encode_loaded_file,
    get_file_architecture,
    get_input_file_path,
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
        self.check_file_exists()
        if self.file_exists:
            self.make_list_api_call("Matches")

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
            if match["sha1"] != self.sha1:
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
                    binary_id=self.sha1,
                    expand_mask=expand_mask,
                    no_links=True,
                    async_req=True,
                )
            else:
                response = api_call(
                    binary_id=self.sha1, no_links=True, async_req=True
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
            else:
                print(f"Error gathering {list_type}.")
                print(f"Status Code: {response.status}")
                print(f"Error message: {response.errors}")
        if list_type == "Notes":
            self.populate_file_notes(response.resources)
        elif list_type == "Tags":
            self.populate_file_tags(response.resources)

    def check_file_exists(self):
        """Call the api at `get_file`

        Return the sha1 of the file if it exists.
        """
        try:
            self.sha1 = hash_file()
            response = self.ctmfiles.get_file(
                binary_id=self.sha1, no_links=True, async_req=True
            )
            response = response.get()
        except ApiException as exp:
            logger.debug(traceback.format_exc())
            print("File GET request failed.")
            self.file_exists = False
            for error in json.loads(exp.body).get("errors"):
                logger.info(error["reason"])
                print(f"{error['reason']}: {error['message']}")
            self.process_file_nonexistent()
            return None
        except Exception as exp:
            logger.debug(traceback.format_exc())
            print("Unknown Error occurred")
            print(f"<{exp.__class__}>: {str(exp)}")
            # exit if this call fails so user can retry
            # (this func always returns None anyway)
            return None
        else:
            if 200 <= response.status <= 299:
                print("File uploaded previously.")
                self.file_exists = True
                self.list_widget.enable_tab_bar()
            elif response.status == 404:
                print("File not yet uploaded.")
                self.file_exists = False
                self.process_file_nonexistent()
                return None
            elif response.status == 403:
                print("Access denied to existing file.")
                # setting file_exists to false so that they are not given
                # any of the values for that file (notes, tags, etc.)
                self.file_exists = False
                self.process_file_nonexistent()
                return None
            else:
                print("Error with file GET.")
                print(f"Status Code: {response.status}")
                print(f"Error message: {response.errors}")
                return None

    def process_file_nonexistent(self):
        """Disables FileListWidget's tabbar and displays FileNotFound popup."""
        self.list_widget.disable_tab_bar()
        self.files_buttons_layout.show_file_not_found_popup()

    def upload_idb(self):
        idb = create_idb_file()
        self.upload_file(idb, skip_unpack=None)

    def upload_binary(self, skip_unpack):
        try:
            binary_path = get_input_file_path()
        except Exception:
            print(f"Binary file not found at path: {get_input_file_path()}.")
            print("To upload this binary, move to this file path.")
        self.upload_file(binary_path, skip_unpack)

    def upload_file(self, file_path, skip_unpack):
        """Upload file button click behavior

        POST to upload_file
        """
        api_call = self.ctmfiles.upload_file
        tags = []
        notes = []
        filedata = encode_loaded_file(file_path)

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
                self.sha1 = response.resources[0].sha1
                self.list_widget.list_widget_tab_bar.setTabEnabled(0, True)
                self.list_widget.list_widget_tab_bar.setTabEnabled(1, True)
                self.list_widget.list_widget_tab_bar.setTabEnabled(2, True)
                print("File previously uploaded and available.")
            elif response.status >= 201 and response.status <= 299:
                self.file_exists = True
                self.sha1 = response.resources[0].sha1
                self.list_widget.list_widget_tab_bar.setTabEnabled(0, True)
                self.list_widget.list_widget_tab_bar.setTabEnabled(1, True)
                self.list_widget.list_widget_tab_bar.setTabEnabled(2, True)
                print("Upload Successful.")
            else:
                print("Error During Upload.")
                print(f"Status Code: {response.status}")

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
