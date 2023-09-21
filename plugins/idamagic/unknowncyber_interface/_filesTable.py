"""
Methods and classes in the MAGICPluginFormClass related to populating the files table.
"""

import logging
import json
import os
import traceback
from unittest import result

import ida_nalt
import ida_loader
import ida_kernwin
import hashlib
import base64
import idaapi
import idc
import idautils
from pprint import pprint
import tempfile

from cythereal_magic.rest import ApiException
from PyQt5 import QtWidgets, Qt

from ..helpers import hash_file, parse_binary

IDA_LOGLEVEL = str(os.getenv("IDA_LOGLEVEL", "INFO")).upper()

logger = logging.getLogger(__name__)


class FileTableItem(Qt.QStandardItem):
    """Generic form of items on the Files lists.

    Contains default features for all list items based on QStandardItem class.
    """

    def __init__(self):
        super().__init__()
        self.setEditable(False)


class FileSimpleTextNode(FileTableItem):
    """Node which contains only simple text information"""

    def __init__(
        self, node_id="", text="", sha1="", binary_id="", uploaded=False
    ):
        super().__init__()
        self.setText(text)
        self.text = text
        self.node_id = node_id
        self.sha1 = sha1
        self.binary_id = binary_id
        self.uploaded = uploaded


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

        self.upload_button = QtWidgets.QPushButton("Upload File")
        self.upload_button.clicked.connect(self.main_upload_button_click)

        self.check_file_exists(self.sha256)
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
                    text=note.note,
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

    def check_file_exists(self, binary_id):
        """Call the api at `get_file`

        Return the sha1 of the file if it exists.
        """
        try:
            response = self.ctmfiles.get_file(
                binary_id=binary_id, no_links=True, async_req=True
            )
            response = response.get()
        except ApiException as exp:
            logger.debug(traceback.format_exc())
            print("File GET request failed.")
            print("File does not exist")
            self.file_exists = False
            for error in json.loads(exp.body).get("errors"):
                logger.info(error["reason"])
                print(f"{error['reason']}: {error['message']}")
            self.sha1 = hash_file()
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
                print("File already exists.")
                # resource = response.resource
                self.file_exists = True
                # self.sha1 = resource.sha1
                self.list_widget.list_widget_tab_bar.setTabEnabled(0, True)
                self.list_widget.list_widget_tab_bar.setTabEnabled(1, True)
                self.list_widget.list_widget_tab_bar.setTabEnabled(2, True)
            elif response.status == 404:
                print("File does not exist.")
                self.file_exists = False
                # self.sha1 = hash_file()
                self.list_widget.list_widget_tab_bar.setTabEnabled(0, False)
                self.list_widget.list_widget_tab_bar.setTabEnabled(1, False)
                self.list_widget.list_widget_tab_bar.setTabEnabled(2, False)
                return None
            elif response.status == 403:
                print("Access denied to existing file.")
                # self.sha1 = response.errors.parameters
                # setting file_exists to false so that they are not given
                # any of the values for that file (notes, tags, etc.)
                self.file_exists = False
                return None
            else:
                print("Error with file GET.")
                print(f"Status Code: {response.status}")
                print(f"Error message: {response.errors}")
                return None
            return response.resource.sha1

    def get_file_location(self):
        """Get the user's input file.

        Move to helpers.py
        """
        # example return: /home/chris/unknowncyber/development/data/file
        file_path = ida_nalt.get_input_file_path()

        return file_path

    def calculate_file_sha1(self):
        """Hash the file and return the hexdigest of its sha1

        Move to helpers.py
        """
        file_path = self.get_file_location()
        sha1 = hashlib.sha1()

        with open(file_path, "rb") as file:
            while True:
                data = file.read(4096)
                if not data:
                    break
                sha1.update(data)
        return sha1.hexdigest()

    def encode_loaded_file(self):
        """Encode the currenly loaded file into base64

        Move to helpers.py
        """
        with open(self.get_file_location(), "rb") as file:
            file_bytes = base64.b64encode(file.read())
        return file_bytes

    def encode_disassembled_file(self, path):
        """Encode the disassembled file into base64"""
        with open(path, "rb") as file:
            file_bytes = base64.b64encode(file.read())
        return file_bytes

    def main_upload_button_click(self):
        """Main upload button click behavior

        Renders a QMessageBox with all upload buttons
        """
        upload_popup = QtWidgets.QMessageBox()
        upload_popup.setWindowTitle("Upload")
        upload_popup.setText("Select the type of upload to perform.")

        # File upload button
        file_upload_button = upload_popup.addButton(
            "File", QtWidgets.QMessageBox.ActionRole
        )
        file_upload_button.setEnabled(True)
        file_upload_button.clicked.connect(self.upload_file_button_click)
        # Disassembly upload button
        binary_upload_button = upload_popup.addButton(
            "Disassembly", QtWidgets.QMessageBox.ActionRole
        )
        binary_upload_button.setEnabled(True)
        binary_upload_button.clicked.connect(
            self.upload_disassembled_click
        )

        upload_popup.exec_()

    def upload_file_button_click(self):
        """Upload file button click behavior

        POST to upload_file
        """
        api_call = self.ctmfiles.upload_file
        tags = []
        notes = []
        filedata = self.encode_loaded_file()

        try:
            response = api_call(
                filedata=[filedata],
                password="",
                tags=tags,
                notes=notes,
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

    def upload_database_click(self):
        """Upload database file"""
        from ..helpers import get_input_file_path

        input_path = get_input_file_path()
        ida_dir = os.path.dirname(input_path)
        file = ida_loader.save_database(ida_dir, ida_loader.DBFL_BAK)

    def upload_disassembled_click(self):
        """Upload editted binaries button behavior"""
        zip_path = parse_binary()
        api_call = self.ctmfiles.upload_disassembly
        filetype = "archive"

        try:
            _, status, _ = api_call(
                filedata=zip_path,
                filetype=filetype,
                no_links=True,
                binary_id=self.sha1,
            )
        except ApiException as exp:
            logger.debug(traceback.format_exc())
            print("Disassembly upload failed.")
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
            if 200 <= status <= 299:
                self.file_exists = True
                self.sha1 = hash_file()
                self.list_widget.list_widget_tab_bar.setTabEnabled(0, True)
                self.list_widget.list_widget_tab_bar.setTabEnabled(1, True)
                self.list_widget.list_widget_tab_bar.setTabEnabled(2, True)
                print("Upload Successful.")
            else:
                print("Error uploading disassembled binary.")
                print(f"Status Code: {status}")

    def update_list_widget(
        self,
        widget,
        list_items,
        list_type,
    ):
        """Handle updating the list widget"""
        widget.refresh_list_data(list_items, list_type)

        if "MATCHES" not in widget.label.text():
            widget.create_button.setEnabled(True)
        else:
            widget.create_button.setEnabled(False)
        widget.update()
