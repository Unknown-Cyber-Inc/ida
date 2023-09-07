"""
Methods and classes in the MAGICPluginFormClass related to populating the files table.
"""

import logging
import json
import os
import traceback

import ida_nalt
import ida_loader
import hashlib
import base64

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

    def init_and_populate_tabs(self):
        """
        Helper, initialize and populate items in analysis tab widget
        """

        # create the original file upload button and skip_unpack checkbox
        self.skip_unpack_check = QtWidgets.QCheckBox("Skip Unpack")
        self.original_upload_button = QtWidgets.QPushButton("Submit File")
        self.original_upload_button.setEnabled(True)
        self.original_upload_button.clicked.connect(
            self.upload_file_button_click
        )

        # create layout to hold original upload button, password, and checkbox
        self.file_inputs_layout = QtWidgets.QHBoxLayout()
        self.file_inputs_layout.addWidget(self.skip_unpack_check)
        self.file_inputs_layout.addWidget(self.original_upload_button)

        # create the binary upload buttons
        self.binary_upload_button = QtWidgets.QPushButton(
            "Submit disassembled binary"
        )
        self.binary_upload_button.setEnabled(True)
        self.binary_upload_button.clicked.connect(
            self.upload_disassembled_click
        )

        # TABS FOR FILE PAGE
        # original file upload tab
        self.file_upload_tab = QtWidgets.QWidget()
        self.file_upload_tab_layout = QtWidgets.QVBoxLayout(
            self.file_upload_tab
        )
        self.file_upload_tab_layout.addLayout(self.file_inputs_layout)

        # binary upload tab
        self.binary_upload_tab = QtWidgets.QWidget()
        self.binary_upload_tab_layout = QtWidgets.QVBoxLayout(
            self.binary_upload_tab
        )
        self.binary_upload_tab_layout.addWidget(self.binary_upload_button)

        # add tabs to sub upload_tab_table
        self.upload_tabs = QtWidgets.QTabWidget()
        self.upload_tabs.addTab(self.file_upload_tab, "Original File")
        self.upload_tabs.addTab(
            self.binary_upload_tab, "Disassembled"
        )
        # set layout for sub upload tab table
        self.upload_tabs_layout = QtWidgets.QVBoxLayout(
            self.upload_tabs
        )
        self.upload_tabs.setLayout(self.upload_tabs_layout)

        # ---------------------------------------------------------------------------
        # populate this tab similar to populate_files_view
        # it's less confusing if individual tab population is not in its own function

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
            matches.append(
                FileSimpleTextNode(
                    text=match.filename,
                )
            )
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

        try:
            if list_type == "Tags":
                ctmr = api_call(binary_id=self.sha1, expand_mask=expand_mask, no_links=True)
            else:
                ctmr = api_call(binary_id=self.sha1, no_links=True)
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
                if ctmr["status"] >= 200 and ctmr["status"] <= 299:
                    print(f"{list_type} gathered from File successfully.")
                    self.populate_file_matches(ctmr["resources"])
                else:
                    print(f"Error gathering {list_type}.")
                    print(f"Status Code: {ctmr['status']}")
                    print(f"Error message: {ctmr['errors']}")
                return None
            if ctmr.status >= 200 and ctmr.status <= 299:
                print(f"{list_type} gathered from File successfully.")
            else:
                print(f"Error gathering {list_type}.")
                print(f"Status Code: {ctmr.status}")
                print(f"Error message: {ctmr.errors}")
        if list_type == "Notes":
            self.populate_file_notes(ctmr.resources)
        elif list_type == "Tags":
            self.populate_file_tags(ctmr.resources)
        elif list_type == "Matches":
            self.populate_file_matches(ctmr.resources)

    def check_file_exists(self, binary_id):
        """Call the api at `get_file`

        Return the sha1 of the file if it exists.
        """
        try:
            response = self.ctmfiles.get_file(binary_id=binary_id, no_links=True)
        except ApiException as exp:
            logger.debug(traceback.format_exc())
            print("File GET request failed.")
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
                print("File already exists.")
                resource = response.resource
                self.file_exists = True
                self.sha1 = resource.sha1
                self.list_widget.list_widget_tab_bar.setTabEnabled(0, True)
                self.list_widget.list_widget_tab_bar.setTabEnabled(1, True)
                self.list_widget.list_widget_tab_bar.setTabEnabled(2, True)
            elif response.status == 404:
                print("File does not exist.")
                self.file_exists = False
                self.sha1 = hash_file()
                self.list_widget.list_widget_tab_bar.setTabEnabled(0, False)
                self.list_widget.list_widget_tab_bar.setTabEnabled(1, False)
                self.list_widget.list_widget_tab_bar.setTabEnabled(2, False)
                return None
            elif response.status == 403:
                print("Access denied to existing file.")
                self.sha1 = response.errors.parameters
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

    def upload_file_button_click(self):
        """Upload file button click behavior

        POST to upload_file
        """
        api_call = self.ctmfiles.upload_file
        tags = []
        notes = []
        skip_unpack = self.skip_unpack_check.isChecked()
        filedata = self.encode_loaded_file()

        try:
            return_data, status, _ = api_call(
                skip_unpack=skip_unpack,
                filedata=[filedata],
                password="",
                tags=tags,
                notes=notes,
                no_links=True,
                b64=True,
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
            # exit if this call fails so user can retry
            # (this func always returns None anyway)
            return None
        else:
            if status >= 200 and status <= 299:
                self.file_exists = True
                self.sha1 = hash_file()
                self.list_widget.list_widget_tab_bar.setTabEnabled(0, True)
                self.list_widget.list_widget_tab_bar.setTabEnabled(1, True)
                self.list_widget.list_widget_tab_bar.setTabEnabled(2, True)
                # self.make_list_api_call("Matches")
                print(str(return_data))
                print("Upload Successful.")
            else:
                print("Error gathering Procedures.")
                print(f"Status Code: {status}")

    def upload_disassembled_click(self):
        """Upload editted binaries button behavior"""
        # from ..helpers import get_input_file_path
        # path = get_input_file_path()
        # file = ida_loader.base2file(path)

        # api_call = self.ctmfiles.upload_file
        # skip_unpack = self.skip_unpack_check.isChecked()
        # tags = []
        # notes = []
        # try:
        #     return_data, status, _ = api_call(
        #         skip_unpack=skip_unpack,
        #         filedata=[file],
        #         password="",
        #         tags=tags,
        #         notes=notes,
        #         no_links=True,
        #     )
        # except ApiException as exp:
        #     logger.debug(traceback.format_exc())
        #     print("No procedures could be gathered.")
        #     for error in json.loads(exp.body).get("errors"):
        #         logger.info(error["reason"])
        #         print(f"{error['reason']}: {error['message']}")
        # except Exception as exp:
        #     logger.debug(traceback.format_exc())
        #     print("Unknown Error occurred")
        #     print(f"<{exp.__class__}>: {str(exp)}")
        #     # exit if this call fails so user can retry
        #     # (this func always returns None anyway)
        #     return None
        # else:
        #     if status >= 200 and status <= 299:
        #         self.file_exists = True
        #         self.sha1 = hash_file()
        #         self.list_widget.list_widget_tab_bar.setTabEnabled(0, True)
        #         self.list_widget.list_widget_tab_bar.setTabEnabled(1, True)
        #         self.list_widget.list_widget_tab_bar.setTabEnabled(2, True)
        #         # self.make_list_api_call("Matches")
        #         print(str(return_data))
        #         print("Upload Successful.")
        #     else:
        #         print("Error gathering Procedures.")
        #         print(f"Status Code: {status}")
        parse_binary()
        print("Attempted to upload editted disassembled binary")

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
