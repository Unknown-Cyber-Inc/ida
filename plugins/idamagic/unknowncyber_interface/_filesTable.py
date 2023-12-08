"""
Methods and classes in the MAGICPluginFormClass related to populating the files table.
"""

import logging
import os

import traceback
import hashlib

from cythereal_magic.rest import ApiException
from ..helpers import (
    encode_file,
    get_disassembly_hashes,
    get_linked_binary_expected_path,
    parse_binary,
    process_api_exception,
    process_regular_exception,
)
from ..widgets import FileSimpleTextNode, StatusPopup, ErrorPopup, GenericPopup
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
        if self.check_env_vars():
            self.check_idb_uploaded()
            if self.main_interface.get_file_exists():
                self.list_widget.enable_tab_bar()
                self.list_widget.binary_id = self.main_interface.hashes["ida_md5"]
            else:
                self.process_file_nonexistent()

    #
    # methods for connecting pyqt signals
    #

    def check_env_vars(self):
        """Make an API call to check the validity of the API vars."""
        try:
            sha1 = self.main_interface.hashes["loaded_sha1"]
            response = self.ctmfiles.get_file(
                binary_id=sha1,
                no_links=True,
                explain=True,
                async_req=True,
            )
            response = response.get()
        except ApiException as exc:
            info_msgs = []
            if "Unauthorized" in str(exc):
                info_msgs = [
                    "The `MAGIC_API_KEY` env var is invalid."
                    + " Correct and reload.\n"
                ]
            else:
                info_msgs = [
                    "An unknown error has occured. Please check host domain, "
                    + "port, and api key below.\n",
                    str(exc),
                ]
            process_regular_exception(exc, False, info_msgs)
            return None
        except Exception as exc:
            info_msgs = []
            if "NameResolutionError" in  str(exc):
                info_msgs = [
                    "The `MAGIC_API_HOST` env var's domain is not set correctly."
                    + " Correct and reload.\n",
                ]
            elif "NewConnectionError" in str(exc):
                info_msgs = [
                    "The `MAGIC_API_HOST` env var's port is not set correctly."
                    + " Correct and reload.\n"
                ]
            else:
                info_msgs = [
                    "An unknown error has occured. Please check host domain, "
                    + "port, and api key below.\n",
                    str(exc),
                ]
            process_regular_exception(exc, False, info_msgs)
            return None
        else:
            return True

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
        self.update_list_widget(self.list_widget, notes)

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
        self.update_list_widget(self.list_widget, tags)

    def populate_file_matches(self, list_items):
        """Populates the File list 'Matches' tab with recieved matches"""
        matches = []
        for match in list_items:
            if match["sha1"] != self.main_interface.hashes["version_hash"]:
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
        self.list_widget.pagination_selector.page_item_total = len(list_items)
        self.list_widget.pagination_selector.update_next_button()
        self.list_widget.list_widget.clear()
        self.update_list_widget(self.list_widget, matches)

    def make_list_api_call(self, list_type, page=1):
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
                    binary_id=self.main_interface.hashes["ida_md5"],
                    expand_mask=expand_mask,
                    no_links=True,
                    async_req=True,
                )
            elif list_type == "Matches":
                response = api_call(
                    binary_id=self.main_interface.hashes["version_hash"],
                    expand_mask=expand_mask,
                    page_count=page,
                    page_size=10,
                    no_links=True,
                    async_req=True,
                )
            else:
                response = api_call(
                    binary_id=self.main_interface.hashes["ida_md5"], no_links=True, async_req=True
                )
            response = response.get()
        except ApiException as exc:
            info_msgs = ["No " + list_type.lower() + " could be gathered from File."]
            if list_type == "Matches":
                process_api_exception(exc, True, info_msgs)
            else:
                process_api_exception(exc, False, info_msgs)
            if list_type == "Matches":
                self.populate_file_matches(list())
        except Exception as exc:
            process_regular_exception(exc, False, [str(exc)])
            return None
        else:
            if list_type == "Matches":
                if 200 <= response["status"] <= 299:
                    self.populate_file_matches(response["resources"])
            elif list_type == "Notes":
                self.populate_file_notes(response.resources)
            elif list_type == "Tags":
                self.populate_file_tags(response.resources)

    def set_version_hash(self, new_hash):
        """
        Set the hash for "version".
        """
        self.main_interface.hashes["version_hash"] = new_hash
        self.main_interface.version_hash_changed()

    def check_idb_uploaded(self):
        """
        Call the api at `get_file` to check for idb's pervious upload.
        If not, check for original binary's pervious upload.
        """
        self.main_interface.set_file_exists(False)
        read_mask = "*,children.*"
        expand_mask = "children"
        try:
            sha1 = self.main_interface.hashes["loaded_sha1"]
            response = self.ctmfiles.get_file(
                binary_id=sha1,
                no_links=True,
                read_mask=read_mask,
                expand_mask=expand_mask,
                async_req=True,
            )
            response = response.get()
        except ApiException as exc:
            print(
                "Previous IDB upload match failed. Checking for binary or it's child content files."
            )
            self.main_interface.set_file_exists(False)
            linked_binary_uploaded = self.check_linked_binary_object_exists(False)
            if not linked_binary_uploaded:
                self.set_version_hash(self.main_interface.hashes["loaded_sha1"])
                self.list_widget.disable_tab_bar()
                process_api_exception(
                    exc,
                    True,
                    ["No upload has occurred for the loaded IDB's linked binary file."
                    + " This includes any disassembly or IDB uploads."]
                )
        except Exception as exc:
            process_regular_exception(exc, False, [str(exc)])
            self.list_widget.disable_tab_bar()
            return None
        else:
            if 200 <= response.status <= 299:
                print("IDB uploaded previously.")
                self.main_interface.set_file_exists(True)
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
                binary_id=self.main_interface.hashes["ida_md5"],
                no_links=True,
                read_mask=read_mask,
                expand_mask=expand_mask,
                async_req=True,
            )
            response = response.get()
        except ApiException as exc:
            info_msgs = [
                "IDB-linked binary nor any IDB/disassemblies from this binary uploaded yet.\n"
            ]
            process_api_exception(exc, True, info_msgs)
            return False
        except Exception as exc:
            process_regular_exception(exc, True, [str(exc)])
            return False
        print("IDB-Linked Binary Found. Checking for content-children.")
        self.populate_content_versions(response.resource)
        if not idb_uploaded:
            # Cast content_versions dict to a list.
            # Select the last item in the list. Select the value, a tuple, of that dict item.
            # Get the second value, a file hash, of that tuple.
            content_child_sha1 = list(self.content_versions.items())[-1][-1][0]
            if content_child_sha1:
                count = self.files_buttons_layout.dropdown.count()
                self.files_buttons_layout.dropdown.setCurrentIndex(count - 1)
                self.set_version_hash(content_child_sha1)
                self.main_interface.set_file_exists(True)
                return True
            elif self.verify_linked_binary_sha1(response.resource):
                print(
                    "No content-children found. Updating set_version_hash to linked-binary's"
                )
                self.set_version_hash(response.resource.sha1)
                self.main_interface.set_file_exists(True)
                return True
            return False

    def verify_linked_binary_sha1(self, file):
        """
        Verify the sha1 of the returned file is not a hash of the md5 + sha256.
        If it is, it will not have any genomics attached.
        """
        sha1_prestring = (file.md5 + file.sha256).encode("utf-8")
        sha1 = hashlib.sha1(sha1_prestring).hexdigest()

        try:
            response = self.ctmfiles.get_file(
                binary_id=sha1, no_links=True, async_req=True
            )
            response = response.get()
        except ApiException:
            logger.debug(traceback.format_exc())
            print("IDB-linked binary previously uploaded.")
            return True
        except Exception as exc:
            process_regular_exception(exc, False, [str(exc)])
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
        self.content_versions["Original File"] = (file.sha1, "content")
        for child in file.children:
            if child.get("sha1"):
                sha1 = child.get("sha1")
                service_name = child.get("service_name", None)
                service_data = child.get("service_data", {})
                timestamp = service_data.get("time", None)
                obj_type = service_data.get("type", None)
                if (
                    timestamp
                    and obj_type == "disasm-contents"
                    and service_name == "alt_juice_handler"
                    or service_name == "webRequestHandler"
                ):
                    self.content_versions[timestamp] = (sha1, "content")
        self.populate_dropdown()

    def process_file_nonexistent(self):
        """Disables FileListWidget's tabbar and displays FileNotFound popup."""
        self.list_widget.disable_tab_bar()
        self.files_buttons_layout.show_file_not_found_popup()

    def upload_idb(self):
        idb = create_idb_file()
        self.upload_file(idb, None, True)

    def upload_binary(self, skip_unpack):
        try:
            binary_path = get_linked_binary_expected_path()
        except Exception:
            GenericPopup(
                f"Binary file not found at path: {get_linked_binary_expected_path()}."
                + "To upload this binary, move to this file path."
            )
        self.upload_file(binary_path, skip_unpack, False)

    def upload_file(self, file_path, skip_unpack, is_idb):
        """Upload file button click behavior

        POST to upload_file
        """
        api_call = self.ctmfiles.upload_file
        tags = []
        notes = []
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
        except ApiException as exc:
            info_msgs = ["Error uploading file.\n"]
            process_api_exception(exc, False, info_msgs)
        except Exception as exc:
            process_regular_exception(exc, False, [str(exc)])
            return None
        else:
            if response.status == 200:
                popup = GenericPopup("File previously uploaded and accessible.")
                popup.exec_()

            elif response.status >= 201 and response.status <= 299:
                response_hash = response.resources[0].sha1
                dropdown = self.main_interface.unknown_plugin.files_buttons_layout.dropdown
                index = dropdown.count()

                if is_idb: # response_hash will belong to the container file object
                    self.main_interface.hashes["upload_container_hashes"][response_hash] = index
                    dropdown_item_data = (response_hash, "container")
                    dropdown.addItem("Session IDB Upload", dropdown_item_data)

                else: # response_hash will belong to the original file object

                    self.main_interface.hashes["upload_content_hashes"][response_hash] = index
                    dropdown_item_data = (response_hash, "content")
                    dropdown.addItem("Session Binary Upload", dropdown_item_data)

                    self.main_interface.set_file_exists(True)
                    self.set_version_hash(response_hash)
                    self.enable_all_list_tabs()

                self.status_button.setEnabled(True)
                self.set_status_label("pending")

                popup = GenericPopup("File upload successful.")
                popup.exec_()
        # finally:
        #     os.remove(temp_file_path)

    def upload_disassembled(self):
        """Upload editted binaries button behavior"""
        # Check if binary is available and generates hashes before any other actions are taken.
        disassembly_hashes = get_disassembly_hashes()
        if (
            not disassembly_hashes
            or not disassembly_hashes["sha1"]
            or not disassembly_hashes["sha512"]
        ):
            return None

        zip_path = parse_binary(
            self.main_interface.hashes,
            orig_dir=None,
            disassembly_hashes=disassembly_hashes,)
        api_call = self.ctmfiles.upload_disassembly

        try:
            response, _, _ = api_call(
                filedata=zip_path,
                no_links=True,
            )
        except ApiException as exc:
            info_msgs = ["Disassembly upload failed.\n"]
            process_api_exception(exc, False, info_msgs)
        except Exception as exc:
            process_regular_exception(exc, False, [str(exc)])
            return None
        else:
            response_hash = response.resource.sha1
            dropdown = self.main_interface.unknown_plugin.files_buttons_layout.dropdown
            index = dropdown.count()
            self.main_interface.hashes["upload_container_hashes"][response_hash] = index
            dropdown_item_data = (response_hash, "container")
            dropdown.addItem("Session Disassembly Upload", dropdown_item_data)

            self.status_button.setEnabled(True)
            self.set_status_label("pending")

            popup = GenericPopup("Disassembly Upload Successful.")
            popup.exec_()

    def get_file_statuses(self):
        """Get the statuses of uploaded files."""
        read_mask = "status,pipeline,sha1,create_time"
        dropdown = self.main_interface.unknown_plugin.files_buttons_layout.dropdown
        content_hashes = self.main_interface.hashes["upload_content_hashes"]
        container_hashes = self.main_interface.hashes["upload_container_hashes"]
        self.containers_to_content_hashes() # convert container -> child content hashes

        any_pending = False
        any_failure = False
        any_success = False
        latest_non_failure = None # Value will be a tuple of (hash, dropdown_index)
        status_objects = []

        if len(content_hashes) > 0:
            new_content_dict = {}
            for content_hash, index in content_hashes.items():
                try:
                    response = self.ctmfiles.get_file(
                        binary_id=content_hash,
                        no_links=True,
                        read_mask=read_mask,
                        async_req=True,
                    )
                    response = response.get()
                except ApiException as exc:
                    info_msgs = [
                        "Error retrieving status of uploaded file.\n"
                    ]
                    process_api_exception(exc, False, info_msgs)
                    self.set_status_label("Api failure")
                    return None
                except Exception as exc:
                    info_msgs = [
                        "Unknown error retrieving status of uploaded file.\n"
                    ]
                    process_regular_exception(exc, False, info_msgs)
                    self.set_status_label("Plugin failure")
                    return None
                else:
                    # get upload status
                    upload_status = response.resource.status.lower()
                    if upload_status == "pending": # Get hash/index, add to new content dict
                        any_pending = True
                        latest_non_failure = (content_hash, index)
                        new_content_dict[content_hash] = index
                    elif upload_status == "success": # Get hash/index, don't add to new content dict
                        any_success = True
                        latest_non_failure = (content_hash, index)
                    elif upload_status == "failure":
                        any_failure = True
                        new_content_dict[content_hash] = index

                    # capture file status info
                    status_objects.append(response.resource)

            self.main_interface.hashes["upload_content_hashes"] = new_content_dict

            # update the upload status label
            status_result = []
            if any_pending:
                status_result.append("Pending")
            if any_failure:
                status_result.append("Failure")
            if any_success:
                status_result.append("Success")
            self.set_status_label(", ".join(status_result))

            # file exists behavior
            if any_success or any_pending:
                self.main_interface.set_file_exists(True)
                self.enable_all_list_tabs()
                if dropdown.currentIndex == latest_non_failure[1]:
                    self.set_version_hash(latest_non_failure[0])
                else:
                    dropdown.setCurrentIndex(latest_non_failure[1])

            # display status popup
            status_popup = StatusPopup(status_objects, self)
            status_popup.show()

        elif not self.main_interface.file_exists:
            err_popup = ErrorPopup(
                ["No record of an uploaded file. Try to upload a file again."],
                None
            )
            err_popup.exec_()
        elif len(content_hashes) < 1 and len(container_hashes) < 1:
            err_popup = ErrorPopup(
                ["All uploaded files have entered the processing stage."],
                None
            )
            err_popup.exec_()

    def containers_to_content_hashes(self):
        """Get the child content hash of the given container hash's file object."""
        container_hashes = self.main_interface.hashes["upload_container_hashes"]
        if len(container_hashes) < 1:
            return None

        dropdown = self.main_interface.unknown_plugin.files_buttons_layout.dropdown
        content_hashes = self.main_interface.hashes["upload_content_hashes"]
        failed_conversions_to_content_hashes = []
        hashes_to_remove = []

        for h, index in container_hashes.items():
            timestamp, content_hash = self.get_upload_child_hash(h)
            if content_hash:
                new_item_data = (content_hash, "content")
                # update dropdown item
                dropdown.setItemText(index, timestamp)
                dropdown.setItemData(index, new_item_data)
                # add hash/index to content_hashes
                content_hashes[content_hash] = index
                # remove hash from container_hashes
                hashes_to_remove.append(h)
            else:
                failed_conversions_to_content_hashes.append(h)

        if len(hashes_to_remove) > 0:
            for h in hashes_to_remove:
                del container_hashes[h]

        if failed_conversions_to_content_hashes:
            failed_hashes = ", ".join(failed_conversions_to_content_hashes)
            msg = (
            "Some hashes failed to find their processed files in our system. This could be "
            + "caused by the recency of the file(s) upload or a failure in file processing. "
            + "\n\nThe hash(es) with this failure follow:"
            + f"\n{failed_hashes}"
            )
            popup = GenericPopup(msg)
            popup.show()

    def get_content_hashes_statuses(self):
        """Get the status of all hashes in the upload_content_hashes dictionary."""

    def add_upload_hash(self, response_hash):
        """Set the initial upload hash to the sha1 in the upload response."""
        self.main_interface.hashes["upload_container_hashes"].append(response_hash)

    def get_upload_child_hash(self, response_hash):
        """Get the latest matching upload child."""
        expand_mask = "children"
        read_mask = "*,children.*"
        try:
            response = self.ctmfiles.get_file(
                binary_id=response_hash,
                no_links=True,
                read_mask=read_mask,
                expand_mask=expand_mask,
                async_req=True,
            )
            response = response.get()
        except ApiException as exc:
            info_msgs = [
                "Unable to gather information on the uploaded file.\n"
            ]
            process_api_exception(exc, False, info_msgs)
            return None
        except Exception as exc:
            process_regular_exception(exc, False, [str(exc)])
            return None
        else:
            latest_child_hash = None
            timestamp = None
            for child in response.resource.children:
                if child.get("sha1"):
                    sha1 = child.get("sha1")
                    service_name = child.get("service_name", None)
                    service_data = child.get("service_data", {})
                    timestamp = service_data.get("time", None)
                    obj_type = service_data.get("type", None)
                    if (
                        timestamp
                        and obj_type == "disasm-contents"
                        and (service_name == "alt_juice_handler"
                        or service_name == "webRequestHandler")
                    ):
                        latest_child_hash = sha1
            return (timestamp, latest_child_hash)

    def enable_all_list_tabs(self):
        """Enable all file list tabs (notes, tags, matches)."""
        self.list_widget.list_widget_tab_bar.setTabEnabled(0, True)
        self.list_widget.list_widget_tab_bar.setTabEnabled(1, True)
        self.list_widget.list_widget_tab_bar.setTabEnabled(2, True)

    def update_list_widget(
        self,
        widget,
        list_items,
    ):
        """Handle updating the list widget"""
        widget.refresh_list_data(list_items)
        widget.update()
