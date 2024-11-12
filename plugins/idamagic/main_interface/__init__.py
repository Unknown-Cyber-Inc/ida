"""Main interface. Used to hold sub-interfaces."""
import logging
import os

import ida_kernwin
import ida_nalt
from PyQt5 import QtWidgets

from ..helpers import get_all_idb_hashes
from ..IDA_interface import MAGICPluginScrClass
from ..unknowncyber_interface import MAGICPluginFormClass
from ..references import (
    add_upload_content_entry,
    add_upload_container_entry,
    get_version_hash,
    get_file_exists,
    remove_upload_container_entry,
    set_file_exists,
    set_recent_upload_type,
    set_version_hash,
    set_loaded_sha1,
    set_loaded_sha256,
    set_loaded_md5,
    set_ida_sha256,
    set_ida_md5,
    set_ida_version_valid,
    set_upload_container_hashes,
    set_upload_content_hashes
)
logging.basicConfig(level=os.getenv("IDA_LOGLEVEL", "INFO"))
logger = logging.getLogger(__name__)


class MAGICMainClass(ida_kernwin.PluginForm):
    """Main plugin form at the highest level."""

    def __init__(
        self,
        main_title,
        magic_api_client,
        autoinst=False,
    ):
        """Initialize main plugin and attach sub-plugins."""
        set_ida_version_valid(self.check_ida_version())
        super().__init__()
        loaded_hashes = get_all_idb_hashes()

        # set global variables
        set_file_exists(False)
        set_loaded_sha1(loaded_hashes.get("sha1", None))
        set_loaded_md5(loaded_hashes.get("md5", None))
        set_loaded_sha256(loaded_hashes.get("sha256", None))
        set_ida_md5(ida_nalt.retrieve_input_file_md5().hex())
        set_ida_sha256(ida_nalt.retrieve_input_file_sha256().hex())
        set_version_hash()
        set_upload_container_hashes()
        set_upload_content_hashes()
        set_recent_upload_type()

        self.title = main_title
        self.api_client = magic_api_client

        # main plugin widget
        self.main_widget = QtWidgets.QWidget()

        # create File widget
        self.unknown_plugin = MAGICPluginFormClass(
            "Unknown Cyber MAGIC", self.api_client, self
        )
        # create Procedure widget
        self.ida_plugin = MAGICPluginScrClass("MAGIC Genomics", self.api_client)
        self.unknown_plugin.init_and_populate()

        # set layout for main plugin
        self.main_layout = QtWidgets.QVBoxLayout()
        self.main_layout.addWidget(self.unknown_plugin)
        self.main_layout.addWidget(self.ida_plugin)
        self.main_widget.setLayout(self.main_layout)

        self.unknown_plugin.files_buttons_layout.dropdown.currentIndexChanged.connect(
            self.dropdown_selection_changed
        )

        self.Show()

        if not autoinst:
            self.parent.parent().parent().setSizes([1200, 1])

    def check_ida_version(self):
        """
        Check if IDA version is 8.x.

        Returns:
            bool: True if version is 8.x, False otherwise
        """
        try:
            version = ida_kernwin.get_kernel_version()
            major_version = int(version.split('.')[0])
            logger.debug(f"Detected IDA version: {version} (Major: {major_version})")

            if major_version != 8:
                error_msg = (
                    f"The Unknown Cyber plugin requires IDA version 8.x.\n"
                    f"Detected version: {version}\n"
                    f"Plugin loading with some features disabled, others may not work as intended."
                )
                QtWidgets.QMessageBox.critical(None,
                    "IDA Version Error",
                    error_msg
                )
                logger.error(
                    f"Incompatible IDA version for use with Unknown Cyber plugin: {version}"
                )
                return False

            return True

        except Exception as e:
            error_msg = f"Failed to check IDA version: {str(e)}"
            logger.error(error_msg)
            QtWidgets.QMessageBox.critical(None,
                "IDA Version Error",
                error_msg
            )
            return False

    def dropdown_selection_changed(self, index):
        """
        When dropdown selection changes, update version hashes.
        """
        dropdown = self.unknown_plugin.files_buttons_layout.dropdown
        item_data = dropdown.currentData()
        obj_type = item_data[1]
        init_hash = item_data[0]
        content_child_data = None

        # if obj_type is container, query for content
        if obj_type.lower() == "container":
            content_child_data = self.unknown_plugin.get_upload_child_data(init_hash)
          # if content found:
            if content_child_data:
                # remove hash from container hash list
                remove_upload_container_entry(init_hash)
                # add hash to content hash list,
                add_upload_content_entry(content_child_data[1], index)
                # create new data tuple for dropdown item
                new_data = (content_child_data[1], "content")
                # update dropdown item data
                dropdown.setItemData(index, new_data)
                dropdown.setItemText(index, content_child_data[0])

        # update version_hash
        if content_child_data:
            set_version_hash(content_child_data[1])
        else:
            set_version_hash(init_hash)
        self.version_hash_changed()

    def version_hash_changed(self):
        """
        Defined behavior for when the version_hash changes.

        Clear the procedure table.
        """
        self.ida_plugin.proc_table.reset_table()
        self.ida_plugin.center_widget.update_sha1(get_version_hash())
        self.ida_plugin.update_sync_warning()
        self.unknown_plugin.version_hash.setText(f"Version hash: {get_version_hash()}")
        self.unknown_plugin.list_widget.list_widget.clear()
        self.unknown_plugin.list_widget.list_widget_tab_bar.setCurrentIndex(2)
        self.unknown_plugin.make_list_api_call("Matches")

    def OnCreate(self, form):
        """
        Called when the widget is created.
        """
        # Convert form to PyQt obj
        self.parent = self.FormToPyQtWidget(form)
        self.parent.setLayout(self.main_layout)

    def OnClose(self, form):
        """
        Called when the widget is closed.
        """
        self.ida_plugin.plugin_hook.unhook()
        return

    def Show(self):
        """
        Take created widget object and display it on IDA's GUI
        """
        # show with intrinsic title, specific options
        # dock this widget on the rightmost side of IDA,
        # ensure this by setting dest_ctrl to an empty string
        super().Show(self.title, options=ida_kernwin.PluginForm.WOPN_DP_SZHINT)

        ida_kernwin.set_dock_pos(self.title, "", ida_kernwin.DP_RIGHT)
