"""Main interface. Used to hold sub-interfaces."""

import ida_kernwin
import ida_nalt
import logging
import os

from PyQt5 import QtWidgets

from ..helpers import to_bool, get_all_idb_hashes
from ..IDA_interface import MAGICPluginScrClass
from ..unknowncyber_interface import MAGICPluginFormClass

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
        super().__init__()
        loaded_hashes = get_all_idb_hashes()
        self.file_exists = False
        self.hashes = {
            "loaded_sha1": loaded_hashes.get("sha1", None),
            "loaded_sha256": loaded_hashes.get("sha256", None),
            "loaded_md5": loaded_hashes.get("md5", None),
            "version_hash": None,
            "ida_sha256": ida_nalt.retrieve_input_file_sha256().hex(),
            "ida_md5": ida_nalt.retrieve_input_file_md5().hex(),
            "upload_hash": None,
            "initial_upload_hash": None,
        }

        self.recent_upload_type = None

        self.title = main_title
        self.api_client = magic_api_client

        # main plugin widget
        self.main_widget = QtWidgets.QWidget()

        # create File widget
        self.unknown_plugin = MAGICPluginFormClass(
            "Unknown Cyber MAGIC", self.api_client, self
        )
        # create Procedure widget
        self.ida_plugin = MAGICPluginScrClass(
            "MAGIC Genomics", self.api_client, self
        )
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

    def get_file_exists(self):
        """Return value of self.file_exists"""
        return self.file_exists

    def set_file_exists(self, val):
        """Set the value of self.file_exists."""
        self.file_exists = val

    def dropdown_selection_changed(self, index):
        """
        When dropdown selection changes, update version hashes.
        """
        sha1 = self.unknown_plugin.files_buttons_layout.dropdown.itemData(
            index
        )
        self.hashes["version_hash"] = sha1

        self.version_hash_changed()

    def version_hash_changed(self):
        """
        Defined behavior for when the version_hash changes.

        Clear the procedure table.
        """
        self.ida_plugin.proc_table.reset_table()
        self.ida_plugin.center_widget.update_sha1(self.hashes["version_hash"])
        self.ida_plugin.update_sync_warning()
        self.unknown_plugin.version_hash.setText(f"Version hash: {self.hashes['version_hash']}")
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
