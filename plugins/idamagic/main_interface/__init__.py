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

HOT_RELOAD = to_bool(os.getenv("HOT_RELOAD"))


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
        self.hashes = {
            "loaded_sha1": loaded_hashes.get("sha1", None),
            "loaded_sha256": loaded_hashes.get("sha256", None),
            "loaded_md5": loaded_hashes.get("md5", None),
            "version_sha1": None,
            "ida_sha256": ida_nalt.retrieve_input_file_sha256().hex(),
            "ida_md5": ida_nalt.retrieve_input_file_md5().hex(),
        }

        self.title = main_title
        self.api_client = magic_api_client

        # main plugin widget
        self.main_widget = QtWidgets.QWidget()

        # create File widget
        self.unknown_plugin = MAGICPluginFormClass(
            "Unknown Cyber MAGIC", self.api_client, self.hashes
        )
        # create Procedure widget
        self.ida_plugin = MAGICPluginScrClass(
            "MAGIC Genomics", self.api_client, self.hashes
        )

        # set layout for main plugin
        self.main_layout = QtWidgets.QVBoxLayout()
        self.main_layout.addWidget(self.unknown_plugin)
        self.main_layout.addWidget(self.ida_plugin)
        self.main_widget.setLayout(self.main_layout)

        self.Show()

        if not autoinst:
            self.parent.parent().parent().setSizes([800, 1])

    def set_loaded_hashes(self):
        """
        Set the values of the set of loaded idb's hashes.
        """


    def OnCreate(self, form):
        """
        Called when the widget is created.
        """
        # Convert form to PyQt obj
        self.parent = self.FormToPyQtWidget(form)
        self.parent.setLayout(self.main_layout)
        # self.parent.setMaximumWidth(400)

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
        super().Show(
            self.title,
            options=ida_kernwin.PluginForm.WOPN_DP_SZHINT
        )

        ida_kernwin.set_dock_pos(self.title, "", ida_kernwin.DP_RIGHT)
