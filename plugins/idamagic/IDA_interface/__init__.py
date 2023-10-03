"""
Main scroll widget.

This is widget object which displays all procedure
information of the current file from unknowncyber.
"""

import cythereal_magic
import ida_nalt
import ida_kernwin
import os

from PyQt5.QtWidgets import (
    QVBoxLayout,
    QPushButton,
    QHBoxLayout,
    QSpacerItem,
    QSizePolicy,
    QTableWidget,
    QAbstractItemView,
    QWidget,
)
from idamagic.helpers import to_bool
from ..widgets import CenterDisplayWidget, ProcTableWidget
from ..helpers import hash_file
from ..layouts import ProcsToggleLayout
from ._procTree import _ScrClassMethods

HOT_RELOAD = to_bool(os.getenv("HOT_RELOAD"))


class MAGICPluginScrClass(QWidget, _ScrClassMethods):
    """
    Plugin Scroll UI Object.
    Inherits ida_kernwin.PluginForm which wraps IDA's Form object as a PyQt object.
    """

    def __init__(self, title, magic_api_client):
        """Initialializes the formtype some UI elements may not be loaded in this case,
            which may cause issues.
        Additionally, sets a few member variables necessary to the function of the plugin.
        A few are variables which are determined by IDA.
        """
        super().__init__()
        self.sha1 = hash_file()
        self.sha256 = ida_nalt.retrieve_input_file_sha256().hex()
        self.baseRVA = ida_nalt.get_imagebase()
        self.image_base = None
        self.title: str = title
        self.ctmfiles = cythereal_magic.FilesApi(magic_api_client)
        self.ctmprocs = cythereal_magic.ProceduresApi(magic_api_client)
        # dict solutions to jump from IDA ea to plugin procedure
        self.procedureEADict = {}
        self.procedureEADict_unbased = {}
        self.popup = None
        self.plugin_hook = None

        self.load_scroll_view()
        self.hook()

    def hook(self):
        """
        Take created widget object and display it on IDA's GUI
        """
        from idamagic.hooks import PluginScrHooks

        # hook into the IDA code
        self.plugin_hook = PluginScrHooks(
            self.proc_table, self.procedureEADict, self.procedureEADict_unbased
        )
        self.plugin_hook.hook()

        # if HOT_RELOAD:
        #     self.pushbutton_click()

    """
    functions for building and displaying pyqt.
    """

    def load_scroll_view(self):
        """
        Create form items then populate page with them.
        """
        self.init_scroll_view()
        self.populate_scroll_view()

    def init_scroll_view(self):
        """Initialize individual items which will be added to the form."""
        self.center_widget = CenterDisplayWidget(self.sha256)
        self.procs_toggle_layout = ProcsToggleLayout(self)
        self.pushbutton = QPushButton("Get Procedures")
        self.pushbutton.setCheckable(False)
        self.pushbutton.clicked.connect(self.pushbutton_click)
        self.proc_table = ProcTableWidget(self)

    def populate_scroll_view(self):
        """
        After individual form items are initialized, populate the form with them.
        """
        # Create layout object
        self.layout = QVBoxLayout()

        # adding widgets to layout, order here matters
        self.layout.addWidget(self.center_widget)
        self.layout.addLayout(self.procs_toggle_layout)
        self.layout.addWidget(self.pushbutton)
        self.layout.addWidget(self.proc_table)

        # set widget's layout based on the above items
        self.setLayout(self.layout)
