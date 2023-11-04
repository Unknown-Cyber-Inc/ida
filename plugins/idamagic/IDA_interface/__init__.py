"""
Main scroll widget.

This is widget object which displays all procedure
information of the current file from unknowncyber.
"""

import cythereal_magic
import ida_nalt
from PyQt5.QtWidgets import (
    QVBoxLayout,
    QPushButton,
    QWidget,
)

from ..widgets import CenterDisplayWidget, ProcTableWidget
from ..layouts import ProcsToggleLayout
from ._procTree import _ScrClassMethods


class MAGICPluginScrClass(QWidget, _ScrClassMethods):
    """
    Plugin Scroll UI Object.
    """

    def __init__(self, title, magic_api_client, hashes):
        """Initialializes the formtype some UI elements may not be loaded in this case,
            which may cause issues.
        Additionally, sets a few member variables necessary to the function of the plugin.
        A few are variables which are determined by IDA.
        """
        super().__init__()
        self.hashes = hashes
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
        self.center_widget = CenterDisplayWidget(self)
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
