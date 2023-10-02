"""
Main scroll widget.

This is widget object which displays all procedure
information of the current file from unknowncyber.
"""

import cythereal_magic
import ida_nalt
import ida_kernwin
import os

from PyQt5 import QtWidgets, Qt
from idamagic.helpers import to_bool
from ..widgets import CenterDisplayWidget
from ..helpers import hash_file

# contains classes related to different types of nodes in the list,
# + methods for scrclass related to list
from ._procTree import _ScrClassMethods

HOT_RELOAD = to_bool(os.getenv("HOT_RELOAD"))


class MAGICPluginScrClass(QtWidgets.QWidget, _ScrClassMethods):
    """
    Plugin Scroll UI Object.
    Inherits ida_kernwin.PluginForm which wraps IDA's Form object as a PyQt object.
    """

    """
    functions for PluginForm object functionality.
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
        # dict solution to jump from IDA ea to plugin procedure
        self.procedureEADict = {}
        self.procedureEADict_unbased = {}
        self.popup = None
        self.plugin_hook = None
        """
        A 'QSplitter' is created which can handle the default creation size.
        Through testing I have found out which widget this is relative to self.
        It is handled by IDA and doesn't have a simple reference.
        The number here is a relative size ratio between two widgets
        (between the scroll widget and the widgets to the left)
        """

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

    def populate_scroll_view(self):
        """
        After individual form items are initialized, populate the form with them.
        """
        # Create layout object
        self.layout = QtWidgets.QVBoxLayout()

        # adding widgets to layout, order here matters
        self.layout.addWidget(self.center_widget)
        self.layout.addLayout(self.procs_toggle_layout)
        self.layout.addWidget(self.pushbutton)
        self.layout.addWidget(self.proc_table)

        # set widget's layout based on the above items
        self.setLayout(self.layout)

    def init_scroll_view(self):
        """Initialize individual items which will be added to the form."""
        self.center_widget = CenterDisplayWidget(self.sha256)

        self.procs_toggle = QtWidgets.QPushButton("Hide Procedures Section")
        self.procs_toggle.clicked.connect(self.toggle_procs)
        self.procs_toggle_layout = QtWidgets.QHBoxLayout()
        self.procs_toggle_layout.addWidget(self.procs_toggle)
        spacer = QtWidgets.QSpacerItem(
            0,
            0,
            QtWidgets.QSizePolicy.Expanding,
            QtWidgets.QSizePolicy.Minimum,
        )
        self.procs_toggle_layout.addItem(spacer)

        # create procedure buttons, place them in layout, add to main layout
        self.pushbutton = QtWidgets.QPushButton("Get Procedures")
        self.pushbutton.setCheckable(False)

        # move this to the widgets file
        self.proc_table = QtWidgets.QTableWidget()
        self.proc_table.setColumnCount(5)
        self.proc_table.setHorizontalHeaderLabels(
            ["Address", "Occurrence #", "Type", "Notes", "Tags"]
        )
        self.proc_table.setEditTriggers(
            QtWidgets.QAbstractItemView.NoEditTriggers
        )
        self.proc_table.setSortingEnabled(True)
        self.proc_table.verticalHeader().setVisible(False)
        self.proc_table.itemDoubleClicked.connect(
            self.on_address_col_double_click
        )

        # connecting events to items if necessary, in order of appearance
        self.pushbutton.clicked.connect(self.pushbutton_click)

    #
    # functions for connecting pyqt signals
    #

    def proc_tree_jump_to_hex(self, start_ea):
        """From item address in table view, jump IDA to that position."""
        start_ea = ida_kernwin.str2ea(start_ea)
        found_ea = ida_kernwin.jumpto(start_ea)
        if not found_ea:
            start_ea = start_ea + self.image_base
            ida_kernwin.jumpto(start_ea)

    def on_address_col_double_click(self, item):
        """Handle proc table row double clicks."""
        self.center_widget.create_tab(
            "Original procedure",
            self.sha1,
            item.data(1),
        )
        self.proc_tree_jump_to_hex(item.data(1).start_ea)

    def toggle_procs(self):
        """Toggle collapse or expansion of procedures widget"""
        if self.procs_toggle.text() == "Hide Procedures Section":
            self.procs_toggle.setText("Show Procedures Section")
            self.hide_widgets()
        else:
            self.procs_toggle.setText("Hide Procedures Section")
            self.show_widgets()

    def show_widgets(self):
        """Set widgets to `show()`"""
        self.pushbutton.show()
        self.proc_table.show()

    def hide_widgets(self):
        """Set widgets to `hide()`"""
        self.pushbutton.hide()
        self.proc_table.hide()
