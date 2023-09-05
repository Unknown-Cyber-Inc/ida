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
from ..widgets import ProcTextPopup

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
        self.sha256 = ida_nalt.retrieve_input_file_sha256().hex()
        self.baseRVA = ida_nalt.get_imagebase()
        self.title: str = title
        self.ctmfiles = cythereal_magic.FilesApi(magic_api_client)
        self.ctmprocs = cythereal_magic.ProceduresApi(magic_api_client)
        # dict solution to jump from IDA ea to plugin procedure
        self.procedureEADict = {}
        self.popup = ProcTextPopup(fill_text=None, parent=None)
        self.plugin_hook = None

        # # dock this widget on the rightmost side of IDA,
        # # ensure this by setting dest_ctrl to an empty string
        # ida_kernwin.set_dock_pos(self.title, "", ida_kernwin.DP_RIGHT)
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
            self.proc_tree, self.procedureEADict, self.parent
        )
        self.plugin_hook.hook()

        if HOT_RELOAD:
            self.pushbutton_click()

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
        self.layout.addWidget(self.t1)
        self.layout.addWidget(self.pushbutton)
        self.layout.addWidget(self.proc_tree)
        self.layout.addLayout(self.button_row)

        # set widget's layout based on the above items
        self.setLayout(self.layout)

    def init_scroll_view(self):
        """Initialize individual items which will be added to the form."""
        self.t1 = QtWidgets.QLabel("<font color=red>Procedures</font>")

        # create procedure buttons, place them in layout, add to main layout
        self.pushbutton = QtWidgets.QPushButton("Get Procedures")
        self.pushbutton.setCheckable(False)

        self.create_button = QtWidgets.QPushButton("Create")
        self.create_button.setMinimumSize(30, 30)
        self.edit_button = QtWidgets.QPushButton("Edit")
        self.edit_button.setMinimumSize(30, 30)
        self.delete_button = QtWidgets.QPushButton("Delete")
        self.delete_button.setMinimumSize(30, 30)

        # link button to clicked functions and set default 'enabled'
        self.create_button.clicked.connect(self.on_create_click)
        self.create_button.setEnabled(False)
        self.edit_button.setEnabled(False)
        self.edit_button.clicked.connect(self.on_edit_click)
        self.delete_button.setEnabled(False)
        self.delete_button.clicked.connect(self.on_delete_click)

        # create button row for create/edit/delete buttons
        self.button_row = QtWidgets.QHBoxLayout()
        self.button_row.addWidget(self.create_button)
        self.button_row.addWidget(self.edit_button)
        self.button_row.addWidget(self.delete_button)
        self.button_row.setSizeConstraint(QtWidgets.QLayout.SetFixedSize)

        self.proc_tree = QtWidgets.QTreeView()
        self.proc_tree.setHeaderHidden(True)
        self.proc_tree.setModel(Qt.QStandardItemModel())

        # connecting events to items if necessary, in order of appearance
        self.pushbutton.clicked.connect(self.pushbutton_click)

        self.proc_tree.expanded.connect(
            self.onTreeExpand
        )
        self.proc_tree.doubleClicked.connect(
            self.proc_tree_jump_to_hex
        )
        self.proc_tree.clicked.connect(
            self.item_selected
        )

    #
    # functions for connecting pyqt signals
    #
