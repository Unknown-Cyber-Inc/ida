"""
Main scroll widget at the highest level.

This is widget object which displays all procedure
information of the current file from unknowncyber.
"""

import cythereal_magic
import ida_nalt
import ida_kernwin
import os

from PyQt5 import QtWidgets, Qt
from idamagic.helpers import to_bool

# contains classes related to different types of nodes in the tree,
# + methods for scrclass related to tree
from ._procTree import _ScrClassMethods

HOT_RELOAD = to_bool(os.getenv("HOT_RELOAD"))


class MAGICPluginScrClass(ida_kernwin.PluginForm, _ScrClassMethods):
    """
    Highest level of the plugin Scroll UI Object.
    Inherits ida_kernwin.PluginForm which wraps IDA's Form object as a PyQt object.
    """

    """
    functions for PluginForm object functionality.
    """

    def __init__(self, title, magic_api_client, autoinst=False):
        """Initialializes the form object

        PARAMETERS
        ----------
        title: string
            Name of the widget
        magic_api_client: cythereal_magic.ApiClient
            The api client for cythereal_magic to send requests to unknowncyber
        autoinst: bool
            Tells the widget if this is being launched by the auto instantiation hooks.
            This is because some UI elements may not be loaded in this case,
            which may cause issues.
        Additionally, sets a few member variables necessary to the function of the plugin.
        A few are variables which are determined by IDA.
        """
        from idamagic.hooks import PluginScrHooks

        super().__init__()
        self.sha256 = ida_nalt.retrieve_input_file_sha256().hex()
        self.baseRVA = ida_nalt.get_imagebase()
        self.title: str = title
        self.ctmfiles = cythereal_magic.FilesApi(magic_api_client)
        self.ctmprocs = cythereal_magic.ProceduresApi(magic_api_client)
        # dict solution to jump from IDA ea to plugin procedure
        self.procedureEADict = {}

        # show widget on creation of new form
        self.Show()

        # hook into the IDA code
        self.hooks = PluginScrHooks(
            self.proc_tree, self.procedureEADict, self.parent
        )
        self.hooks.hook()

        # dock this widget on the rightmost side of IDA,
        # ensure this by setting dest_ctrl to an empty string
        ida_kernwin.set_dock_pos(self.title, "", ida_kernwin.DP_RIGHT)
        """
        A 'QSplitter' is created which can handle the default creation size.
        Through testing I have found out which widget this is relative to self.
        It is handled by IDA and doesn't have a simple reference.
        The number here is a relative size ratio between two widgets
        (between the scroll widget and the widgets to the left)
        """
        if not autoinst:
            self.parent.parent().parent().setSizes([600, 1])

        if HOT_RELOAD:
            self.pushbutton_click()

    def OnCreate(self, form):
        """
        Called when the widget is created.
        """
        # Convert form to PyQt obj
        self.parent = self.FormToPyQtWidget(form)

        self.load_scroll_view()

    def OnClose(self, form):
        """
        Called when the widget is closed.
        """
        self.hooks.unhook()
        return

    def Show(self):
        """
        Take created widget object and display it on IDA's GUI
        """
        # show with intrinsic title, specific options
        return super().Show(
            self.title,
            options=(
                # for some reason the options appear to only work once
                # after resetting desktop in IDA
                ida_kernwin.PluginForm.WOPN_DP_SZHINT
                # | ida_kernwin.PluginForm.WOPN_RESTORE
                # | ida_kernwin.PluginForm.WCLS_CLOSE_LATER
                # | ida_kernwin.PluginForm.WCLS_SAVE
            ),
        )

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
        layout = QtWidgets.QVBoxLayout()

        # adding widgets to layout, order here matters
        layout.addWidget(self.t1)
        layout.addWidget(self.t2)
        layout.addWidget(self.pushbutton)
        layout.addWidget(self.proc_tree)
        layout.addWidget(self.textbrowser)

        # set main widget's layout based on the above items
        self.parent.setLayout(layout)

    def init_scroll_view(self):
        """Initialize individual items which will be added to the form."""
        # personalizing QT items, in order of appearance (order is set by layout though)
        self.t1 = QtWidgets.QLabel(
            "Lorem Ipsum <font color=red>Cythereal</font>"
        )
        self.t2 = QtWidgets.QLabel("Lorem Ipsum <font color=blue>MAGIC</font>")

        self.pushbutton = QtWidgets.QPushButton("request procedures")
        self.pushbutton.setCheckable(False)

        self.proc_tree = QtWidgets.QTreeView()
        self.proc_tree.setHeaderHidden(True)
        self.proc_tree.setModel(Qt.QStandardItemModel())
        # let widget handle doubleclicks
        self.proc_tree.doubleClicked.connect(self.proc_tree_jump_to_hex)
        # handle certain expand events
        self.proc_tree.expanded.connect(self.onTreeExpand)

        self.textbrowser = QtWidgets.QTextEdit()
        self.textbrowser.setReadOnly(True)

        # connecting events to items if necessary, in order of appearance
        self.pushbutton.clicked.connect(self.pushbutton_click)

    """
    functions for connecting pyqt signals
    """
