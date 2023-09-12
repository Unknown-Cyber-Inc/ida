"""
Pluginform object.

This is the scaffolding of the form object which will be displayed to the viewer.
Contains ida_kernwin.PluginForm and also ida_kernwin.Choose.
Will likely be broken into components as the insides of the form grow.
"""

import cythereal_magic
import ida_nalt
import ida_kernwin
import logging

from PyQt5 import QtWidgets

from ._filesTable import _MAGICFormClassMethods
from ..widgets import FileListWidget

logger = logging.getLogger(__name__)


class MAGICPluginFormClass(QtWidgets.QWidget, _MAGICFormClassMethods):
    """
    Plugin UI object.
    Inherits ida_kernwin.PluginForm which wraps IDA's Form object as a PyQt object.

    Populate_pluginform_with_pyqt_widgets.py code was used to create the basics of the plugin.
    """

    #
    # functions for PluginForm object functionality.
    #

    def __init__(self, title, magic_api_client):
        """Initialializes the form object

        Additionally, sets a few member variables necessary to the function of the plugin.
        A few are variables which are determined by IDA.
        """
        super().__init__()

        # non pyqt attrs
        self.title: str = title
        self.file_exists = False
        self.file_type = None
        self.sha1 = None
        self.sha256 = ida_nalt.retrieve_input_file_sha256().hex()
        self.md5 = ida_nalt.retrieve_input_file_md5().hex()
        self.ctmfiles = cythereal_magic.FilesApi(magic_api_client)

        # main pyqt widgets used
        self.t1: QtWidgets.QLabel
        self.upload_tabs: QtWidgets.QTabWidget

        self.list_widget: FileListWidget

        self.load_files_view()

    #
    # functions for building and displaying pyqt.
    #

    def load_files_view(self):
        """
        Create form items then populate page with them.
        """
        self.init_files_view()
        self.populate_files_view()

    def populate_files_view(self):
        """
        After individual form items are initialized, populate the form with them.
        """
        # Create layout object
        self.layout = QtWidgets.QVBoxLayout()

        # adding widgets to layout, order here matters
        self.layout.addWidget(self.t1)
        self.layout.addWidget(self.upload_tabs)
        self.layout.addWidget(self.list_widget)

        # set main widget's layout based on the above items
        self.setLayout(self.layout)

    def init_files_view(self):
        """
        Initialize individual items which will be added to the form.
        """
        # Personalizing QT items, in decending order of appearance.
        # NOTE! Upon display, actual arrangement is solely determined by
        #       the order widgets are ADDED to the layout.
        self.t1 = QtWidgets.QLabel("<font color=red>Files</font>")

        # create main tab bar widget and its tabs
        self.list_widget = FileListWidget(
            list_items=[],
            list_type="NOTES",
            binary_id=self.sha256,
            parent=self,
        )
        self.list_widget.list_widget_tab_bar.currentChanged.connect(
            self.tab_changed
        )

        # help create items, add to tab widget
        self.init_and_populate_tabs()

    def tab_changed(self, index):
        """Tab change behavior

           Index here is used to access the tab position.
           [NoteTab, TagsTab, MatchesTab]
        """
        if index == 0:
            self.make_list_api_call("Notes")
        elif index == 1:
            self.make_list_api_call("Tags")
        elif index == 2:
            self.make_list_api_call("Matches")

    #
    # functions for connecting pyqt signals
    #
