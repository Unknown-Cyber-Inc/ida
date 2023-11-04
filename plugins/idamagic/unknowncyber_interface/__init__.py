"""
Pluginform object.

This is the scaffolding of the form object which will be displayed to the viewer.
Contains ida_kernwin.PluginForm and also ida_kernwin.Choose.
Will likely be broken into components as the insides of the form grow.
"""

import cythereal_magic
import logging

from PyQt5.QtCore import Qt

from PyQt5.QtWidgets import (
    QPushButton,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QWidget,
)

from ._filesTable import _MAGICFormClassMethods
from ..widgets import FileListWidget
from ..layouts import FilesButtonsLayout

logger = logging.getLogger(__name__)


class MAGICPluginFormClass(QWidget, _MAGICFormClassMethods):
    """
    Plugin UI object.
    Inherits ida_kernwin.PluginForm which wraps IDA's Form object as a PyQt object.

    Populate_pluginform_with_pyqt_widgets.py code was used to create the basics of the plugin.
    """

    #
    # functions for PluginForm object functionality.
    #

    def __init__(self, title, magic_api_client, hashes):
        """Initialializes the form object

        Additionally, sets a few member variables necessary to the function of the plugin.
        A few are variables which are determined by IDA.
        """
        super().__init__()

        # non pyqt attrs
        self.title: str = title
        self.file_exists = False
        self.file_type = None
        self.hashes = hashes
        self.ctmfiles = cythereal_magic.FilesApi(magic_api_client)

        # main pyqt widgets used
        self.layout: QVBoxLayout
        self.loaded_md5: QLabel
        self.linked_md5: QLabel
        self.files_toggle: QPushButton
        self.upload_button: QPushButton
        self.files_buttons_layout: QHBoxLayout
        self.list_widget: FileListWidget

        self.load_files_view()

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
        self.layout = QVBoxLayout()

        # adding widgets to layout, order here matters
        self.layout.addWidget(self.loaded_md5)
        self.layout.addWidget(self.linked_md5)
        self.layout.addLayout(self.files_buttons_layout)
        self.layout.addWidget(self.list_widget)

        # set main files widget's layout based on the above items
        self.setLayout(self.layout)

    def init_files_view(self):
        """
        Initialize individual items which will be added to the form.
        """
        # Personalizing QT items, in decending order of appearance.
        # NOTE! Upon display, actual arrangement is solely determined by
        #       the order widgets are ADDED to the layout.
        self.loaded_md5 = QLabel(f"IDB hash: {self.hashes['loaded_md5']}")
        self.loaded_md5.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.linked_md5 = QLabel(f"Binary hash: {self.hashes['ida_md5']}")
        self.linked_md5.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.files_buttons_layout = FilesButtonsLayout(self)
        # create main tab bar widget and its tabs
        self.list_widget = FileListWidget(
            list_items=[],
            list_type="Matches",
            binary_id=self.hashes["version_sha1"],
            widget_parent=self,
        )
        # help create items, add to tab widget
        self.init_and_populate()
