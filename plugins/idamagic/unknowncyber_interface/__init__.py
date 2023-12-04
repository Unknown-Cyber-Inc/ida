"""
Pluginform object.

This is the scaffolding of the form object which will be displayed to the viewer.
Contains ida_kernwin.PluginForm and also ida_kernwin.Choose.
Will likely be broken into components as the insides of the form grow.
"""

from collections import OrderedDict
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
from ..widgets import FileListWidget, StatusPopup
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

    def __init__(self, title, magic_api_client, main_interface):
        """Initialializes the form object

        Additionally, sets a few member variables necessary to the function of the plugin.
        A few are variables which are determined by IDA.
        """
        super().__init__()

        # non pyqt attrs
        self.title: str = title
        self.file_type = None
        self.main_interface = main_interface
        self.content_versions = OrderedDict()
        self.ctmfiles = cythereal_magic.FilesApi(magic_api_client)

        # main pyqt widgets used
        self.layout: QVBoxLayout
        self.loaded_md5: QLabel
        self.linked_md5: QLabel
        self.status_label: QLabel
        self.status_button: QPushButton
        self.status_layout: QHBoxLayout
        self.status_popup: StatusPopup
        self.files_toggle: QPushButton
        self.files_buttons_layout: FilesButtonsLayout
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
        self.layout.addLayout(self.status_layout)
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
        self.loaded_md5 = QLabel(f"IDB md5: {self.main_interface.hashes['loaded_md5']}")
        self.loaded_md5.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.linked_md5 = QLabel(f"Binary md5: {self.main_interface.hashes['ida_md5']}")
        self.linked_md5.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.status_label = QLabel(
            "Upload Processing Status: Upload a file to track it's status."
        )
        self.status_button = QPushButton("Check Upload Status")
        self.status_button.clicked.connect(self.get_file_status)
        self.status_button.setEnabled(False)
        self.status_layout = QHBoxLayout()
        self.status_layout.addWidget(self.status_label)
        self.status_layout.addWidget(self.status_button)
        self.status_popup = None
        self.files_buttons_layout = FilesButtonsLayout(self)
        # create main tab bar widget and its tabs
        self.list_widget = FileListWidget(
            list_items=[],
            binary_id=self.main_interface.hashes["ida_md5"],
            widget_parent=self,
        )

    def populate_dropdown(self):
        """
        Populate the dropdown with the returned original binary and content file versions
        """
        if len(self.content_versions) > 0:
            for key, value in self.content_versions.items():
                self.files_buttons_layout.dropdown.addItem(key, value)

    def add_upload_version_to_dropdown(self, binary_id):
        """
        Add the latest uploaded version and binary_id to the version dropdown.
        The version name will be set as a temporary one. Upon reloading the plugin
        or IDA, the version name will be normalized by the API.
        """
        self.files_buttons_layout.dropdown.addItem("Recent Upload", binary_id)

    def set_status_label(self, status):
        """Set the color of the status button according to the input status."""
        self.status_label.setText(
            f"Upload Processing Status: {str(status).capitalize()}"
        )
