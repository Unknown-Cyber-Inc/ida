"""
Main scroll widget.

This is widget object which displays all procedure
information of the current file from unknowncyber.
"""
import logging

import cythereal_magic
from cythereal_magic.rest import ApiException
import ida_kernwin
import ida_nalt
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QLabel,
    QVBoxLayout,
    QPushButton,
    QWidget,
    QTableWidgetItem
)

from ..widgets.popups.popups import GenericPopup
from ..widgets.collections.tables import ProcTableWidget
from ..widgets.collection_elements.table_items import ProcTableAddressItem, ProcTableIntegerItem
from ..widgets.displays.center_display import CenterDisplayWidget
from ..layouts import ProcsToggleLayout
from ..helpers import create_proc_name, process_regular_exception, process_api_exception
from ..api import list_file_genomics
from ..references import get_version_hash, get_loaded_sha1, get_file_exists, get_dropdown_widget

logger = logging.getLogger(__name__)


class MAGICPluginScrClass(QWidget):
    """
    Plugin Scroll UI Object.
    """

    def __init__(self, title, magic_api_client):
        """Initialializes the formtype some UI elements may not be loaded in this case,
            which may cause issues.
        Additionally, sets a few member variables necessary to the function of the plugin.
        A few are variables which are determined by IDA.
        """
        super().__init__()
        self.baseRVA = ida_nalt.get_imagebase()
        self.image_base = None
        self.title: str = title
        self.sync_warning = QLabel
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
        self.sync_warning = QLabel(
            f"Showing procedures from file with hash {get_version_hash()}."
            + " Addresses may be out of sync with IDA session."
        )
        self.sync_warning.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.sync_warning.setWordWrap(True)
        self.sync_warning.setStyleSheet("color: red;")
        self.sync_warning.hide()
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
        self.layout.addWidget(self.sync_warning)
        self.layout.addWidget(self.proc_table)

        # set widget's layout based on the above items
        self.setLayout(self.layout)


    def update_sync_warning(self):
        """Update the hash displayed in the sync warning when version hash changes."""
        self.sync_warning.setText(
            f"Showing procedures from file with hash {get_version_hash()}."
            +" Addresses may be out of sync with IDA session."
        )
        self.sync_warning.hide()

    def populate_proc_table(self, procedureInfo):
        """populates the procedures table with recieved procedures

        @param resources: dict containing procedures return request
        """
        self.image_base = int(procedureInfo.image_base, 16)
        for proc in procedureInfo.procedures:
            proc_name = create_proc_name(proc)

            proc_info = [
                proc_name,
                proc.occurrence_count,
                proc.block_count,
                proc.code_count,
                proc.status,
                (0 if not proc.notes else len(proc.notes)),
                (0 if not proc.tags else len(proc.tags)),
            ]
            # insert blank row
            self.proc_table.insertRow(self.proc_table.rowCount())
            # place data in column slots of blank row
            for col, info in enumerate(proc_info):
                if col == 0:
                    col_item = ProcTableAddressItem(info)
                elif isinstance(info, int):
                    col_item = ProcTableIntegerItem(str(info))
                else:
                    col_item = QTableWidgetItem(info)
                self.proc_table.setItem(
                        self.proc_table.rowCount() - 1, col, col_item
                    )
            # Set the row's address column .data() to proc object
            row = self.proc_table.rowCount() - 1
            row_addr_col = self.proc_table.item(row, 0)
            # QtTableWidgetItem.setData(role: int, value: object)
            row_addr_col.setData(1, proc)

            # add node to dict to avoid looping through objects in PluginScrHooks
            start_ea = ida_kernwin.str2ea(proc.start_ea)
            self.procedureEADict_unbased[start_ea] = proc.start_ea
            start_ea = start_ea + self.image_base
            self.procedureEADict[start_ea] = proc.start_ea

    def pushbutton_click(self):
        """What to do when the 'Get Procedures' button is clicked.

        GET from procedures and list all procedures associated with file.
        """
        if not get_file_exists():
            popup = GenericPopup(
                "Upload a file or IDB first to generate procedures.\n\n"
                + "If you have already uploaded, check the status with"
                + " the 'Check Upload Status' button."
            )
            popup.exec_()
            return None
        elif get_dropdown_widget().currentData()[1] == "container":
            popup = GenericPopup(
                "The file respresented by the current version has not started processing yet.\n\n"
                + "Use the 'Check Upload Status' to continue with this version or select a "
                + "different version from the dropdown to view procedures."
            )
            popup.exec_()
            return None

        self.proc_table.reset_table()

        response = list_file_genomics(
            binary_id=get_version_hash(),
            info_msgs=[
                "No procedures could be gathered.",
                "This may occur if the file was recently uploaded."
            ]
        )

        if 200 <= response.status <= 299:
            if len(response.resource.procedures) < 1:
                popup = GenericPopup(
                    "The request for procedures came back empty.\n\n" +
                    "Please check the UnknownCyber dashboard to see if the" +
                    " file associated with the hash below contains any genomics.\n\n" +
                    f"Hash: {get_version_hash()}"
                )
                popup.exec_()
                return None
            self.populate_proc_table(response.resource)
            if get_version_hash() != get_loaded_sha1():
                self.sync_warning.show()
