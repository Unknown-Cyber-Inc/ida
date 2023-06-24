"""
Methods and classes in the MAGICPluginFormClass related to populating the files table.
"""

import logging
import json
import os
import traceback

from cythereal_magic.rest import ApiException
from PyQt5 import QtWidgets, QtGui

IDA_LOGLEVEL = str(os.getenv("IDA_LOGLEVEL", "INFO")).upper()

logger = logging.getLogger(__name__)


class _MAGICFormClassMethods:
    """
    Methods in the MAGICPluginFormClass related to populating the files table
    """

    """
    functions for building and displaying pyqt.
    """

    def init_and_populate_files_analysis_tab(self):
        """
        Helper, initialize and populate items in analysis tab widget
        """
        # create empty widget and add it as a tab to tab widget
        self.files_analysis_tab = QtWidgets.QWidget()
        self.tab_tables.addTab(self.files_analysis_tab, "Analysis")

        # create the objects that will be placed in the analysis tab widget
        self.files_analysis_tab_table = QtWidgets.QTableWidget()
        self.files_analysis_tab_testbutton = QtWidgets.QPushButton("test")

        # ---------------------------------------------------------------------------
        # populate this tab similar to populate_files_view
        # it's less confusing if individual tab population is not in its own function
        self.files_analysis_tab.layout = QtWidgets.QVBoxLayout()

        self.files_analysis_tab.layout.addWidget(self.files_analysis_tab_table)
        self.files_analysis_tab.layout.addWidget(
            self.files_analysis_tab_testbutton
        )

        self.files_analysis_tab.setLayout(self.files_analysis_tab.layout)

    """
    functions for connecting pyqt signals
    """

    def get_and_populate_tables(self):
        """
        calls GET /files and populates the different tables

        Also there must be some way to populate without setting every single row.
        This might be through some custom table class.
        """
        # setting up column names
        identifier = ["sha256"]
        analysis_tab_columns = ["filenames", "filetype"]
        page_size = 0  # ignore default page size
        inputfile_highlight_color = QtGui.QColor(255, 232, 255)

        try:
            # request file from website with the above columns of info
            ctmr = self.ctmfiles.list_files(
                read_mask=",".join(identifier + analysis_tab_columns),
                page_size=page_size,
            )
        except ApiException as e:
            logger.debug(traceback.format_exc())
            self.textbrowser.append("No files could be gathered.")
            for error in json.loads(e.body).get("errors"):
                logger.info(error["reason"])
                self.textbrowser.append(
                    f"{error['reason']}: {error['message']}"
                )
        except Exception as e:
            logger.debug(traceback.format_exc())
            self.textbrowser.append("Unknown Error occurred")
            self.textbrowser.append(f"<{e.__class__}>: {str(e)}")
            # exit if this call fails so user can retry
            # (this func always returns None anyway)
            return None
        else:
            self.textbrowser.append("Files gathered successfully.")

        # set row and col of table based on returned data sizes
        self.files_analysis_tab_table.setRowCount(len(ctmr["resources"]))
        # number of columns = number of analysis_tab_columns + identifier entry (1)
        self.files_analysis_tab_table.setColumnCount(
            len(analysis_tab_columns) + 1
        )

        # label the column based on returned labels
        self.files_analysis_tab_table.setHorizontalHeaderLabels(
            identifier + analysis_tab_columns
        )
        # hide the row headers
        self.files_analysis_tab_table.verticalHeader().setVisible(False)

        # this is almost certainly not the most effecient way
        # loop through every single value and add it to the table cell by cell
        for row, resource in enumerate(ctmr["resources"]):
            # makae sure first column is always identifier
            self.files_analysis_tab_table.setItem(
                row, 0, QtWidgets.QTableWidgetItem(resource[identifier[0]])
            )

            # for this row check if the hash of input file matches the
            # hash of the file in this row and change cell bg color
            current_is_infile = False
            if resource[identifier[0]] == self.sha256:
                self.files_analysis_tab_table.item(row, 0).setBackground(
                    inputfile_highlight_color
                )
                self.files_analysis_tab_table.selectRow(row)
                current_is_infile = True

            self.populate_analysis_table_row(
                resource,
                row,
                analysis_tab_columns,
                current_is_infile,
                inputfile_highlight_color,
            )

        # resize first column (assuming sha256) to show entire entry
        self.files_analysis_tab_table.resizeColumnToContents(0)
        # stretch the final column to the end of the widget
        self.files_analysis_tab_table.horizontalHeader().setStretchLastSection(
            True
        )

    def populate_analysis_table_row(
        self,
        resource,
        row,
        analysis_tab_columns,
        current_is_infile,
        inputfile_highlight_color,
    ):
        """
        When looping through returned resources,
        call this func to populate a row of the table held in the "analysis" tab.

        Needed this function to reduce clutter.
        Each column in each tab may require specific handling before it can be displayed.

        PARAMETERS
        ----------
        resource: dict (vbfilestore.File object representation)
            A single file object returned when calling GET /files
        row: int
            row index
        analysis_tab_columns: [str]
            Column names for the table, as specified at the top of get_and_populate_tables
        current_is_infile: bool
            whether or not the current resource is also the input file
        inputfile_highlight_color: QtGui.QColor
            Defines the color to highlight the infile with
        """
        # check all keys which belong to columns specified by analysis table tab
        # note first col (0) is always identifier. hence why we use col+1
        for col, key in enumerate(analysis_tab_columns):
            # if key requires special handling:
            if key == "filenames":
                self.files_analysis_tab_table.setItem(
                    row,
                    col + 1,
                    QtWidgets.QTableWidgetItem(",".join(resource[key])),
                )
            else:  # returned item is string, add to table cell as normal
                self.files_analysis_tab_table.setItem(
                    row, col + 1, QtWidgets.QTableWidgetItem(resource[key])
                )

            # current hash is infile, change cell background color so user can identify it easily
            if current_is_infile:
                self.files_analysis_tab_table.item(row, col + 1).setBackground(
                    inputfile_highlight_color
                )
