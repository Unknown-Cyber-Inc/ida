"""
Main pluginform object at the highest level. 

This is the scaffolding of the form object which will be displayed to the viewer.
Contains ida_kernwin.PluginForm and also ida_kernwin.Choose.
Will likely be broken into components as the insides of the form grow.
"""

# IDA and UI imports
import ida_nalt, ida_kernwin
from PyQt5 import QtWidgets

#cythereal magic for calling API
import cythereal_magic

# load_dotenv sources the below environment variables from .env
import os
PLUGIN_DEBUG = True if os.getenv("PLUGIN_DEBUG") == "True" else False

class TableView(QtWidgets.QTableWidget):
    def __init__(self, data, *args):
        QtWidgets.QTableWidget.__init__(self, *args)
        self.data = data
        self.setData()
        self.resizeColumnsToContents()
        self.resizeRowsToContents()
 
    def setData(self): 
        horHeaders = []
        for n, key in enumerate(sorted(self.data.keys())):
            horHeaders.append(key)
            for m, item in enumerate(self.data[key]):
                newitem = QtWidgets.QTableWidgetItem(item)
                self.setItem(m, n, newitem)
        self.setHorizontalHeaderLabels(horHeaders)

class MAGICPluginFormClass(ida_kernwin.PluginForm):
    """
    Highest level of the plugin UI object. Inherits ida_kernwin.PluginForm which wraps IDA's Form object as a PyQt object.

    Populate_pluginform_with_pyqt_widgets.py code was used to create the basics of the plugin.
    """

    def __init__(self, title:str):
        super().__init__()
        
        self.title: str = title 
        self.sha256 = ida_nalt.retrieve_input_file_sha256().hex()
        self.md5 = ida_nalt.retrieve_input_file_md5().hex()
        self.ctm = cythereal_magic.ApiClient()
        self.ctmfiles = cythereal_magic.FilesApi(self.ctm) 

        self.parent: QtWidgets.QtWidget 

        self.t1: QtWidgets.QLabel
        self.t2: QtWidgets.QLabel
        self.pushbutton: QtWidgets.QPushButton
        self.textbrowser: QtWidgets.QTextEdit

        self.Show()         

    def OnCreate(self, form):
        """
        Called when the widget is created
        """
        # Convert form to PyQt obj
        self.parent = self.FormToPyQtWidget(form)

        self.load_views()
     
    def OnClose(self, form):
        """
        Called when the widget is closed
        """
        return

    def Show(self):   
        return super().Show(
            self.title,
            options=(
            ida_kernwin.PluginForm.WOPN_TAB
            | ida_kernwin.PluginForm.WOPN_RESTORE
            | ida_kernwin.PluginForm.WCLS_CLOSE_LATER
            | ida_kernwin.PluginForm.WCLS_SAVE
            ),
        )
    
    def load_views(self):
        self.get_file_view()
        self.get_files_table_subview()

        self.populate_layout()

    def populate_layout(self):
        # Create layout
        layout = QtWidgets.QVBoxLayout()

        #adding widgets to layout
        layout.addWidget(self.t1)
        layout.addWidget(self.t2)
        layout.addWidget(self.pushbutton)
        layout.addWidget(self.tab_tables)
        layout.addWidget(self.textbrowser)

        self.parent.setLayout(layout)

    def get_file_view(self):
        #personalizing QT widgets
        self.t1 = QtWidgets.QLabel("Lorem Ipsum <font color=red>Cythereal</font>")
        self.t2 = QtWidgets.QLabel("Lorem Ipsum <font color=blue>MAGIC</font>")

        self.textbrowser = QtWidgets.QTextEdit()
        self.textbrowser.setReadOnly(True)

        self.pushbutton = QtWidgets.QPushButton("request files")
        self.pushbutton.setCheckable(True)
        #button actions
        self.pushbutton.clicked.connect(self.pushbutton_click)

    def get_files_table_subview(self):
        # create tab widget
        self.tab_tables = QtWidgets.QTabWidget()

        # create table widget to fill tab
        self.files_analysis_tab = QtWidgets.QTableWidget()

        # add table tab to tab widget
        self.tab_tables.addTab(self.files_analysis_tab,"Analysis")

    def pushbutton_click(self):
        self.textbrowser.clear()

        try:
            self.get_and_populate_tables()

            self.textbrowser.append('Resources gathered successfully.')
        except:
            self.textbrowser.append('No resources could be gathered.')
            if PLUGIN_DEBUG: 
                import traceback
                self.textbrowser.append(traceback.format_exc())

    def get_and_populate_tables(self):
        # request file from website
        ctmr = self.ctmfiles.list_files(read_mask="sha256,filetype")

        # set row and col of table based on returned data sizes
        self.files_analysis_tab.setRowCount(len(ctmr['resources']))
        # assuming here that every returned entry has the same number of columns
        self.files_analysis_tab.setColumnCount(len(ctmr['resources'][0]))
        
        # label the column based on returned keys
        self.files_analysis_tab.setHorizontalHeaderLabels(ctmr['resources'][0].keys())   
        # hide the row headers
        self.files_analysis_tab.verticalHeader().setVisible(False)  

        # this is almost certainly not the most effecient way
        # loop through every single value and add it to the table
        for i,resource in enumerate(ctmr['resources']):
            for j,key in enumerate(resource):
                self.files_analysis_tab.setItem(i, j, QtWidgets.QTableWidgetItem(resource[key]))

        # resize first column (assuming sha256) to show entire entry
        self.files_analysis_tab.resizeColumnToContents(0)
        #stretch the final column to the end of the widget
        self.files_analysis_tab.horizontalHeader().setStretchLastSection(True)
