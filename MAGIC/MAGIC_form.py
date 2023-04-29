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
        layout.addWidget(self.files_analysis_tab)
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
        self.tab_tables = QtWidgets.QTabWidget()
        self.files_analysis_tab = QtWidgets.QTableWidget()
        self.files_analysis_tab.setRowCount(5)
        self.files_analysis_tab.setColumnCount(3)
        self.files_analysis_tab.setItem(0, 0, QtWidgets.QTableWidgetItem("test"))

        self.tab_tables.addTab(self.files_analysis_tab,"Analysis")

    def pushbutton_click(self):
        self.textbrowser.clear()

        try:
            # request file from website
            ctmr = self.ctmfiles.list_files(read_mask="sha256,filetype")
            for item in ctmr['resources']:
                print(item)
            self.textbrowser.append(str(ctmr['resources']))
            self.textbrowser.append('Resources gathered successfully.')
        except:
            self.textbrowser.append('No resources could be gathered.')
            if PLUGIN_DEBUG: 
                import traceback
                self.textbrowser.append(traceback.format_exc())