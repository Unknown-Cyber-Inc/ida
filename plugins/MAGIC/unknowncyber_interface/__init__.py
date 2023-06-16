"""
Main pluginform object at the highest level. 

This is the scaffolding of the form object which will be displayed to the viewer.
Contains ida_kernwin.PluginForm and also ida_kernwin.Choose.
Will likely be broken into components as the insides of the form grow.
"""

# IDA and UI imports
import ida_nalt, ida_kernwin
from PyQt5 import QtWidgets, Qt, QtGui

#cythereal magic for calling API, subnodes containing important member classes and methods
import cythereal_magic
from . import _filesTable # contains classes related to different types of nodes in the tree, + methods for scrclass related to tree

# load_dotenv sources the below environment variables from .env
import os
PLUGIN_DEBUG = True if os.getenv("PLUGIN_DEBUG") == "True" else False

class MAGICPluginFormClass(ida_kernwin.PluginForm,_filesTable._MAGICFormClassMethods):
    """
    Highest level of the plugin UI object. Inherits ida_kernwin.PluginForm which wraps IDA's Form object as a PyQt object.

    Populate_pluginform_with_pyqt_widgets.py code was used to create the basics of the plugin.
    """

    """
    functions for PluginForm object functionality.
    """
    def __init__(self, title, magic_api_client):
        """Initialializes the form object

        Additionally, sets a few member variables necessary to the function of the plugin.
        A few are variables which are determined by IDA.
        """
        super().__init__()
        
        # non pyqt attrs
        self.title: str = title 
        self.sha256 = ida_nalt.retrieve_input_file_sha256().hex()
        self.md5 = ida_nalt.retrieve_input_file_md5().hex()
        self.ctmfiles = cythereal_magic.FilesApi(magic_api_client) 

        self.parent: QtWidgets.QWidget # overarching pyqt widget of this form

        # main pyqt widgets used
        self.t1: QtWidgets.QLabel
        self.t2: QtWidgets.QLabel
        self.pushbutton: QtWidgets.QPushButton
        self.tab_tables: QtWidgets.QTabWidget
        self.textbrowser: QtWidgets.QTextEdit

        # pyqt widgets in tab_tables
        # analysis tab
        self.files_analysis_tab: QtWidgets.QWidget
        self.files_analysis_tab_table: QtWidgets.QTableWidget

        # show widget on creation of new form
        self.Show()         

    def OnCreate(self, form):
        """
        Called when the widget is created.
        """
        # Convert form to PyQt obj
        self.parent = self.FormToPyQtWidget(form)

        self.load_files_view()
     
    def OnClose(self, form):
        """
        Called when the widget is closed.
        """
        return

    def Show(self):
        """
        Take created widget object and display it on IDA's GUI
        """
        #show with intrinsic title, specific options
        return super().Show(
            self.title,
            options=(
            # for some reason the options appear to only work once after resetting desktop in IDA
            ida_kernwin.PluginForm.WOPN_TAB
            | ida_kernwin.PluginForm.WOPN_RESTORE
            | ida_kernwin.PluginForm.WCLS_CLOSE_LATER
            | ida_kernwin.PluginForm.WCLS_SAVE
            ),
        )
 
    """
    functions for building and displaying pyqt.
    """
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
        layout = QtWidgets.QVBoxLayout()

        #adding widgets to layout, order here matters
        layout.addWidget(self.t1)
        layout.addWidget(self.t2)
        layout.addWidget(self.pushbutton)
        layout.addWidget(self.tab_tables)
        layout.addWidget(self.textbrowser)

        # set main widget's layout based on the above items
        self.parent.setLayout(layout)

    def init_files_view(self):
        """
        Initialize individual items which will be added to the form.
        """
        #personalizing QT items, in order of appearance (order is set by layout though)
        self.t1 = QtWidgets.QLabel("Lorem Ipsum <font color=red>Cythereal</font>")
        self.t2 = QtWidgets.QLabel("Lorem Ipsum <font color=blue>MAGIC</font>")

        self.pushbutton = QtWidgets.QPushButton("request files")
        self.pushbutton.setCheckable(False)

        self.tab_tables = QtWidgets.QTabWidget() # create overarching tab widget
        self.init_and_populate_files_analysis_tab() # help create items in analysis tab, add to tab widget 

        self.textbrowser = QtWidgets.QTextEdit()
        self.textbrowser.setReadOnly(True)

        #connecting events to items if necessary, in order of appearance
        self.pushbutton.clicked.connect(self.pushbutton_click)

    """
    functions for connecting pyqt signals
    """
    def pushbutton_click(self):
        """
        User clicks "get resources" button, call cythereal API and populate tables.

        Provide information through textbox
        """
        self.textbrowser.clear()

        self.get_and_populate_tables()