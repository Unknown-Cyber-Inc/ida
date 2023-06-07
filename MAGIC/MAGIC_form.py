"""
Main pluginform object at the highest level. 

This is the scaffolding of the form object which will be displayed to the viewer.
Contains ida_kernwin.PluginForm and also ida_kernwin.Choose.
Will likely be broken into components as the insides of the form grow.
"""

# IDA and UI imports
import ida_nalt, ida_kernwin
from PyQt5 import QtWidgets, QtGui

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

    """
    functions for PluginForm object functionality.
    """
    def __init__(self, title, magic_api_client):
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

    def init_and_populate_files_analysis_tab(self):
        """
        Helper, initialize and populate items in analysis tab widget
        """
        # create empty widget and add it as a tab to tab widget
        self.files_analysis_tab = QtWidgets.QWidget()
        self.tab_tables.addTab(self.files_analysis_tab,"Analysis")

        # create the objects that will be placed in the analysis tab widget
        self.files_analysis_tab_table = QtWidgets.QTableWidget()
        self.files_analysis_tab_testbutton = QtWidgets.QPushButton("test")

        # ---------------------------------------------------------------------------
        # populate this tab similar to populate_files_view
        # it's less confusing if individual tab population is not in its own function
        self.files_analysis_tab.layout = QtWidgets.QVBoxLayout()

        self.files_analysis_tab.layout.addWidget(self.files_analysis_tab_table)
        self.files_analysis_tab.layout.addWidget(self.files_analysis_tab_testbutton)

        self.files_analysis_tab.setLayout(self.files_analysis_tab.layout)

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


    def get_and_populate_tables(self):
        """
        calls GET /files and populates the different tables

        Also there must be some way to populate without setting every single row. This might be through some custom table class.
        """
        #setting up column names
        identifier = ["sha256"]
        analysis_tab_columns = ["filenames","filetype"]
        inputfile_highlight_color = QtGui.QColor(255,232,255)

        try:
            # request file from website with the above columns of info
            ctmr = self.ctmfiles.list_files(read_mask=','.join(identifier + analysis_tab_columns))
        except:
            self.textbrowser.append('No files could be gathered.')
            if PLUGIN_DEBUG: 
                import traceback
                self.textbrowser.append(traceback.format_exc())
            return None # don't continue populating on failed call, exit (this func always returns None anyway)
        else:
            self.textbrowser.append('Files gathered successfully.')

        # set row and col of table based on returned data sizes
        self.files_analysis_tab_table.setRowCount(len(ctmr['resources']))
        # number of columns = number of analysis_tab_columns + identifier entry (1)
        self.files_analysis_tab_table.setColumnCount(len(analysis_tab_columns)+1)
        
        # label the column based on returned labels
        self.files_analysis_tab_table.setHorizontalHeaderLabels(identifier + analysis_tab_columns)   
        # hide the row headers
        self.files_analysis_tab_table.verticalHeader().setVisible(False)  

        # this is almost certainly not the most effecient way
        # loop through every single value and add it to the table cell by cell
        for row,resource in enumerate(ctmr['resources']):
            # makae sure first column is always identifier
            self.files_analysis_tab_table.setItem(row, 0, QtWidgets.QTableWidgetItem(resource[identifier[0]]))

            #for this row check if the hash of input file matches the hash of the file in this row and change cell bg color
            current_is_infile = False
            if resource[identifier[0]] == self.sha256:
                self.files_analysis_tab_table.item(row,0).setBackground(inputfile_highlight_color)
                self.files_analysis_tab_table.selectRow(row)
                current_is_infile = True
            
            self.populate_analysis_table_row(resource,row,analysis_tab_columns,current_is_infile,inputfile_highlight_color)

        # resize first column (assuming sha256) to show entire entry
        self.files_analysis_tab_table.resizeColumnToContents(0)
        #stretch the final column to the end of the widget
        self.files_analysis_tab_table.horizontalHeader().setStretchLastSection(True)

    def populate_analysis_table_row(self,resource,row,analysis_tab_columns,current_is_infile,inputfile_highlight_color):
        """
        When looping through returned resources, call this func to populate a row of the table held in the "analysis" tab.

        Needed this function to reduce clutter. Each column in each tab may require specific handling before it can be displayed.
        @param self: overarching MAGICPluginFormClass
        @param resource: a single file object returned when calling GET /files
        @param row: row index
        @param analysis_tab_columns: column names/resource keys as specified at the top of get_and_populate_tables
        @param current_is_infile: boolean on whether or not the current resource is also the input file
        @param inputfile_highlight_color: the QtGui.QColor object defining the color to highlight the infile with
        """
        # check all keys which belong to columns specified by analysis table tab
        # note first col (0) is always identifier. hence why we use col+1
        for col,key in enumerate(analysis_tab_columns):
            # if key requires special handling:
            if key == "filenames":
                self.files_analysis_tab_table.setItem(row, col+1, QtWidgets.QTableWidgetItem(','.join(resource[key])))
            else: # returned item is string, add to table cell as normal
                self.files_analysis_tab_table.setItem(row, col+1, QtWidgets.QTableWidgetItem(resource[key]))

            # current hash is infile, change cell background color so user can identify it easily
            if current_is_infile:
                self.files_analysis_tab_table.item(row,col+1).setBackground(inputfile_highlight_color)
