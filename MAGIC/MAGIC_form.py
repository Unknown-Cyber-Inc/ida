# IDA and UI imports
import ida_nalt, ida_kernwin
from PyQt5 import QtWidgets

#cythereal magic for calling API
import cythereal_magic

# load_dotenv sources the below environment variables from .env
import os
PLUGIN_DEBUG = True if os.getenv("PLUGIN_DEBUG") == "True" else False

# -----------------------------------------------------------------------

class FileListChooser(ida_kernwin.Choose):
    """
    Inhereits IDA's chooser class. By default it is a TWidget.
    
    It is a table with selectable lines.
    """
    def __init__(self, title):
        super().__init__(
            title,
            [ ["Sha1", 10 | ida_kernwin.Choose.CHCOL_HEX],
            ["Filetype",    30 | ida_kernwin.Choose.CHCOL_PLAIN] ],
            )
        self.items = []

        # .Embedded or .Show is REQUIRED to get the widget pointer
        # .Show will not work since we set embedded=True
        self.Show()
        
    def OnGetSize(self):
        return len(self.items)
    
    def OnGetLine(self, n):
        return self.items[n]
    
    def SetItems(self,items=[]):
        """
        Set columns of the chooser from outside the class.

        @param items: array of arrays, with columns = num of table columns and rows = num of entries.
        """
        self.items = items

# -----------------------------------------------------------------------

class MAGICPluginFormClass(ida_kernwin.PluginForm):
    """
    Highest level of the plugin UI object. Inherits ida_kernwin.PluginForm which wraps IDA's Form object as a PyQt object.

    Populate_pluginform_with_pyqt_widgets.py code was used to create the basics of the plugin.
    """
    class TWidgetToPyQtWidget:
        """
        Object grouping TWidgets and their converted QtWidgets

        We need both the qw widget to add it to the pyqt layout object
        and the tw object to actually make modifications to it.
        Instead of making PluginForm.objecttw and PluginForm.objectqw in the form class
        I made this class to automatically create the qw from passed tw
        and store both in the same object.
        """
        def __init__(self,tw:object):
            """ 
            @param tw: TWidget to be converted to QtWidget
            @attribute tw: stored version of passed tw
            @attribute qw: converted QtWidget from tw 
            """
            self.tw = tw # tw is IDA python Twidget
            # qw is PyQt5 QtWidget
            self.qw = ida_kernwin.PluginForm.TWidgetToPyQtWidget(tw.GetWidget())


    def __init__(self):
        super().__init__()     

    def OnCreate(self, form):
        # Convert form to PyQt obj
        self.parent = self.FormToPyQtWidget(form)

        #gather important form information -- consider moving the location of this
        self.sha256 = ida_nalt.retrieve_input_file_sha256().hex()
        self.md5 = ida_nalt.retrieve_input_file_md5().hex()
        self.ctm = cythereal_magic.ApiClient()
        self.ctmfiles = cythereal_magic.FilesApi(self.ctm)

        self.CreateFormObjects()
        self.PopulateForm()

    def OnClose(self, form):
        pass

    def Show(self,title,options=0):
        return super().Show(title)

    def CreateFormObjects(self):

        #personalizing QT widgets
        self.t1 = QtWidgets.QLabel("Hello from <font color=red>PyQt</font>")
        self.t2 = QtWidgets.QLabel("Hello from <font color=blue>IDAPython</font>")

        self.pushbutton = QtWidgets.QPushButton("request files")
        self.pushbutton.setCheckable(True)
        self.pushbutton.clicked.connect(self.pushbutton_click)

        self.textbrowser = QtWidgets.QTextEdit()
        self.textbrowser.setReadOnly(True)

        # personalizing T widgets
        self.filechooser = self.TWidgetToPyQtWidget(FileListChooser("FileListChooser"))


    def PopulateForm(self):
        # Create layout
        layout = QtWidgets.QVBoxLayout()

        #adding widgets
        layout.addWidget(self.t1)
        layout.addWidget(self.t2)
        layout.addWidget(self.pushbutton)
        layout.addWidget(self.filechooser.qw)
        layout.addWidget(self.textbrowser)

        self.parent.setLayout(layout)

    def pushbutton_click(self, form):
        self.textbrowser.clear()

        try:
            # request file from website
            ctmr = self.ctmfiles.list_files()

            # add the resources to the chooser object
            self.filechooser.tw.SetItems([ [ resource['sha1'], resource['filetype'] ] for resource in ctmr['resources'] ])
            self.filechooser.tw.Refresh()
            self.textbrowser.append('Resources gathered successfully.')
        except:
            self.textbrowser.append('No resources could be gathered.')
            if PLUGIN_DEBUG: 
                import traceback
                self.textbrowser.append(traceback.format_exc())