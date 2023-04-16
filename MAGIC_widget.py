#IDA and UI imports
import ida_idaapi
import ida_kernwin
import ida_nalt
from PyQt5 import QtWidgets

#imports for setup
import os
from dotenv import load_dotenv 

#cythereal magic for calling API
import cythereal_magic

# .env should be in the MAGIC folder
load_dotenv(os.path.join(os.path.dirname(os.path.realpath(__file__)),'MAGIC','.env'))

# load_dotenv sources the below environment variables from .env
PLUGIN_DEVELOP = True if os.getenv("PLUGIN_DEVELOP") == "True" else False
PLUGIN_DEBUG = True if os.getenv("PLUGIN_DEBUG") == "True" else False

#ida plugin related constants
PLUGIN_NAME = 'MAGIC interface'
PLUGIN_HOTKEY = 'Ctrl-Shift-A'
PLUGIN_COMMENT = 'MAGICwidgettest'
PLUGIN_HELP = ''
PLUGIN_VERSION = '0.0.1'
PLUGIN_WINDOW_TITLE = 'MAGIC interface'

# -----------------------------------------------------------------------
"""
This is IDA's chooser class. It is essentially a table with selectable lines
"""
class FileListChooser(ida_kernwin.Choose):
    def __init__(self, title):
        super().__init__(
            title,
            [ ["Sha1", 10 | ida_kernwin.Choose.CHCOL_HEX],
            ["Filetype",    30 | ida_kernwin.Choose.CHCOL_PLAIN] ],
            embedded=True)
        self.items = []

        # .Embedded or .Show is REQUIRED to get the widget pointer
        # .Show will not work since we set embedded=True
        self.Embedded()
        
    def OnGetSize(self):
        return len(self.items)
    
    def OnGetLine(self, n):
        return self.items[n]
    
    def SetItems(self,items=[]):
        self.items = items

# -----------------------------------------------------------------------
"""
populate_pluginform_with_pyqt_widgets.py code was used to create the base of the plugin
this is the entire body of the plugin form
"""
class MAGICPluginFormClass(ida_kernwin.PluginForm):

    """
    We need both the qw widget to add it to the pyqt layout object
    and the tw object to actually make modifications to it
    instead of making PluginForm.objecttw and PluginForm.objectqw
    I made this class to automatically create the qw from passed tw
    and store both in the same object
    """
    class TWidgetToPyQtWidget:
        def __init__(self,tw:object):
            self.tw = tw # tw is IDA python Twidget
            # qw is PyQt5 QtWidget
            self.qw = ida_kernwin.PluginForm.TWidgetToPyQtWidget(tw.GetWidget())


    def __init__(self):
        super().__init__()     

    def OnCreate(self, form):
        """
        Called when the widget is created
        """
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
        """
        Called when the widget is closed
        """
        pass

    def Show(self,title):
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
            self.filechooser.tw.SetItems([ [ resource.sha1, resource.filetype ] for resource in ctmr.resources ])
            self.filechooser.tw.Refresh()
            self.textbrowser.append('Resources gathered successfully.')
        except:
            self.textbrowser.append('No resources could be gathered.')
            if PLUGIN_DEBUG: 
                import traceback
                self.textbrowser.append(traceback.format_exc())


# -----------------------------------------------------------------------
# """
# auto_instantiate_widget_plugin.py code was used to make the plugin window persist on IDA launch
# """
# def register_autoinst_hooks():
#     """
#     Register hooks that will create the widget when IDA
#     requires it because of the IDB/desktop
#     """
#     class auto_inst_hooks_t(ida_kernwin.UI_Hooks):
#         def create_desktop_widget(self, ttl, cfg):
#             if ttl == PLUGIN_WINDOW_TITLE:
#                 MAGICWidgetPage = MAGICPluginFormClass(PLUGIN_WINDOW_TITLE)
#                 assert(MAGICWidgetPage.Show(PLUGIN_WINDOW_TITLE))
#                 return MAGICWidgetPage.GetWidget()

#     global auto_inst_hooks
#     auto_inst_hooks = auto_inst_hooks_t()
#     auto_inst_hooks.hook()

# -----------------------------------------------------------------------
"""
this is the class which manages the plugin entry
"""
class MAGIC_widget_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP 
    if PLUGIN_DEVELOP: flags = ida_idaapi.PLUGIN_UNL #dev entry - unload plugin from memory when widget is closed
    comment = PLUGIN_COMMENT
    help = PLUGIN_HELP
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    """
    what to do on IDA startup
    """
    def init(self):
        #check if our widget is registered with IDA
        #if found, display it
        #if not found, register it
        # register_autoinst_hooks()

        print('MAGIC widget -- hotkey is \"%s\"' % PLUGIN_HOTKEY)
        return ida_idaapi.PLUGIN_KEEP

    """
    what to do when running the plugin through shortcut or Edit -> Plugins -> PLUGIN_NAME
    """
    def run(self, arg):
        # if IDA widget with our title does not exist, create it and populate it. Do nothing otherwise.
        if ida_kernwin.find_widget(PLUGIN_WINDOW_TITLE) is None:
            MAGICWidgetPage = MAGICPluginFormClass()
            MAGICWidgetPage.Show(PLUGIN_WINDOW_TITLE)

    """
    what to do on IDA shutdown
    """
    def term(self):
        pass

# -----------------------------------------------------------------------
"""
this is the required function that IDA uses as an entry to the plugin functionality
you'll see it in Edit -> Plugins -> PLUGIN_NAME
"""
def PLUGIN_ENTRY():
    return MAGIC_widget_t()
