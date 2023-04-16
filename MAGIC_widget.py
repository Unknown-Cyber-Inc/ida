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
populate_pluginform_with_pyqt_widgets.py code was used to create the base of the plugin
"""
class MAGICPluginFormClass(ida_kernwin.PluginForm):
    def OnCreate(self, form):
        """
        Called when the widget is created
        """
        # Get parent widget
        self.parent = self.FormToPyQtWidget(form)
        self.sha256 = ida_nalt.retrieve_input_file_sha256().hex()
        self.md5 = ida_nalt.retrieve_input_file_md5().hex()
        try:
            self.ctm = cythereal_magic.ApiClient()
            self.ctmf = cythereal_magic.FilesApi(self.ctm)
        except:
            print("Error establishing magic API client.")
            self.ctm = None
            self.ctmf = None
        self.PopulateForm()

    def PopulateForm(self):
        # Create layout
        layout = QtWidgets.QVBoxLayout()

        #personalizing widgets
        self.t1 = QtWidgets.QLabel("Hello from <font color=red>PyQt</font>")
        self.t2 = QtWidgets.QLabel("Hello from <font color=blue>IDAPython</font>")

        self.pushbutton = QtWidgets.QPushButton("request files")
        self.pushbutton.setCheckable(True)
        self.pushbutton.clicked.connect(self.pushbutton_click)

        self.textbrowser = QtWidgets.QTextEdit()
        self.textbrowser.setReadOnly(True)

        #adding widgets
        layout.addWidget(self.t1)
        layout.addWidget(self.t2)
        layout.addWidget(self.pushbutton)
        layout.addWidget(self.textbrowser)

        self.parent.setLayout(layout)

    def OnClose(self, form):
        """
        Called when the widget is closed
        """
        pass

    def pushbutton_click(self, form):
        self.textbrowser.clear()
        try:
            ctmr = self.ctmf.list_files()
            for resource in ctmr.resources:
                self.textbrowser.append(resource.sha1 + ': ' + resource.filetype)
        except:
            self.textbrowser.append('No resources could be gathered.')

# -----------------------------------------------------------------------
"""
auto_instantiate_widget_plugin.py code was used to make the plugin window persist on IDA launch
"""
def register_autoinst_hooks():
    """
    Register hooks that will create the widget when IDA
    requires it because of the IDB/desktop
    """
    class auto_inst_hooks_t(ida_kernwin.UI_Hooks):
        def create_desktop_widget(self, ttl, cfg):
            if ttl == PLUGIN_WINDOW_TITLE:
                MAGICWidgetPage = MAGICPluginFormClass()
                assert(MAGICWidgetPage.Show(PLUGIN_WINDOW_TITLE))
                return MAGICWidgetPage.GetWidget()

    global auto_inst_hooks
    auto_inst_hooks = auto_inst_hooks_t()
    auto_inst_hooks.hook()

# -----------------------------------------------------------------------
"""
this is the class which manages the plugin entry
"""
class MAGIC_widget_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP 
    if PLUGIN_DEVELOP: flags = ida_idaapi.PLUGIN_UNL #dev entry - unload plugin from memory when finished
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
        register_autoinst_hooks()

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
