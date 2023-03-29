#IDA and UI imports
import ida_idaapi
import ida_kernwin
from PyQt5 import QtCore, QtGui, QtWidgets

#imports for other functionality
import requests

#in development or not, changes that make quick editing easier
DEVELOP = True

#ida plugin related constants
PLUGIN_NAME = 'MAGIC interface'
PLUGIN_HOTKEY = 'Ctrl-Shift-A'
PLUGIN_COMMENT = 'MAGICwidgettest'
PLUGIN_HELP = ''
PLUGIN_VERSION = '0.0.1'
PLUGIN_WINDOW_TITLE = 'MAGIC interface'

#constants related to making requsts to local instance of MAGIC
CYTH_API_MAIN_ENDPOINT = 'https://api:80/v2/'
CYTH_API_CERT_PATH = "/home/luka/Desktop/cythereal/development/certs/dev.crt"
CYTH_API_KEY = "adminkey"

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
        url = CYTH_API_MAIN_ENDPOINT + "files"
        res = requests.get(url=url, params={"key":CYTH_API_KEY}, verify=CYTH_API_CERT_PATH)
        self.textbrowser.clear()
        self.textbrowser.append(str(res.json()))

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
    if DEVELOP: flags = ida_idaapi.PLUGIN_UNL #dev entry - unload plugin from memory when finished
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
