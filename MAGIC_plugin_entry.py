#IDA imports
import ida_idaapi
from ida_kernwin import find_widget

# other MAGIC imports
from MAGIC.MAGIC_form import MAGICPluginFormClass

#imports for setup
import os
from dotenv import load_dotenv 
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
        if find_widget(PLUGIN_WINDOW_TITLE) is None:
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
