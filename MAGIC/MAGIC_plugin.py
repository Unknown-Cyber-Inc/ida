#IDA imports
import ida_idaapi
from ida_kernwin import find_widget

# other MAGIC imports
from MAGIC.MAGIC_form import MAGICPluginFormClass
from MAGIC.MAGIC_hooks import register_autoinst_hooks

"""
imports for setup
load_dotenv sources the below environment variables from .env
.env should be in the MAGIC folder and os.path ensures this will always be the correct absolute path
"""
import os
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.realpath(__file__)),'.env'))

PLUGIN_DEVELOP = True if os.getenv("PLUGIN_DEVELOP") == "True" else False
PLUGIN_DEBUG = True if os.getenv("PLUGIN_DEBUG") == "True" else False

#ida plugin constants
PLUGIN_NAME = 'MAGIC'
PLUGIN_HOTKEY = 'Ctrl-Shift-A'
PLUGIN_COMMENT = 'IDA interface for Cythereal MAGIC'
PLUGIN_HELP = 'Upload and request information about owned files. Not yet implemented for the terminal version of IDA.'
PLUGIN_VERSION = '0.0.1'

"""
this is the class which manages the plugin entry
"""
class MAGIC_plugin_t(ida_idaapi.plugin_t):

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
        # register_autoinst_hooks(PLUGIN_NAME)

        print('\nMAGIC widget -- hotkey is \"'+PLUGIN_HOTKEY+'\"')
        if PLUGIN_DEVELOP: print("MAGIC running mode DEVELOP")
        if PLUGIN_DEBUG: print("MAGIC running mode DEBUG")

        return ida_idaapi.PLUGIN_KEEP

    """
    what to do when running the plugin through shortcut or Edit -> Plugins -> PLUGIN_NAME
    """
    def run(self, arg):
        # if IDA widget with our title does not exist, create it and populate it. Do nothing otherwise.
        if find_widget(PLUGIN_NAME) is None:
            MAGICWidgetPage = MAGICPluginFormClass()
            MAGICWidgetPage.Show(PLUGIN_NAME)

    """
    what to do on IDA shutdown
    """
    def term(self):
        pass