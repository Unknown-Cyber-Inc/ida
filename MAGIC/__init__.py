#IDA imports
import ida_idaapi
from ida_kernwin import find_widget,is_idaq,UI_Hooks
import ida_kernwin

# other MAGIC imports
from MAGIC.MAGIC_form import MAGICPluginFormClass, FileListChooser
# from MAGIC.MAGIC_hooks import register_open_action

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

class MAGIC_plugin(ida_idaapi.plugin_t):
    """
    this is the class which manages the plugin entry
    """

    flags = ida_idaapi.PLUGIN_KEEP 
    if PLUGIN_DEVELOP: flags = ida_idaapi.PLUGIN_UNL #dev entry - unload plugin from memory when widget is closed
    comment = PLUGIN_COMMENT
    help = PLUGIN_HELP
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY
    version = PLUGIN_VERSION

    def init(self):
        """
        what to do on IDA startup
        """
        # check if this is the GUI version of IDA
        if not is_idaq():
            os.system("echo this plugin is not yet built for the terminal version.")
            return ida_idaapi.PLUGIN_SKIP
        
        #check if our widget is registered with IDA
        #if found, display it
        #if not found, register it
        # register_autoinst_hooks()

        print('\nMAGIC widget -- hotkey is \"'+PLUGIN_HOTKEY+'\"')
        if PLUGIN_DEVELOP: print("MAGIC running mode DEVELOP")
        if PLUGIN_DEBUG: print("MAGIC running mode DEBUG")

        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        """
        what to do when running the plugin through shortcut or Edit -> Plugins -> PLUGIN_NAME
        """
        # if IDA widget with our title does not exist, create it and populate it. Do nothing otherwise.
        if find_widget(PLUGIN_NAME) is None:
            MAGICPluginFormClass().Show(PLUGIN_NAME)

    def Create(self):
        pass

    def term(self):
        """
        what to do on IDA shutdown
        """
        pass