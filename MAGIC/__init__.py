"""
Main plugin object at the highest level. 

Contains ida_idaapi.plugin_t and environment variable information.
Will contain auto_inst_hooks if they are available
"""

# imports for setup
# load_dotenv sources the below environment variables from .env
# .env should be in the MAGIC folder and os.path ensures this will always be the correct absolute path
import os
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.realpath(__file__)),'.env'))

#IDA imports
import ida_idaapi
from ida_kernwin import find_widget,is_idaq

# other MAGIC imports
from MAGIC import MAGIC_form

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
    Inherits base IDA plugin class. 
    
    Declare attributes below which are parsed by IDA to appropriate UI spots around IDA.
    For example, wanted_hotkey shows up in Edit -> Plugins to the right of wanted_name.
    This hotkey is linked to plugin_t.run().
    """

    flags = ida_idaapi.PLUGIN_FIX 
    if PLUGIN_DEVELOP: flags = ida_idaapi.PLUGIN_UNL #dev entry - unload plugin from memory when widget is closed
    comment = PLUGIN_COMMENT
    help = PLUGIN_HELP
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY
    version = PLUGIN_VERSION

    def __init__(self):
        super().__init__()
        self.form: MAGIC_form.MAGICPluginFormClass

    def init(self):
        """
        IDA initializes and begins loading plugins. This is not the same as plugin_t's __init__.
        
        This is run once per plugin unless, for example, PLUGIN_UNL is specified in flags.
        @return literals defined by PLUGIN_SKIP, PLUGIN_KEEP, or PLUGIN_OK.
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
        if PLUGIN_DEBUG: 
            print("MAGIC running mode DEBUG")
        if PLUGIN_DEVELOP: 
            print("MAGIC running mode DEVELOP")
            ida_idaapi.require("MAGIC.MAGIC_form") # reloads the module so we can make changes without restarting IDA
            return ida_idaapi.PLUGIN_KEEP
        return ida_idaapi.PLUGIN_OK

    def run(self, args):
        """
        Edit -> Plugins -> PLUGIN_NAME or the plugin shortcut has been hit. This should have most of the functionality.
        
        @param args: int, most likely bits demonstrating different flags. More research required
        """
        # if IDA widget with our title does not exist, create it and populate it. Do nothing otherwise.
        if find_widget(PLUGIN_NAME) is None:
            self.form = MAGIC_form.MAGICPluginFormClass(PLUGIN_NAME)

    def term(self):
        """
        Plugin is unloaded by IDA.
        """
        pass