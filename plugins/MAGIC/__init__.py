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
from ida_kernwin import find_widget,is_idaq,close_widget

#cythereal magic for calling API
import cythereal_magic
# other MAGIC imports
from MAGIC import unknowncyber_interface
from MAGIC import IDA_interface
from MAGIC import MAGIC_hooks

PLUGIN_DEVELOP = True if os.getenv("PLUGIN_DEVELOP") == "True" else False
PLUGIN_DEVELOP_RECREATE_WIDGETS = True if os.getenv("PLUGIN_DEVELOP_RECREATE_WIDGETS") == "True" else False
PLUGIN_DEVELOP_LOCAL_API = True if os.getenv("PLUGIN_DEVELOP_LOCAL_API") == "True" else False
PLUGIN_DEBUG = True if os.getenv("PLUGIN_DEBUG") == "True" else False

#create local API client to be used by plugin
# if .env says to use unknowncyber at localhost, then replace the default host and key value
if PLUGIN_DEVELOP and PLUGIN_DEVELOP_LOCAL_API:
    os.environ["MAGIC_API_HOST"] = os.getenv("MAGIC_API_HOST_LOCAL")
    os.environ["MAGIC_API_KEY"] = os.getenv("MAGIC_API_KEY_LOCAL")
    apiconfig = cythereal_magic.Configuration()
    # apiconfig.verify_ssl works but prints warnings. if you have a local instance it will contain dev.crt anyway.
    apiconfig.ssl_ca_cert = os.getenv("PLUGIN_DEVELOP_LOCAL_CERT_PATH")
    plugin_api_client = cythereal_magic.ApiClient(configuration=apiconfig)
else:
    # create default client for interacting with cythereal magic website
    plugin_api_client = cythereal_magic.ApiClient()
PLUGIN_API_CLIENT = plugin_api_client

#ida synchronized scroll widget constants
PLUGIN_SCROLLWIDGET_NAME = 'MAGIC Procedures'
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
        self.form: unknowncyber_interface.MAGICPluginFormClass

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
        
        #display hotkey to user
        print('\nMAGIC widget -- hotkey is \"'+PLUGIN_HOTKEY+'\"')
      
        if PLUGIN_DEBUG: 
            print("MAGIC running mode DEBUG")
        if PLUGIN_DEVELOP: 
            print("MAGIC running mode DEVELOP")
            ida_idaapi.require("MAGIC.unknowncyber_interface") # reloads the module so we can make changes without restarting IDA
            ida_idaapi.require("MAGIC.IDA_interface")
            ida_idaapi.require("MAGIC.MAGIC_hooks")
            return ida_idaapi.PLUGIN_OK
        
        # check if our widget is registered with IDA
        # if found, display it
        # if not found, register it
        self.form = MAGIC_hooks.register_autoinst_hooks(PLUGIN_NAME)

        return ida_idaapi.PLUGIN_KEEP

    def run(self, args):
        """
        Edit -> Plugins -> PLUGIN_NAME or the plugin shortcut has been hit. This should have most of the functionality.
        
        @param args: int, most likely bits demonstrating different flags. More research required
        """
    
        # in development mode, close and reopen the widget every time the shortcut is hit
        if PLUGIN_DEVELOP and PLUGIN_DEVELOP_RECREATE_WIDGETS:
            close_widget(find_widget(PLUGIN_NAME),0)
            close_widget(find_widget(PLUGIN_SCROLLWIDGET_NAME),0)
        
        # if IDA widget with our title does not exist, create it and populate it. Do nothing otherwise.
        if find_widget(PLUGIN_NAME) is None:
            self.form = unknowncyber_interface.MAGICPluginFormClass(PLUGIN_NAME,PLUGIN_API_CLIENT)
        if find_widget(PLUGIN_SCROLLWIDGET_NAME) is None:    
            self.syncscroll = IDA_interface.MAGICPluginScrClass(PLUGIN_SCROLLWIDGET_NAME,PLUGIN_API_CLIENT)

    def term(self):
        """
        Plugin is unloaded by IDA.
        """
        pass