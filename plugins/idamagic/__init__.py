"""
Main plugin object at the highest level.

Contains ida_idaapi.plugin_t and environment variable information.
Will contain auto_inst_hooks if they are available
"""

import cythereal_magic as unknowncyber
import ida_idaapi
import logging
import os

from dotenv import load_dotenv
from ida_kernwin import find_widget, is_idaq, close_widget

from .helpers import to_bool
from .unknowncyber_interface import MAGICPluginFormClass
from .IDA_interface import MAGICPluginScrClass
from .hooks import register_autoinst_hooks

# load_dotenv sources the below environment variables from .env
# .env should be in the idamagic folder
# os.path ensures this will always be the correct absolute path
load_dotenv(os.path.join(os.path.dirname(os.path.realpath(__file__)), ".env"))

logging.basicConfig(level=os.getenv("IDA_LOGLEVEL", "INFO"))
logger = logging.getLogger(__name__)

# Ida plugin constants
PLUGIN_NAME = "Unknown Cyber MAGIC"
PLUGIN_HOTKEY = "Ctrl-Shift-A"
PLUGIN_COMMENT = "IDA interface for Unknown Cyber MAGIC"
PLUGIN_HELP = """
Upload and request information about owned files.
Not yet implemented for the terminal version of IDA."
"""
PLUGIN_VERSION = "0.0.1"

# Ida synchronized scroll widget constants
SCROLLWIDGET_TITLE = "MAGIC Genomics"

HOT_RELOAD = to_bool(os.getenv("HOT_RELOAD"))


class magic(ida_idaapi.plugin_t):
    """
    Inherits base IDA plugin class.

    Declare attributes below which are parsed by IDA to appropriate UI spots around IDA.
    For example, wanted_hotkey shows up in Edit -> Plugins to the right of wanted_name.
    This hotkey is linked to plugin_t.run().
    """

    # unload plugin from memory when widget is closed
    if HOT_RELOAD:
        flags = ida_idaapi.PLUGIN_UNL
    else:
        flags = ida_idaapi.PLUGIN_FIX

    form = MAGICPluginFormClass

    # required or otherwise handled by IDA
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY
    comment = PLUGIN_COMMENT
    help = PLUGIN_HELP
    version = PLUGIN_VERSION

    def init(self):
        """
        IDA initializes and begins loading plugins. This is not the same as plugin_t's __init__.

        This is run once per plugin unless, for example, PLUGIN_UNL is specified in flags.
        @return literals defined by PLUGIN_SKIP, PLUGIN_KEEP, or PLUGIN_OK.
        """
        # check if this is the GUI version of IDA
        if not is_idaq():
            os.system(
                "echo This plugin is not yet built for the terminal version."
            )
            return ida_idaapi.PLUGIN_SKIP

        # display hotkey to user
        logger.info(f'MAGIC widget -- hotkey is "{self.wanted_hotkey}"')

        logger.debug(logger)

        self.api_client = unknowncyber.ApiClient()  # Create API client to be used by plugin

        if HOT_RELOAD:
            logger.info("MAGIC plugin is hot reloadable")
            ida_idaapi.require(
                "idamagic.unknowncyber_interface"
            )  # reloads the module so we can make changes without restarting IDA
            ida_idaapi.require("idamagic.IDA_interface")
            ida_idaapi.require("idamagic.hooks")
            return ida_idaapi.PLUGIN_OK

        # check if our widget is registered with IDA
        # if found, display it
        # if not found, register it
        self.form = register_autoinst_hooks(self.wanted_name, self.api_client, MAGICPluginFormClass)
        self.syncscroll = register_autoinst_hooks(SCROLLWIDGET_TITLE,
                                                  self.api_client,
                                                  MAGICPluginScrClass)

        return ida_idaapi.PLUGIN_KEEP

    def run(self, args):
        """
        Edit -> Plugins -> PLUGIN_NAME or the plugin shortcut has been hit.
        This should have most of the functionality.

        @param args: int, most likely bits demonstrating different flags. More research required
        """

        # close and reopen the widget
        if HOT_RELOAD:
            logger.debug("Reloading MAGIC")
            close_widget(find_widget(self.wanted_name), 0)
            close_widget(find_widget(SCROLLWIDGET_TITLE), 0)

        # if IDA widget with our title does not exist,
        # create it and populate it. Do nothing otherwise.
        if find_widget(self.wanted_name) is None:
            logger.debug("Creating MAGIC plugin form")
            self.form = MAGICPluginFormClass(self.wanted_name, self.api_client)
        if find_widget(SCROLLWIDGET_TITLE) is None:
            logger.debug("Creating MAGIC plugin sync scroll")
            self.syncscroll = MAGICPluginScrClass(
                SCROLLWIDGET_TITLE, self.api_client,
            )

    def term(self):
        """
        Plugin is unloaded by IDA.
        """
        pass
