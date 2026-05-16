"""
Main plugin object at the highest level.

Contains ida_idaapi.plugin_t and environment variable information.
Will contain auto_inst_hooks if they are available
"""

import cythereal_magic as unknowncyber
import ida_idaapi
import ida_kernwin
import logging
import os

from dotenv import load_dotenv
from ida_kernwin import find_widget, is_idaq, close_widget

from .unknowncyber_interface import MAGICPluginFormClass
from .IDA_interface import MAGICPluginScrClass
from .main_interface import MAGICMainClass
from .hooks import register_autoinst_hooks

# load_dotenv sources the below environment variables from .env
# .env should be in the idamagic folder
# os.path ensures this will always be the correct absolute path
load_dotenv(os.path.join(os.path.dirname(os.path.realpath(__file__)), ".env"))

logging.basicConfig(level=os.getenv("IDA_LOGLEVEL", "INFO"))
logger = logging.getLogger(__name__)

# Ida plugin constants
MAIN_PLUGIN_NAME = "UnknownCyber Magic Plugin"
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


class magic(ida_idaapi.plugin_t):
    """
    Inherits base IDA plugin class.

    Declare attributes below which are parsed by IDA to appropriate UI spots around IDA.
    For example, wanted_hotkey shows up in Edit -> Plugins to the right of wanted_name.
    This hotkey is linked to plugin_t.run().
    """

    flags = ida_idaapi.PLUGIN_FIX
    main_widget = MAGICMainClass
    syncscroll = MAGICPluginScrClass
    form = MAGICPluginFormClass

    # required or otherwise handled by IDA
    main_name = MAIN_PLUGIN_NAME
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
            logger.warning(
                "This plugin is not yet built for the terminal version."
            )
            return ida_idaapi.PLUGIN_SKIP

        # display hotkey to user
        logger.info(f'MAGIC widget -- hotkey is "{self.wanted_hotkey}"')

        self.api_client = (
            unknowncyber.ApiClient()
        )  # Create API client to be used by plugin

        self.api_client.configuration.api_key["key"] = os.getenv("MAGIC_API_KEY")
        self.api_client.configuration.host = os.getenv("MAGIC_API_HOST")

        ida_idaapi.require("idamagic.main_interface")
        ida_idaapi.require("idamagic.unknowncyber_interface")
        ida_idaapi.require("idamagic.IDA_interface")
        ida_idaapi.require("idamagic.hooks")

        # Keep a handle on the auto-instantiation hook so we can unhook in term().
        self.autoinst_hook = register_autoinst_hooks(
            self.main_name, self.api_client, MAGICMainClass
        )
        # Do not store the hook in `self.main_widget` - that field is meant
        # for the widget instance and is populated on first run().
        self.main_widget = None
        return ida_idaapi.PLUGIN_KEEP

    def run(self, args):
        """
        Edit -> Plugins -> PLUGIN_NAME or the plugin shortcut has been hit.
        This should have most of the functionality.

        @param args: int, most likely bits demonstrating different flags. More research required
        """
        existing = find_widget(self.main_name)
        if existing is None:
            logger.debug("Creating MAGIC main form")
            self.main_widget = MAGICMainClass(self.main_name, self.api_client)
        else:
            # Re-focus the existing widget instead of doing nothing.
            ida_kernwin.activate_widget(existing, True)

    def term(self):
        """
        Plugin is unloaded by IDA. Clean up hooks and the widget.
        """
        try:
            if getattr(self, "autoinst_hook", None) is not None:
                self.autoinst_hook.unhook()
                self.autoinst_hook = None
        except Exception:
            logger.exception("Failed to unhook autoinst hook")

        try:
            w = find_widget(self.main_name)
            if w is not None:
                close_widget(w, 0)
        except Exception:
            logger.exception("Failed to close main widget on term")
