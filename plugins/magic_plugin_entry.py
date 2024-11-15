"""
Required entrypoint by IDA.

All IDA python files placed in the plugin folder must contain a unique definition to PLUGIN_ENTRY(),
which returns the plugin class that tells IDA what to do with it during certain events.
"""
import importlib
import idamagic


def PLUGIN_ENTRY():
    """
    python plugin entrypoint for IDA. You'll see it in Edit -> Plugins -> PLUGIN_NAME.

    @return ida_idaapi.plugin_t: plugin object
    """
    importlib.reload(idamagic)
    return idamagic.magic()
