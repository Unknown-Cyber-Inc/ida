from MAGIC import MAGIC_plugin

def PLUGIN_ENTRY():
    """
    python plugin entrypoint for IDA. You'll see it in Edit -> Plugins -> PLUGIN_NAME.
    
    @return ida_idaapi.plugin_t: plugin object
    """
    return MAGIC_plugin()
