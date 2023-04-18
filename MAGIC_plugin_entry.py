from MAGIC import MAGIC_plugin

def PLUGIN_ENTRY():
    """
    this is the required function that IDA uses as an entry to the plugin functionality
    you'll see it in Edit -> Plugins -> PLUGIN_NAME
    """
    return MAGIC_plugin()
