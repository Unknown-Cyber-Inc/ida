from MAGIC import MAGIC_plugin

"""
this is the required function that IDA uses as an entry to the plugin functionality
you'll see it in Edit -> Plugins -> PLUGIN_NAME
"""
def PLUGIN_ENTRY():
    return MAGIC_plugin()
