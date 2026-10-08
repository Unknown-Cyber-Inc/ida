"""IDA plugin entry point for the Unknown Cyber MAGIC plugin.

IDA imports every ``*.py`` file in its plugins directory and calls
``PLUGIN_ENTRY()``.  Everything else lives in the ``unknowncyber`` package next
to this file so that this module stays tiny and import-safe.
"""


def PLUGIN_ENTRY():
    from unknowncyber import UnknownCyberPlugin

    return UnknownCyberPlugin()
