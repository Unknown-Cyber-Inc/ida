"""Minimal stand-in for ida_idaapi used by the headless tests."""

PLUGIN_FIX = 0x80
PLUGIN_KEEP = 2
PLUGIN_SKIP = 0
PLUGIN_OK = 1
BADADDR = 0xFFFFFFFFFFFFFFFF


class plugin_t:  # noqa: N801 - IDA naming
    def __init__(self):
        pass
