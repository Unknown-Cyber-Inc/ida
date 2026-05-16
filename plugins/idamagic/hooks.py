"""
Contains IDA UI hooks for the plugin widgets.
"""

import ida_idaapi
import ida_kernwin
import logging

from PyQt5 import QtWidgets
from idamagic.main_interface import MAGICMainClass

logger = logging.getLogger(__name__)


def register_autoinst_hooks(
    name, ctx, form_type: ida_kernwin.PluginForm
):
    """
    Register hook to start unknowncyber_interface automatically at IDA launch,
    if previously unclosed during last session.

    PARAMETERS
    ----------
    name: str
        The name of the plugin to select.
    ctx: idamagic.core.context.PluginContext
        Shared plugin state, including the API client.
    form_type: ida_kernwin.PluginForm
        The type of form which is to be hooked and returned
    Returns the hook handle so the caller can unhook in term().
    """

    class MAGIC_main_inst_auto_hook_t(ida_kernwin.UI_Hooks):
        """
        Same as above but for the main widget
        """

        def create_desktop_widget(self, ttl, cfg):
            if ttl == name:
                MAGICWidgetPage = form_type(name, ctx, autoinst=True)
                return MAGICWidgetPage.GetWidget()

    if form_type is MAGICMainClass:
        global MAGIC_main_inst_auto_hook
        MAGIC_main_inst_auto_hook = MAGIC_main_inst_auto_hook_t()
        MAGIC_main_inst_auto_hook.hook()
        return MAGIC_main_inst_auto_hook
    return None


class PluginScrHooks(ida_kernwin.UI_Hooks):
    """Hooks necessary for the functionality of the procedure widget form (IDA_interface)

    Connect to IDA's screen_ea_changed hook.
    In a way, "notifies" the plugin when user clicks on or scrolls to different addresses in IDA.
    Since this class is for use by IDA_interface only, "self" refers to type MAGICPluginScrClass.
    """

    def __init__(
        self, proc_table, procedureEADict, procedureEADict_unbased, *args
    ):
        super().__init__(*args)
        # needs to be able to access the proc_table view once generated
        self.proc_table = proc_table
        self.procedureEADict = procedureEADict
        self.procedureEADict_unbased = procedureEADict_unbased

    def screen_ea_changed(self, ea, prev_ea):
        # `ea` is already an int. The previous string-round-trip via
        # ea2str().split(":")[1] crashes with IndexError whenever IDA
        # returns a string without a segment prefix (unmapped EAs,
        # navigation band, etc). It also threw on BADADDR.
        if ea is None or ea == ida_idaapi.BADADDR:
            return

        if ea in self.procedureEADict:
            ea_text = self.procedureEADict[ea]
        elif ea in self.procedureEADict_unbased:
            ea_text = self.procedureEADict_unbased[ea]
        else:
            return

        row = self.search_table(ea_text)
        if row is None:
            return
        self.proc_table.setCurrentCell(row, 0)
        item_to_scroll_to = self.proc_table.item(row, 0)
        self.proc_table.scrollToItem(
            item_to_scroll_to, QtWidgets.QAbstractItemView.PositionAtTop
        )

    def search_table(self, ea_text):
        """Search through the table to find the current position of the EA."""
        for row in range(self.proc_table.rowCount()):
            item = self.proc_table.item(row, 0)
            if item:
                item_text = item.text()
                if ea_text in item_text:
                    return row
        return None

    def ready_to_run(self, *args):
        return
