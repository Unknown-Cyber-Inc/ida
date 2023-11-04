"""
Contains IDA UI hooks for the plugin widgets.
"""

import ida_kernwin
import logging

from PyQt5 import QtWidgets
from idamagic.main_interface import MAGICMainClass

logger = logging.getLogger(__name__)


def register_autoinst_hooks(
    name, api_client, form_type: ida_kernwin.PluginForm
):
    """
    Register hook to start unknowncyber_interface automatically at IDA launch,
    if previously unclosed during last session.

    PARAMETERS
    ----------
    name: str
        The name of the plugin to select.
    api_client: cythereal_magic.apiClient
        cythereal_magic's API client to access the system.
    form_type: ida_kernwin.PluginForm
        The type of form which is to be hooked and returned
    MAGIC_inst_auto_hook: ida_kernwin.UI_Hooks (global)
        hook to register globally with IDA.
    MAGIC_procedures_inst_auto_hook: ida_kernwin.UI_Hooks (global)
        hook to register globally with IDA.
    """

    class MAGIC_main_inst_auto_hook_t(ida_kernwin.UI_Hooks):
        """
        Same as above but for the main widget
        """

        def create_desktop_widget(self, ttl, cfg):
            if ttl == name:
                MAGICWidgetPage = form_type(name, api_client, autoinst=True)
                return MAGICWidgetPage.GetWidget()

    if form_type is MAGICMainClass:
        global MAGIC_main_inst_auto_hook
        MAGIC_main_inst_auto_hook = MAGIC_main_inst_auto_hook_t()
        MAGIC_main_inst_auto_hook.hook()


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
        eaKey = ida_kernwin.ea2str(ea).split(":")[1]
        eaKey = int(eaKey, 16)
        if eaKey in self.procedureEADict:
            procedureItemRow = self.procedureEADict[eaKey]
            row = procedureItemRow
            self.proc_table.setCurrentCell(row, 0)
            item_to_scroll_to = self.proc_table.item(row, 0)
            self.proc_table.scrollToItem(
                item_to_scroll_to, QtWidgets.QAbstractItemView.PositionAtTop
            )
        elif eaKey in self.procedureEADict_unbased:
            procedureItemRow = self.procedureEADict_unbased[eaKey]
            row = procedureItemRow
            self.proc_table.setCurrentCell(row, 0)
            item_to_scroll_to = self.proc_table.item(row, 0)
            self.proc_table.scrollToItem(
                item_to_scroll_to, QtWidgets.QAbstractItemView.PositionAtTop
            )

    def ready_to_run(self, *args):
        return
