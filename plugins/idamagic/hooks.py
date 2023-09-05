"""
Contains IDA UI hooks for the plugin widgets.
"""

import ida_kernwin
import logging

from idamagic.unknowncyber_interface import MAGICPluginFormClass
from idamagic.IDA_interface import MAGICPluginScrClass
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

    def __init__(self, proc_tree, procedureEADict, procWidgetParent, *args):
        super().__init__(*args)
        # needs to be able to access the proc_tree view once generated
        self.procWidgetParent = procWidgetParent
        self.proc_tree = proc_tree
        self.procedureEADict = procedureEADict

    def screen_ea_changed(self, ea, prev_ea):
        eaKey = ida_kernwin.ea2str(ea).split(":")[1]
        eaKey = int(eaKey, 16)
        if eaKey in self.procedureEADict:
            procedureQIndexItem = self.procedureEADict[eaKey].index()
            self.proc_tree.setCurrentIndex(
                procedureQIndexItem
            )  # highlight and select it
            if not self.proc_tree.isExpanded(
                procedureQIndexItem
            ):  # do not expand before checking if expanded, see proc_tree_jump_to_hex for info
                self.proc_tree.expand(procedureQIndexItem)
                print(procedureQIndexItem)
            # 3 is an enum telling the widget to open with the item in the center
            self.proc_tree.scrollTo(
                procedureQIndexItem, 3
            )  # jump to and center it

    # this object will not have "parent" until all UI objects are loaded
    # additionally, this 'ready_to_run' will only occur once on initialization
    def ready_to_run(self, *args):
        # self.procWidgetParent.parent().parent().setSizes([100, 1])
        return
