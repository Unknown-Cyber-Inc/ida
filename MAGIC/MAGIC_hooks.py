"""
Will contain IDA UI hooks for the MAGIC plugin.
"""

import ida_kernwin
from MAGIC.unknowncyber_interface import MAGIC_form

def register_autoinst_hooks(PLUGIN_NAME):
    """
    Register hook to start plugin automatically at IDA launch, if previously unclosed during last session.

    @param PLUGIN_NAME: pass the name of the plugin to select it
    @global hook: hook to register globally with IDA
    auto_instantiate_widget_plugin.py code was used to make this.
    """
    class MAGIC_inst_auto_hook_t(ida_kernwin.UI_Hooks):
        """
        Inherets UI_hooks functionality from IDA C++ objects.

        Register hooks that will be used by IDA.
        These are essentially listeners for certain global events associated with a particular task/function.
        """
        def create_desktop_widget(self, ttl, cfg):
            if ttl == PLUGIN_NAME:
                MAGICWidgetPage = MAGIC_form.MAGICPluginFormClass(PLUGIN_NAME)
                MAGICWidgetPage.Show()
                return MAGICWidgetPage.GetWidget()

    global hooks
    hooks = MAGIC_inst_auto_hook_t()
    hooks.hook()

class PluginScrHooks(ida_kernwin.UI_Hooks):
        """Hooks necessary for the functionality of this form
        
        Connect to IDA's screen_ea_changed hook
        """
        def __init__(self, proc_tree, procedureEADict, *args):
            super().__init__(*args)
            # needs to be able to access the process_treeview once generated
            self.proc_tree = proc_tree
            self.procedureEADict = procedureEADict

        def screen_ea_changed(self, ea, prev_ea):
            eaKey = ida_kernwin.ea2str(ea).split(":")[1]
            eaKey = int(eaKey,16)
            if eaKey in self.procedureEADict:
                procedureQIndexItem = self.procedureEADict[eaKey].index()
                self.proc_tree.setCurrentIndex(procedureQIndexItem) # highlight and select it
                if not self.proc_tree.isExpanded(procedureQIndexItem): # do not expand before checking if expanded, see proc_tree_jump_to_hex for info
                    self.proc_tree.expand(procedureQIndexItem)
                # 3 is an enum telling the widget to open with the item in the center
                self.proc_tree.scrollTo(procedureQIndexItem,3) # jump to and center it