"""
Contains IDA UI hooks for the plugin widgets.
"""

import ida_kernwin
from MAGIC import unknowncyber_interface, IDA_interface

def register_autoinst_hooks(PLUGIN_NAME,PLUGIN_API_CLIENT,formType:ida_kernwin.PluginForm):
    """
    Register hook to start unknowncyber_interface automatically at IDA launch, if previously unclosed during last session.

    @param PLUGIN_NAME: pass the name of the plugin to select it.
    @param PLUGIN_API_CLIENT: pass cythereal_magic's API client to access the system.
    @param formType: type of form which is to be hooked and returned
    @globals MAGIC_inst_auto_hook,AGIC_procedures_inst_auto_hook: hooks to register globally with IDA.
    auto_instantiate_widget_plugin.py code was used to make this. there is probably some way to clean this and keep it looking good.
    """
    class MAGIC_inst_auto_hook_t(ida_kernwin.UI_Hooks):
        """
        Inherets UI_hooks functionality from IDA C++ objects.

        Register hooks that will be used by IDA.
        These are essentially listeners for certain global events associated with a particular task/function.
        """
        def create_desktop_widget(self, ttl, cfg):
            if ttl == PLUGIN_NAME:
                MAGICWidgetPage = formType(PLUGIN_NAME,PLUGIN_API_CLIENT)
                return MAGICWidgetPage.GetWidget()
            
    class MAGIC_procedures_inst_auto_hook_t(ida_kernwin.UI_Hooks):
        """
        Same as above but for the procedures widget
        """
        def create_desktop_widget(self, ttl, cfg):
            if ttl == PLUGIN_NAME:
                MAGICWidgetPage = formType(PLUGIN_NAME,PLUGIN_API_CLIENT,autoinst=True)
                return MAGICWidgetPage.GetWidget()

    if(formType is unknowncyber_interface.MAGICPluginFormClass):
        global MAGIC_inst_auto_hook
        MAGIC_inst_auto_hook = MAGIC_inst_auto_hook_t()
        MAGIC_inst_auto_hook.hook()
    elif(formType is IDA_interface.MAGICPluginScrClass):
        global AGIC_procedures_inst_auto_hook
        AGIC_procedures_inst_auto_hook = MAGIC_procedures_inst_auto_hook_t()
        AGIC_procedures_inst_auto_hook.hook()

class PluginScrHooks(ida_kernwin.UI_Hooks):
    """Hooks necessary for the functionality of the procedure widget form (IDA_interface)
    
    Connect to IDA's screen_ea_changed hook. In a way, "notifies" the plugin when user clicks on or scrolls to different addresses in IDA.
    Since this class is for use by IDA_interface only, "self" refers to type MAGICPluginScrClass.
    """
    def __init__(self, proc_tree, procedureEADict,procWidgetParent, *args):
        super().__init__(*args)
        # needs to be able to access the process_treeview once generated
        self.procWidgetParent = procWidgetParent
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

    # this object will not have "parent" until all UI objects are loaded
    # additionally, this 'ready_to_run' will only occur once on initialization
    def ready_to_run(self, *args):
        self.procWidgetParent.parent().parent().setSizes([600,1])