import ida_kernwin
from MAGIC_form import MAGICPluginFormClass

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
                MAGICWidgetPage = MAGICPluginFormClass()
                MAGICWidgetPage.Show(PLUGIN_NAME)
                return MAGICWidgetPage.GetWidget()

    global hook
    hook = MAGIC_inst_auto_hook_t()
    hook.hook()