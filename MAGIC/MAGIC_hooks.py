import ida_kernwin
from MAGIC_form import MAGICPluginFormClass

"""
auto_instantiate_widget_plugin.py code was used to make the plugin window persist on IDA launch
"""
def register_autoinst_hooks(PLUGIN_NAME):
    """
    Register hooks that will create the widget when IDA
    requires it because of the IDB/desktop
    """
    class auto_inst_hooks_t(ida_kernwin.UI_Hooks):
        def create_desktop_widget(self, ttl, cfg):
            if ttl == PLUGIN_NAME:
                MAGICWidgetPage = MAGICPluginFormClass()
                MAGICWidgetPage.Show(PLUGIN_NAME)
                return MAGICWidgetPage.GetWidget()

    global auto_inst_hooks
    auto_inst_hooks = auto_inst_hooks_t()
    auto_inst_hooks.hook()