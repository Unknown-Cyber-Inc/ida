"""
Main pluginform object at the highest level. 

This is the scaffolding of the form object which will be displayed to the viewer.
Contains ida_kernwin.PluginForm and also ida_kernwin.Choose.
Will likely be broken into components as the insides of the form grow.
"""

# IDA and UI imports
import ida_nalt, ida_kernwin, ida_lines
from PyQt5 import QtWidgets, QtGui

#cythereal magic for calling API
import cythereal_magic

# load_dotenv sources the below environment variables from .env
import os
PLUGIN_DEBUG = True if os.getenv("PLUGIN_DEBUG") == "True" else False

class MAGICPluginScrClass(ida_kernwin.simplecustviewer_t):
    def __init__(self,title):
        self.title = title
        super().__init__()
        
        self.Create()
        self.Show()
        # dock this widget on the rightmost side of IDA, ensure this by setting dest_ctrl to an empty string
        ida_kernwin.set_dock_pos(self.title,"",ida_kernwin.DP_RIGHT)
        # A 'QSplitter' is created which can handle the default creation size
        # Through testing I have found out which widget this is relative to self
        # DOESN'T WORK ON TWIDGET
        # self.parent.parent().parent().setSizes([800,1]) 


    def Create(self):
        super().Create(self.title)

        text = __doc__
        for l in text.split("\n"):
            self.AddLine(l)
        return True