"""
Main scroll widget at the highest level. 

This is the scaffolding of a simplecustviewer_t for the purpose of 
testing out how certain functions can be synced.
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

    def Create(self, use_colors=True):
        super().Create(self.title)

        self.use_colors = use_colors

        text = __doc__
        for l in text.split("\n"):
            self.AddLine(l)

        for i in range(0, 1000):
            prefix, bg = ida_lines.COLOR_DEFAULT, None
            # make every 10th line a bit special
            if i % 10 == 0:
                prefix = ida_lines.COLOR_DNAME   # i.e., dark yellow...
                bg = 0xFFFF00                 # ...on cyan
            pfx = ida_lines.COLSTR("%3d" % i, ida_lines.SCOLOR_PREFIX)
            if self.use_colors:
                self.AddLine("%s: Line %d" % (pfx, i), fgcolor=prefix, bgcolor=bg)
            else:
                self.AddLine("%s: Line %d" % (pfx, i))

        return True