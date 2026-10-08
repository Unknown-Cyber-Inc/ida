"""Minimal stand-in for ida_kernwin used by the headless tests."""

from unknowncyber.qt import QtWidgets  # noqa: E402

MFF_READ = 0
MFF_WRITE = 1
_screen_ea = 0x401000
_widgets = {}
_wait_box = []
_cancel = False


def is_idaq():
    return True


def is_main_thread():
    return True


def execute_sync(fn, flags):
    return fn()


def get_kernel_version():
    return "9.2"


def get_screen_ea():
    return _screen_ea


def jumpto(ea):
    global _screen_ea
    _screen_ea = ea
    return True


def find_widget(title):
    return _widgets.get(title)


def activate_widget(widget, flag):
    pass


DP_LEFT, DP_TOP, DP_RIGHT, DP_BOTTOM, DP_INSIDE, DP_TAB = 1, 2, 4, 8, 16, 64
_dock_calls = []


def set_dock_pos(src, dest, orient, left=0, top=0, right=0, bottom=0):
    _dock_calls.append((src, dest, orient))
    return True


_ui_requests = []


def execute_ui_requests(requests):
    """Stub: run the requests immediately (IDA would run them on the next UI cycle)."""
    for req in requests:
        _ui_requests.append(req)
        while req():
            pass
    return True


def show_wait_box(text):
    _wait_box.append(text)


def replace_wait_box(text):
    _wait_box.append(text)


def hide_wait_box():
    _wait_box.clear()


def user_cancelled():
    return _cancel


class UI_Hooks:  # noqa: N801
    _active = []

    def hook(self):
        UI_Hooks._active.append(self)

    def unhook(self):
        if self in UI_Hooks._active:
            UI_Hooks._active.remove(self)


class PluginForm:
    WOPN_DP_RIGHT = 0x10
    WOPN_DP_SZHINT = 0x8000
    WOPN_PERSIST = 0x40

    def Show(self, caption, options=0):  # noqa: N802
        _widgets[caption] = self
        self.OnCreate(QtWidgets.QWidget()) if hasattr(self, "OnCreate") else None
        return 1

    def GetWidget(self):  # noqa: N802
        return None

    def Close(self, options):  # noqa: N802
        pass

    def FormToPySideWidget(self, form):  # noqa: N802
        return form

    def FormToPyQtWidget(self, form):  # noqa: N802
        return form
