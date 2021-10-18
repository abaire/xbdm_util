import wx

from gdbxbdmbridge import bridge


class XBDMDialog(wx.Dialog):
    """Dialog providing tools for interacting with an XBOX devkit."""

    def __init__(self, parent, xbox_bridge: bridge.GDBXBDMBridge, *args, **kw):
        super().__init__(parent, *args, title=xbox_bridge.xbox_info, **kw)

        self._bridge = xbox_bridge
