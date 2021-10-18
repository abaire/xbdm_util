import wx

from gdbxbdmbridge import bridge_manager
from gdbxbdmbridge import discoverer
from gdbxbdmbridge.gui import main_frame
from gdbxbdmbridge.gui import xbdm_dialog


class Application(wx.App):
    def __init__(
        self,
        xbox_discoverer: discoverer.XBOXDiscoverer,
        manager: bridge_manager.BridgeManager,
        *args,
        **kw,
    ):
        super().__init__(*args, **kw)

        self._xbox_discoverer = xbox_discoverer
        self._manager = manager

        self.frame = main_frame.MainFrame(title="GDB <-> XBDM Bridge")
        self.frame.CenterOnScreen()
        self.frame.Show()

        self.frame.Bind(
            main_frame.MainFrame.EVT_LAUNCH_XBDM_BROWSER,
            self._launch_xbdm_browser,
        )

        self.refresh_discovered_devices()

        self._dialogs = {}

    def refresh_discovered_devices(self):
        self.frame.set_discovered_devices(self._manager.get_bridge_infos())

    def _launch_xbdm_browser(self, evt: main_frame.MainFrame.LaunchXBDMBrowserEvent):
        xbox_addr = evt.addr
        old_dialog = self._dialogs.get(xbox_addr)
        if old_dialog:
            # TODO: Raise the dialog
            return

        xbox_bridge = self._manager.get_bridge(xbox_addr)
        if not xbox_bridge:
            print(f"Failed to look up bridge for {xbox_addr}")
            return
        dialog = xbdm_dialog.XBDMDialog(self.frame, xbox_bridge)
        dialog.CenterOnScreen()

        self._dialogs[xbox_addr] = dialog

        def destroy_dialog(_evt):
            del self._dialogs[xbox_addr]
            dialog.Destroy()

        dialog.Bind(wx.EVT_CLOSE, destroy_dialog)

        dialog.Show()
