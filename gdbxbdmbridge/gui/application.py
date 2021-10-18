import wx

from gdbxbdmbridge import bridge_manager
from gdbxbdmbridge import discoverer
from gdbxbdmbridge.gui import main_frame


class Application(wx.App):
    def __init__(
        self,
        xbox_discoverer: discoverer.XBOXDiscoverer,
        manager: bridge_manager.BridgeManager,
        *args,
        **kw
    ):
        super().__init__(*args, **kw)

        self._xbox_discoverer = xbox_discoverer
        self._manager = manager

        self.frame = main_frame.MainFrame(title="GDB <-> XBDM Bridge")
        self.frame.Show()

        self.frame.Bind(
            main_frame.MainFrame.EVT_LAUNCH_XBDM_BROWSER,
            lambda evt: self._launch_xbdm_browser(evt),
        )

        self.refresh_discovered_devices()

    def refresh_discovered_devices(self):
        self.frame.set_discovered_devices(self._manager.get_bridge_infos())

    def _launch_xbdm_browser(self, evt: main_frame.MainFrame.LaunchXBDMBrowserEvent):
        xbox_addr = evt.addr
        print(xbox_addr)
